const express = require('express');
const crypto = require('crypto');
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');
const app = express();

const { PORT, HOST, BASE_PATH, ACCESS_TOKEN, ZONE_STATE,
        PLAYER, SETTINGS_URI, ROUND_DURATION_MS } = require('./config');

const CONNECT = require('./routes/connect');
const SETTINGS = require('./routes/settings');

// Clave de 32 bytes + NUL = 33 bytes (extraída del .so, ver PROTOCOLO.md §3)
const HMAC_KEY = Buffer.concat([
  Buffer.from('PvQmck9?y+ZBjgAfqCpa8W67UhTu_D!S', 'ascii'),
  Buffer.from([0x00])
]);

// Constante del algoritmo (PROTOCOLO.md §3)
const MULT = 0xBDC70E445308C215n;

// ============================================================
// PARSER FLEXIBLE + CAPTURA DE CID EXACTO
// ============================================================
app.use((req, res, next) => {
  let raw = '';
  req.on('data', (chunk) => { raw += chunk.toString('binary'); });
  req.on('end', () => {
    req.rawBody = raw;

    // Extraer cid EXACTO como BigInt (para que no pierda precisión el JSON.parse)
    const cidMatch = raw.match(/"cid"\s*:\s*(-?\d+)/);
    req.cidExact = cidMatch ? BigInt(cidMatch[1]) : null;

    // Extraer version también
    const versionMatch = raw.match(/"version"\s*:\s*(\d+)/);
    req.version = versionMatch ? parseInt(versionMatch[1], 10) : 0;

    // Parsear el body normal (con BigInt para cid)
    const trimmed = raw.trim();
    if (trimmed.startsWith('{')) {
      try {
        req.body = JSON.parse(trimmed, (key, value) => {
          if (key === 'cid' && typeof value === 'number' && !Number.isSafeInteger(value)) {
            return String(value); // conservar como string si excede safe integer
          }
          return value;
        });
      } catch (e) {
        req.body = {};
      }
    } else {
      req.body = {};
    }

    next();
  });
});

app.use((req, res, next) => {
  const ts = new Date().toISOString();
  console.log(`\n[${ts}] ${req.method} ${req.originalUrl} ← ${req.ip}`);
  if (req.rawBody) console.log(`    Raw: ${req.rawBody}`);
  next();
});

function u64le(value) {
  // Acepta BigInt o Number, devuelve Buffer de 8 bytes little-endian
  const buf = Buffer.alloc(8);
  let v = BigInt(value) & 0xFFFFFFFFFFFFFFFFn; // forzar a 64 bits sin signo
  for (let i = 0; i < 8; i++) {
    buf[i] = Number(v & 0xFFn);
    v >>= 8n;
  }
  return buf;
}

function buildChallenge(cid) {
  // cid = BigInt con signo, tal como lo envió el cliente
  // M = (R * MULT mod 2^64) XOR cid   (todo en 64 bits)
  const cidU64 = BigInt.asUintN(64, cid);

  // Elegir R aleatorio de 64 bits
  const R = crypto.randomBytes(8).readBigUInt64LE(0);

  // M = (R * MULT mod 2^64) XOR cid
  const mulResult = (R * MULT) & 0xFFFFFFFFFFFFFFFFn;
  const M = mulResult ^ cidU64;

  // data = u64le(cid) || u64le(M)
  const data = Buffer.concat([u64le(cidU64), u64le(M)]);

  // HMAC-SHA256(clave33, data) = 32 bytes
  const hmac = crypto.createHmac('sha256', HMAC_KEY).update(data).digest();

  // challenge = hmac(32) || u64le(R)(8) || relleno(2) = 42 bytes
  const challengeBuf = Buffer.concat([
    hmac,
    u64le(R),
    Buffer.from([0x00, 0x00])  // relleno de 2 bytes para llegar a 42
  ]);

  return {
    challenge: challengeBuf.toString('base64'),
    challengeToken: crypto.randomBytes(16).toString('hex'),
    R, M, cidU64
  };
}

app.post(`${BASE_PATH}/Handshake.json`, (req, res) => {
  const cid = req.cidExact;
  if (cid === null) {
    console.log(' No se pudo extraer cid del body');
    return res.status(400).json({ status: 1 });
  }

  console.log(` HANDSHAKE: cid=${cid}, version=0x${req.version.toString(16).toUpperCase()}`);

  const { challenge, challengeToken } = buildChallenge(cid);

  console.log(`   → challenge (${Buffer.from(challenge, 'base64').length} bytes): ${challenge.substring(0, 20)}...`);
  res.status(200).json({status: 0, challengeToken, challenge});
});

app.use(BASE_PATH, CONNECT);
app.use(BASE_PATH, SETTINGS);

app.post(`${BASE_PATH}/GetProfile.json`, (req, res) => {
  res.status(200).json({ status: 0, crc: 0, accessToken: ACCESS_TOKEN,
    synchronizedPlayerState: {
    rouge: 0,
    miscData1: 1,
    miscData0: 2,
    awardFlags: 1153045,
    tails: 1,
    currentRoundId: 1449904,
    numAnimalDoubler: 0,
    numQuickFrenzy: 0,
    energyCount: 1,
    numCharTokens: 20,
    spinState: 0,
    redRingTokenTime: 1795476632000,
    blaze: 1,
    silver: 1,
    lastRateVersion: 9,
    numRingStreak: 0,
    numPowerDoubler: 1,
    lastFreeSpin: 0,
    energyRechargeTime: 1795479015478,
    cream: 0,
    numHoopBoost: 0,
    numRedRings: 28,
    lastLogin: 1795478432007,
    score: 2675061,
    numTimeExtend: 0,
    version: 9,
    numChaoSearches: 0,
    numRings: 11774,
    vector: 1,
    numConsecutiveLogins: 1,
    numRedRingTokens: 0,
    amy: 1,
    chaoStates: [
      { collectTime: 0, type: 11, state: 0 },
      { collectTime: 0, type: 15, state: 0 },
      { collectTime: 0, type: 1, state: 0 },
      { collectTime: 0, type: 12, state: 0 },
      { collectTime: 0, type: 16, state: 0 },
      { collectTime: 0, type: 2, state: 0 },
      { collectTime: 0, type: 13, state: 0 },
      { collectTime: 0, type: 3, state: 0 },
      { collectTime: 0, type: 23, state: 0 },
      { collectTime: 0, type: 14, state: 0 },
      { collectTime: 0, type: 4, state: 0 },
      { collectTime: 0, type: 24, state: 0 },
      { collectTime: 0, type: 6, state: 0 },
      { collectTime: 0, type: 18, state: 0 },
      { collectTime: 0, type: 26, state: 0 },
      { collectTime: 1795476521887, type: 7, state: 2739207 },
      { collectTime: 0, type: 19, state: 0 },
      { collectTime: 0, type: 27, state: 0 },
      { collectTime: 0, type: 5, state: 0 },
      { collectTime: 0, type: 17, state: 0 },
      { collectTime: 0, type: 25, state: 0 },
      { collectTime: 0, type: 8, state: 0 },
      { collectTime: 0, type: 20, state: 0 },
      { collectTime: 0, type: 28, state: 0 },
      { collectTime: 0, type: 9, state: 0 },
      { collectTime: 0, type: 21, state: 0 },
      { collectTime: 0, type: 29, state: 0 },
      { collectTime: 0, type: 10, state: 0 },
      { collectTime: 0, type: 22, state: 0 },
      { collectTime: 0, type: 30, state: 0 }
    ],
    sonic: 1,
    shadow: 1,
    charTokenTime: 1795476632000,
    pointsPending: 0,
    doubleRings: true,
    numGoldTotem: 4,
    lastUpdate: 1795480232648,
    knuckles: 1,
    ftueState: 7
  }});
});

app.post(`${BASE_PATH}/PushProfile.json`, (req, res) => {
  res.status(200).json({
    status: 0, lastUpdate: Date.now(),
    numRings: 0, numRedRings: 0,
    score: 0, version: 9,
    accessToken: ACCESS_TOKEN
  });
});


var FRIENDS = [
  {
    playerId: 2,
    score: 0,
    data: 0,
    firstName: 'Juan Perea',
    facebookId: '100002',
    lastLogin: 1795221275330
  },
  {
    playerId: 3,
    score: 0,
    data: 0,
    firstName: 'Angel Ferrer',
    facebookId: '100003',
    lastLogin: 1795221275330
  },
  {
    playerId: 4,
    score: 0,
    data: 0,
    firstName: 'Jose Maestre',
    facebookId: '100004',
    lastLogin: 1795221275330
  },
  {
    playerId: 5,
    score: 0,
    data: 0,
    firstName: 'Edelyn Hernandez',
    facebookId: '100005',
    lastLogin: 1795221275330
  },
  {
    playerId: 6,
    score: 0,
    data: 0,
    firstName: 'Samuel Espinoza',
    facebookId: '100006',
    lastLogin: 1795221275330
  },
  {
    playerId: 7,
    score: 0,
    data: 0,
    firstName: 'Carla Villalobos',
    facebookId: '100007',
    lastLogin: 1795221275330
  }
];

var finRonda = false;

app.post(`${BASE_PATH}/GetFriends.json`, (req, res) => {
  const list = FRIENDS;

  console.log(` GetFriends: ${list.length} amigos`);
  res.status(200).json({ status: 0, friends: list, accessToken: ACCESS_TOKEN });
});

var score = 0, data = 0;
var listaGuardada = [];

// type = 0 → leaderboard actual/pendiente (en curso, se está llenando).
// type = 1 → snapshot de resultados anteriores (la clasificación ya cerrada,
// la de la semana/evento pasado).
/*let score = (newScore > currentScore) ? newScore : currentScore;*/

app.post(`${BASE_PATH}/GetScores.json`, (req, res) => {
  let type = req.body.type;

  var nuevaLista = FRIENDS.map((friend) => {
    let currentScore = friend.score;
    let newScore = Math.floor((Math.random() * 350001) * 0.1);
    return {
      ...friend,
      score: (newScore > currentScore) ? newScore : currentScore,
      data: 0
    }
  });

  var scores;

  if (type === 1) {

    scores = listaGuardada;
    
    res.status(200).json({ status: 0, scores, accessToken: ACCESS_TOKEN });
    
    let listaReiniciada = FRIENDS.map((friend) => {
      return {
        ...friend,
        score: 0,
        data: 0
      }
    })

    scores = [
      {
        playerId: 1,
        score: 0,
        data: 0
      },
      ...listaReiniciada
    ]

    score = 0;
    data = 0;

    FRIENDS = listaReiniciada;
  } else {

    scores = [
      {
        playerId: 1,
        score: score,
        data: data
      },
      ...nuevaLista
    ]

    FRIENDS = nuevaLista;
    listaGuardada = scores;
    res.status(200).json({ status: 0, scores, accessToken: ACCESS_TOKEN });
  }
});


app.post(`${BASE_PATH}/PostScore.json`, (req, res) => {
  const body = req.body || {};
  score = body.score;
  data = body.data;

  res.status(200).json({ status: 0, isHighScore: true, accessToken: ACCESS_TOKEN });
});



app.post(`${BASE_PATH}/GetMessages.json`, (req, res) => {
  let pending = []

  res.status(200).json({ status: 0, messages: pending, accessToken: ACCESS_TOKEN });
});

app.post(`${BASE_PATH}/InviteFriend.json`, (req, res) => {
  res.status(200).json({ status: 0, invited: [false, true], accessToken: ACCESS_TOKEN });
})

app.get(['/v2.7/dialog/oauth', '/v2.7/dialog/oauth/'], (req, res) => {
  // 1. Normalizar query params (equivale a fbFirst)
  const first = (v) => Array.isArray(v) ? v[0] : v;

  const redirectUri = req.query.redirect_uri || 'fbconnect://success';
  const scope       = req.query.scope;
  const state       = req.query.state;
  const userId      = '100001';

  // 2. Construir signed_request falso (base64 de un JSON)
  const payload = Buffer.from(JSON.stringify({
    user_id: userId,
    issued_at: Math.floor(Date.now() / 1000)
  }), 'utf8').toString('base64');
  const signedRequest = `x.${payload}`;

  // 3. Montar el fragmento (#...) que el cliente espera tras el redirect
  const params = new URLSearchParams();
  params.set('access_token',  ACCESS_TOKEN);
  params.set('expires_in',    '0');
  params.set('signed_request', signedRequest);
  params.set('granted_scopes', scope);
  if (state) params.set('state', String(state));

  const target = `${redirectUri}#${params.toString()}`;

  // 4. HTML puente con escape seguro y auto-redirect
  const href   = target
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  const script = JSON.stringify(target).replace(/</g, '\\u003c');

  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Facebook</title></head>` +
    `<body><p>Redirigiendo...</p><p><a href="${href}">Continuar</a></p>` +
    `<script>location.replace(${script});</script></body></html>`;

  console.log(` FB OAuth emulado: state=${state ?? '-'}`);
  res.type('html').send(html);
});


app.get(['/p/:id', '/p/:id/'], (req, res, next) => {
  const id = String(req.params.id || '0');

  console.log("=========== AVATARES =============");
  console.log(id)

  sharp(path.join(__dirname, `avatars/${id}.png`))
    .resize(100, 80, { fit: 'cover' })
    .removeAlpha()
    .png({ compressionLevel: 9, palette: false })
    .toBuffer()
    .then((png) => {
      res.type('png');
      res.set('Cache-Control', 'public, max-age=0');    // 86400
      res.status(200).send(png);
    })
    .catch(next);
});

app.get(['/v2.7/me', '/v2.7/me/'], (req, res) => {
  //console.log(` FB /me emulado: fields=${fbFirst(req.query.fields) ?? '-'}`);

  res.status(200).json({
    id: '100001',                                     // Facebook ID
    name: 'audioasilvab.06',                          // Facebook first name
    link: `https://facebook.com/${'100001'}`,
    numRings: 12345678
  });
});



app.use('/v2.7', (req, res) => {
  console.log(` FB Graph emulado: ${req.method} ${req.originalUrl}`);
  res.status(200).json({ success: true });
});


app.listen(PORT, HOST, () => {
  console.log('============================================================');
  console.log('                     Servidor SJF23                         ');
  console.log('============================================================');
  console.log(`   http://${HOST}:${PORT}${BASE_PATH}`);
  console.log(`   Zona actual: ${ZONE_STATE.zone} (roundId=${ZONE_STATE.roundId})`);
  console.log('============================================================');
});