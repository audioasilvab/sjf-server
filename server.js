const express = require('express');
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');
const app = express();

const { PORT, HOST, BASE_PATH, ACCESS_TOKEN, ZONE_STATE,
        PLAYER, SETTINGS_URI, ROUND_DURATION_MS } = require('./config');

app.use((req, res, next) => {
  let raw = '';
  req.on('data', (chunk) => { raw += chunk.toString('binary'); });
  req.on('end', () => {
    req.rawBody = raw;

    const cidMatch = raw.match(/"cid"\s*:\s*(-?\d+)/);
    req.cidExact = cidMatch ? BigInt(cidMatch[1]) : null;

    const versionMatch = raw.match(/"version"\s*:\s*(\d+)/);
    req.version = versionMatch ? parseInt(versionMatch[1], 10) : 0;

    const trimmed = raw.trim();
    if (trimmed.startsWith('{')) {
      try {
        req.body = JSON.parse(trimmed, (key, value) => {
          if (key === 'cid' && typeof value === 'number' && !Number.isSafeInteger(value)) {
            return String(value);
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

const CONNECT   = require('./routes/connect');
const SETTINGS  = require('./routes/settings');
const PROFILE   = require('./routes/profile');
const HANDSHAKE = require('./routes/handshake');

app.use(BASE_PATH, HANDSHAKE);
app.use(BASE_PATH, CONNECT);
app.use(BASE_PATH, SETTINGS);
app.use(BASE_PATH, PROFILE);

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
app.post(`${BASE_PATH}/GetScores.json`, (req, res) => {
  let type = req.body.type;

  var nuevaLista = FRIENDS.map((friend) => {
    let currentScore = friend.score;
    let newScore = Math.floor((Math.random() * 350001));
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
  params.set('access_token',  ACCESS_TOKEN + "s");
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
    link: `https://facebook.com/${'100001'}`
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