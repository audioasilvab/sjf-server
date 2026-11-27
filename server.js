const express = require('express');
const crypto = require('crypto');
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');
const app = express();

const { PORT, HOST, BASE_PATH, ACCESS_TOKEN, ZONE_STATE,
        PLAYER, SETTINGS_URI, ROUND_DURATION_MS } = require('./config');

const CONNECT = require('./routes/connect');
const HANDSHAKE = require('./routes/handshake');
const SETTINGS = require('./routes/settings');

app.use(BASE_PATH, CONNECT);
app.use(BASE_PATH, SETTINGS);
app.use(BASE_PATH, HANDSHAKE);

app.post(`${BASE_PATH}/GetProfile.json`, (req, res) => {

  const dir = path.join(__dirname, 'data');
  const file = path.join(dir, 'savedata.json');

  const profile = JSON.parse(fs.readFileSync(file, 'utf8'));

  console.log(' Loaded successfully');

  res.status(200).json({ status: 0, crc: profile.crc, accessToken: ACCESS_TOKEN, synchronizedPlayerState: profile.synchronizedPlayerState });
});

app.post(`${BASE_PATH}/PushProfile.json`, (req, res) => {

  let recibido = req.body;


  const dir = path.join(__dirname, 'data');
  const file = path.join(dir, 'savedata.json');

  fs.writeFileSync(file, JSON.stringify(recibido, null, 2), 'utf8');

  console.log(' Saved successfully')

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