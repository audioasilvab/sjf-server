/**
 * Sonic Jump Fever 1.6.1 - servidor propio (Node.js, sin dependencias).
 *
 * PROTOCOLO RECONSTRUIDO POR INGENIERIA INVERSA
 * =============================================
 * Todos los endpoints reciben y devuelven un OBJETO JSON PLANO en la raiz
 * (no hay envoltorio). Clase C++ que lo define entre parentesis.
 *
 *   POST /Handshake.json      -> HandshakeRequest  {version, cid}
 *                             <- HandshakeResponse {status, challengeToken, challenge}
 *   POST /Connect.json        <- ConnectRequest    {challengeToken, response, deviceId,
 *                                                    facebookId, firstName,
 *                                                    facebookAccessToken, lastPlayerId,
 *                                                    numRings, numRedRings, xp,
 *                                                    numPlays, mode}
 *                             -> ConnectResponse    {status, playerId, isNewAccount,
 *                                                    lastLogin, accessToken, uniqueId,
 *                                                    cohortId, settingsUri,
 *                                                    serverSettings, lastUpdate,
 *                                                    numRings, numRedRings, score,
 *                                                    version}
 *   POST /GetSettings.json    -> GetSettingsResponse {status, serverSettings}
 *   POST /GetProfile.json     -> GetProfileResponse  {status, synchronizedPlayerState,
 *                                                     crc, accessToken}
 *   POST /PushProfile.json    -> PushProfileResponse {status, lastUpdate, numRings,
 *                                                     numRedRings, score, version,
 *                                                     accessToken}
 *   POST /GetScores.json      -> {status, scores[], accessToken}
 *   POST /PostScore.json      -> {status, isHighScore, accessToken}
 *   POST /GetFriends.json     -> {status, friends[], accessToken}
 *   POST /GetMessages.json    -> {status, messages[], accessToken}
 *   POST /DeleteMessages.json -> {status, accessToken}
 *   POST /InviteFriend.json   -> {status, invited[], accessToken}
 *   POST /SendGift.json       -> {status, nextRequest, accessToken}
 *   POST /RequestEnergy.json  -> {status, requested[], nextRequest[], accessToken}
 *   POST /LogIAP.json         -> {status, accessToken}
 *   POST /AwardRequestItem.json -> {status, accessToken}
 *
 * serverSettings (network::ServerSettings) es lo que decide LA ZONA:
 *     { serverTime, currentRoundId, currentZone, expiryTime,
 *       nextZone, nextRoundId, previousZone, previousRoundId }
 * Zonas validas: green_hill_zone, mountain_zone, jungle_zone,
 *                blue_sky_zone, mechanical_zone
 *
 * El handshake es un reto-respuesta HMAC-SHA256 (ver verifyChallenge()).
 *
 * Uso:
 *   node sjf-server/server.js
 *   node sjf-server/server.js --zone jungle_zone
 *   node sjf-server/server.js --port 8080
 */

const express = require('express');
const crypto = require('crypto');
const app = express();

const PORT = 8443;
const BASE_PATH = '/SJF23';

// ============================================================
// ESTADO GLOBAL DE LA RONDA (persistente en memoria)
// ============================================================
const ROUND_DURATION_MS = 5 * 60 * 1000; // 5 minutos por ronda

// Estado de la ronda actual
const zoneState = {
  roundId: 1,
  zone: 'blue_sky_zone',
  nextRoundId: 2,
  nextZone: 'jungle_zone',
  previousRoundId: 0,
  previousZone: 'blue_sky_zone',
  startTime: Date.now() // <-- se fija UNA sola vez
};

// Comprueba si la ronda ya expiró y, si es así, rota a la siguiente
function tickRound() {
  const now = Date.now();
  if (now >= zoneState.startTime + ROUND_DURATION_MS) {
    // Rotar
    zoneState.previousRoundId = zoneState.roundId;
    zoneState.previousZone = zoneState.zone;

    zoneState.roundId = zoneState.nextRoundId;
    zoneState.zone = zoneState.nextZone;

    // Siguiente (puedes poner una lista/rotación real)
    zoneState.nextRoundId = zoneState.roundId + 1;
    zoneState.nextZone = pickNextZone(zoneState.zone);

    // Avanzar startTime en múltiplos exactos para no acumular drift
    while (now >= zoneState.startTime + ROUND_DURATION_MS) {
      zoneState.startTime += ROUND_DURATION_MS;
    }

    console.log(` Ronda rotada → roundId=${zoneState.roundId}, zone=${zoneState.zone}`);
  }
}

function pickNextZone(current) {
  const zones = ['mechanical_zone', 'blue_sky_zone', 'green_hill_zone', 'jungle_zone'];
  const idx = zones.indexOf(current);
  return zones[(idx + 1) % zones.length];
}

// Helper para construir el objeto serverSettings siempre coherente
function getServerSettings() {
  tickRound();
  const now = Math.floor(Date.now());
  return {
    serverTime: now,
    currentRoundId: zoneState.roundId,
    currentZone: zoneState.zone,
    expiryTime: Math.floor((zoneState.startTime + ROUND_DURATION_MS)),
    nextZone: zoneState.nextZone,
    nextRoundId: zoneState.nextRoundId,
    previousZone: zoneState.previousZone,
    previousRoundId: zoneState.previousRoundId
  };
}

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

// ============================================================
// UTILIDADES HMAC
// ============================================================

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

// ============================================================
// ENDPOINTS
// ============================================================

app.post(`${BASE_PATH}/Handshake.json`, (req, res) => {
  const cid = req.cidExact;
  if (cid === null) {
    console.log(' No se pudo extraer cid del body');
    return res.status(400).json({ status: 1 });
  }

  console.log(` HANDSHAKE: cid=${cid}, version=0x${req.version.toString(16).toUpperCase()}`);

  const { challenge, challengeToken } = buildChallenge(cid);

  const response = {
    status: 0,
    challengeToken,
    challenge
  };

  console.log(`   → challenge (${Buffer.from(challenge, 'base64').length} bytes): ${challenge.substring(0, 20)}...`);
  res.status(200).json(response);
});

let inicio = Date.now();
let fin = Date.now();

app.post(`${BASE_PATH}/Connect.json`, (req, res) => {
  const now = Math.floor(Date.now());
  console.log(' CONNECT recibido');

  const response = {
    status: 0,
    playerId: 1,
    isNewAccount: false,
    lastLogin: now,
    accessToken: "devtoken",
    uniqueId: "local-0001",
    cohortId: 0,
    settingsUri: `${BASE_PATH}/GetSettings.json`,
    serverSettings: getServerSettings(),   // <-- coherente y persistente
    lastUpdate: now,
    numRings: 0,
    numRedRings: 0,
    score: 0,
    version: req.body?.version || 0
  };

  res.status(200).json(response);
});

app.get(`${BASE_PATH}/GetSettings.json`, (req, res) => {
  console.log(' GetSettings');
  res.status(200).json({
    status: 0,
    serverSettings: getServerSettings()   // <-- mismo estado global
  });
});

app.post(`${BASE_PATH}/GetProfile.json`, (req, res) => {
  console.log(' GetProfile');
  const now = Math.floor(Date.now() / 1000);
  res.status(200).json({
    status: 0,
    crc: 0,
    accessToken: "devtoken",
    synchronizedPlayerState: {
      lastUpdate: now,
      numRings: 0,
      numRedRings: 0,
      score: 0,
      charTokenTime: now,
      numCharTokens: 0,
      redRingTokenTime: now,
      numRedRingTokens: 0,
      numChaoSearches: 0,
      sonic: 0, tails: 0, knuckles: 0, amy: 0, blaze: 0,
      vector: 0, shadow: 0, silver: 0, rouge: 0, cream: 0,
      numGoldTotem: 0, numHoopBoost: 0, numPowerDoubler: 0,
      numQuickFrenzy: 0, numRingStreak: 0, numTimeExtend: 0,
      numAnimalDoubler: 0,
      doubleRings: false,
      currentRoundId: 1,
      spinState: 0,
      chaoStates: []                   // OBLIGATORIO, aunque vacío
    }
  });
});

// Placeholders para el resto
[
  'PushProfile.json', 'GetScores.json', 'PostScore.json',
  'GetFriends.json', 'GetMessages.json', 'DeleteMessages.json',
  'SendGift.json', 'RequestEnergy.json', 'AwardRequestItem.json',
  'InviteFriend.json', 'LogIAP.json'
].forEach(endpoint => {
  app.post(`${BASE_PATH}/${endpoint}`, (req, res) => {
    console.log(`⚠ ${endpoint}`);
    res.status(200).json({ status: 0, accessToken: "devtoken" });
  });
});

app.use(BASE_PATH, (req, res) => {
  console.log(`❌ 404: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ status: 1 });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('============================================================');
  console.log(' Servidor SJF23 (handshake HMAC) corriendo');
  console.log('============================================================');
  console.log(`   http://192.168.31.161:${PORT}${BASE_PATH}`);
  console.log('============================================================');
});
