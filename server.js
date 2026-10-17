#!/usr/bin/env node
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

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = __dirname;
const LOG_DIR = path.join(ROOT, 'logs');
const RESP_DIR = path.join(ROOT, 'responses');
const CONTENT_DIR = path.join(ROOT, 'content');
const CONFIG_PATH = path.join(ROOT, 'config.json');
const STATE_PATH = path.join(ROOT, 'state.json');

// --------------------------------------------------------------- constantes
// Extraidas del binario (libsonicjumpfever.so):
const HMAC_KEY = Buffer.from('PvQmck9?y+ZBjgAfqCpa8W67UhTu_D!S\u0000', 'latin1'); // 33 bytes, incluye el NUL
const NONCE_MAGIC = 0xbdc70e445308c215n;
const CHALLENGE_SIZE = 42;   // el cliente exige que `challenge` decodifique a 42 bytes
const API_VERSION = 0x10010017; // valor de `version` que envia el cliente

const ZONES = ['green_hill_zone', /*'mountain_zone',*/ 'jungle_zone', 'blue_sky_zone',
  'mechanical_zone'];

let i = 0 /* currentZone */,
    j = 1 /* nextZone */;

// ---------------------------------------------------------------- argumentos
function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) out[key] = true;
      else { out[key] = next; i++; }
    } else out._.push(a);
  }
  return out;
}
const ARGS = parseArgs(process.argv.slice(2));

// ------------------------------------------------------------------- config
const DEFAULT_CONFIG = {
  apiBase: '/SJF23',
  port: 8443,
  host: '0.0.0.0',
  // zona que jugara el cliente
  currentZone: 'jungle_zone',
  nextZone: 'mechanical_zone',
  previousZone: 'green_hill_zone',
  currentRoundId: 1,
  nextRoundId: 3,
  previousRoundId: 0,
  // formato de los campos DateTime en el JSON: 'unix' (segundos) o 'iso'
  dateTimeFormat: 'unix',
  accessToken: 'sjf-local-token',
  settingsUri: '',
  energyCount: 5,
  playerState: {},
  // opciones de depuracion servidas en serverSettings (probado: el juego las
  // lee de la configuracion general, no de aqui, pero no molestan)
  debug: { sjunlockAll: false, debug: false }
};

function loadConfig() {
  const cfg = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  if (fs.existsSync(CONFIG_PATH)) {
    try {
      Object.assign(cfg, JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')));
    } catch (e) {
      console.error('config.json invalido:', e.message);
    }
  }
  if (ARGS.port) cfg.port = Number(ARGS.port);
  if (ARGS.host) cfg.host = ARGS.host;
  if (ARGS.zone) cfg.currentZone = ARGS.zone;
  if (ARGS['date-time-format']) cfg.dateTimeFormat = ARGS['date-time-format'];
  return cfg;
}
let CONFIG = loadConfig();

// Recarga en caliente: si editas config.json (por ejemplo para cambiar de zona)
// se aplica en la siguiente peticion, sin reiniciar el servidor.
let configMtime = 0;
try { configMtime = fs.statSync(CONFIG_PATH).mtimeMs; } catch (_) { /* aun no existe */ }
function maybeReloadConfig() {
  try {
    const m = fs.statSync(CONFIG_PATH).mtimeMs;
    if (m !== configMtime) {
      configMtime = m;
      const next = loadConfig();
      const zoneChanged = next.currentZone !== CONFIG.currentZone;
      CONFIG = next;
      console.log(`[config] recargado${zoneChanged ? ' -> zona: ' + CONFIG.currentZone : ''}`);
    }
  } catch (_) { /* ignora */ }
}

// ------------------------------------------------------------------- estado
function loadState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
  } catch (_) {
    return { playerId: 1, uniqueId: 'local-0001', cohortId: 0, plays: 0 };
  }
}
const STATE = loadState();
function saveState() {
  try { fs.writeFileSync(STATE_PATH, JSON.stringify(STATE, null, 2)); } catch (_) {}
}

// ------------------------------------------------------------------ logging
for (const d of [LOG_DIR, RESP_DIR, CONTENT_DIR]) fs.mkdirSync(d, { recursive: true });
if (!fs.existsSync(CONFIG_PATH)) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2));
}
const LOG_FILE = path.join(LOG_DIR, 'requests.log');
function logBlock(text) {
  process.stdout.write(text);
  fs.appendFile(LOG_FILE, `[${new Date().toISOString()}] ${text}\n`, () => {});
}
function hexDump(buf, limit = 256) {
  const lines = [];
  const slice = buf.subarray(0, limit);
  for (let i = 0; i < slice.length; i += 16) {
    const c = slice.subarray(i, i + 16);
    lines.push('      ' + i.toString(16).padStart(4, '0') + '  ' +
      [...c].map((b) => b.toString(16).padStart(2, '0')).join(' '));
  }
  if (buf.length > limit) lines.push(`      ... (${buf.length - limit} bytes mas)`);
  return lines.join('\n');
}
function bodyText(buf) {
  if (buf.length === 0) return '(vacio)';
  const printable = [...buf.subarray(0, 200)].every(
    (b) => b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 128);
  if (!printable) return '(binario)\n' + hexDump(buf);
  const t = buf.toString('utf8');
  try { return JSON.stringify(JSON.parse(t), null, 2); } catch (_) { return t; }
}

// ------------------------------------------------------- DateTime y utilidades
function now() { return Math.floor(Date.now() / 1000); }
function dt(seconds) {
  if (CONFIG.dateTimeFormat === 'iso') return new Date(seconds * 1000).toISOString();
  return seconds;
}

// --------------------------------------------------------------- handshake
/**
 * El cliente (ConnectedProfileManager::handshakeCompleteCallback) hace:
 *   1. decodifica en base64 el campo `challenge`  -> debe dar 42 bytes
 *   2. coge los bytes [32..40) de ese buffer       -> llamemosle R (u64 LE)
 *   3. calcula M = (R * 0xbdc70e445308c215) XOR cid     <-- OJO AL XOR
 *   4. calcula HMAC-SHA256(clave = "PvQmck9?...!S\0" (33 bytes),
 *                          datos = u64le(cid) || u64le(M))
 *   5. compara ese HMAC con los bytes [0..32) del buffer decodificado
 *
 * Del desensamblado (arm64) de handshakeCompleteCallback:
 *   0x4B84E0  movz/movk x10 = 0xBDC70E445308C215
 *   0x4B84E4  ldr  x0,  [x29, #0x90]   ; R = reto[32..40)
 *   0x4B8508  madd x10, x0, x10, xzr   ; x10 = R * MAGIC
 *   0x4B851C  eor  x10, x10, x12       ; x10 ^= cid      <-- este era el que faltaba
 *   0x4B8548  str  x12, [x29, #0x40]   ; datos[0..8)  = cid
 *   0x4B854C  str  x10, [x29, #0x48]   ; datos[8..16) = (R*MAGIC) ^ cid
 *
 * Por eso el servidor construye el challenge como HMAC || R || 2 bytes de relleno.
 */
function buildChallenge(cid) {
  const rBytes = crypto.randomBytes(8);
  const R = rBytes.readBigUInt64LE(0);
  const M = ((((R * NONCE_MAGIC) & 0xFFFFFFFFFFFFFFFFn) ^ cid)) & 0xFFFFFFFFFFFFFFFFn;

  const data = Buffer.alloc(16);
  data.writeBigUInt64LE(cid & 0xFFFFFFFFFFFFFFFFn, 0);
  data.writeBigUInt64LE(M, 8);

  const hmac = crypto.createHmac('sha256', HMAC_KEY).update(data).digest();
  const decoded = Buffer.concat([hmac, rBytes, Buffer.alloc(CHALLENGE_SIZE - 40)]);
  return decoded.toString('base64');
}

function parseCid(value, rawBody) {
  // IMPORTANTE: `cid` es un entero de 64 bits. JSON.parse lo redondearia si
  // supera 2^53, asi que primero se busca el literal exacto en el cuerpo crudo.
  if (rawBody) {
    const m = /"cid"\s*:\s*(-?\d{1,20})/.exec(rawBody);
    if (m) {
      try { return BigInt(m[1]); } catch (_) { /* sigue */ }
    }
    const ms = /"cid"\s*:\s*"([^"]*)"/.exec(rawBody);
    if (ms) return parseCid(ms[1], null);
  }
  try {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') return BigInt(Math.trunc(value));
    if (typeof value === 'string') {
      const t = value.trim();
      if (/^-?\d+$/.test(t)) return BigInt(t);
      const b = Buffer.from(t, 'base64');
      if (b.length >= 8) return b.readBigUInt64LE(0);
    }
  } catch (_) { /* ignora */ }
  return 0n;
}

// --------------------------------------------------------------- respuestas
function serverSettings() {
  console.log("currentZone: " + ZONES[i], "nextZone: " + ZONES[j])

  let object = {
    serverTime: dt(now()),
    currentRoundId: CONFIG.currentRoundId,
    currentZone: ZONES[i], /*CONFIG.currentZone,*/
    expiryTime: dt(now()),
    nextZone: ZONES[j]/*CONFIG.nextZone*/,
    numRedRings: 1000,
    nextRoundId: CONFIG.nextRoundId,
    previousZone: CONFIG.previousZone,
    previousRoundId: CONFIG.previousRoundId
  }

  i = (i + 1) % 4;
  j = (j + 1) % 4;

  return object;
}

/**
 * network::SynchronizedPlayerState, 43 campos, extraidos del desensamblado de
 * su deserialize (arm64 0x32D778). Tipos IMPORTANTES:
 *   - los diez campos de personaje son long (int64), no int
 *   - `chaoStates` es un vector y es OBLIGATORIO
 * Se generan todos para que deserialize() no falle por un campo que falta.
 */
function synchronizedPlayerState() {
  const t = now();
  const s = {
    lastUpdate: dt(t),
    numRings: 0,
    numRedRings: 1000,
    score: 0,
    charTokenTime: dt(t),
    numCharTokens: 0,
    redRingTokenTime: dt(t),
    numRedRingTokens: 0,
    numChaoSearches: 0,
    numGoldTotem: 0,
    numHoopBoost: 0,
    numPowerDoubler: 0,
    numQuickFrenzy: 0,
    numRingStreak: 0,
    numTimeExtend: 0,
    numAnimalDoubler: 0,
    doubleRings: false,
    currentRoundId: CONFIG.currentRoundId,
    spinState: 0,
    lastFreeSpin: dt(t),
    pointsPending: 0,
    chaoStates: [],            // OBLIGATORIO
    awardFlags: 0,
    energyCount: CONFIG.energyCount !== undefined ? CONFIG.energyCount : 5,
    energyRechargeTime: dt(t),
    lastRateVersion: 0,
    version: API_VERSION,
    ftueState: 0,
    miscData0: 0,
    miscData1: 0,
    numConsecutiveLogins: 1
  };
  for (const c of ['sonic', 'tails', 'knuckles', 'amy', 'blaze', 'vector',
    'shadow', 'silver', 'rouge', 'cream']) {
    s[c] = 1;                  // long (int64)
  }
  Object.assign(s, CONFIG.playerState || {});
  return s;
}

function baseResponse(name, req, rawBody) {
  const token = CONFIG.accessToken;
  switch (name) {
    case 'Handshake': {
      const cid = parseCid(req && req.cid, rawBody);
      return {
        status: 0,
        challengeToken: crypto.randomBytes(16).toString('base64'),
        challenge: buildChallenge(cid)
      };
    }
    case 'Connect': {
      const isNew = STATE.newAccount !== false;
      if (isNew) {
        STATE.newAccount = false;
        STATE.lastLogin = now();
        saveState();
      }
      return {
        status: 0,
        playerId: STATE.playerId,
        isNewAccount: isNew,
        lastLogin: dt(STATE.lastLogin || now()),
        accessToken: token,
        uniqueId: STATE.uniqueId,
        // OJO: cohortId es un `long` (int64) en network::ConnectResponse. Si se
        // envia como cadena, deserialize() falla y el cliente reintenta Connect
        // con retroceso exponencial. Ver PROTOCOLO.md §4.
        cohortId: Number(STATE.cohortId) || 0,
        settingsUri: CONFIG.settingsUri,
        serverSettings: serverSettings(),
        lastUpdate: dt(now()),
        numRings: STATE.numRings || 0,
        numRedRings: 1000 || 0,
        score: STATE.score || 0,
        version: API_VERSION
      };
    }
    case 'GetSettings':
      return { status: 0, serverSettings: serverSettings() };
    case 'GetProfile':
      return {
        status: 0,
        synchronizedPlayerState: synchronizedPlayerState(),
        crc: 0,
        accessToken: token
      };
    case 'PushProfile':
      return {
        status: 0,
        lastUpdate: dt(now()),
        numRings: 0,
        numRedRings: 1000,
        score: 0,
        version: API_VERSION,
        accessToken: token
      };
    case 'GetScores':
      return { status: 0, scores: [], accessToken: token };
    case 'PostScore':
      return { status: 0, isHighScore: true, accessToken: token };
    case 'GetFriends':
      return { status: 0, friends: [], accessToken: token };
    case 'GetMessages':
      return { status: 0, messages: [], accessToken: token };
    case 'DeleteMessages':
      return { status: 0, accessToken: token };
    case 'InviteFriend':
      return { status: 0, invited: [], accessToken: token };
    case 'SendGift':
      return { status: 0, nextRequest: dt(now() + 3600), accessToken: token };
    case 'RequestEnergy':
      return { status: 0, requested: [], nextRequest: [], accessToken: token };
    case 'LogIAP':
      return { status: 0, accessToken: token };
    case 'AwardRequestItem':
      return { status: 0, accessToken: token };
    default:
      return { status: 0 };
  }
}

function responseFor(name, req, rawBody) {
  for (const cand of [`${name}.json`, `${name}.json.txt`]) {
    const p = path.join(RESP_DIR, cand);
    if (fs.existsSync(p)) {
      try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
      catch (e) { console.error(`  !! ${cand} invalido: ${e.message}`); }
    }
  }
  return baseResponse(name, req, rawBody);
}

// -------------------------------------------------------------------- HTTP
function send(res, code, body, type = 'application/json') {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  res.writeHead(code, {
    'Content-Type': type,
    'Content-Length': buf.length,
    // Connection: close evita que un cliente que lea hasta el fin del flujo se
    // quede esperando; es lo mas conservador posible.
    'Connection': 'close'
  });
  res.end(buf);
}

// ------------------------------------------------------------ diagnostico
// Huella del propio codigo, para poder comprobar de un vistazo si el servidor
// que esta corriendo es el ultimo (aparece en el arranque y en /__status).
let CODE_VERSION = 'desconocida';
try {
  CODE_VERSION = crypto.createHash('sha256')
    .update(fs.readFileSync(__filename)).digest('hex').slice(0, 12);
} catch (_) { /* ignora */ }

// El juego reintenta el handshake cada ~14 s y nunca manda /Connect.json.
// Estos contadores ayudan a ver que esta pasando en cada ciclo.
const STATS = { codeVersion: CODE_VERSION, handshakes: 0, connects: 0, other: {}, clients: {}, lastHandshake: null };
function noteRequest(name, ip, body) {
  if (name === 'Handshake') {
    STATS.handshakes++;
    STATS.clients[ip] = (STATS.clients[ip] || 0) + 1;
    let cid = null;
    const m = /"cid"\s*:\s*(-?\d{1,20})/.exec(body || '');
    if (m) cid = m[1];
    const prev = STATS.lastHandshake;
    if (prev && prev.cid === cid) {
      logBlock(`  !! el cliente REPITE el mismo cid (${cid}) -> esta reintentando el handshake\n`);
    }
    STATS.lastHandshake = { cid, at: Date.now(), ip };
    logBlock(`  [diag] handshake #${STATS.handshakes} de ${ip}  cid=${cid}\n`);
  } else if (name === 'Connect') {
    STATS.connects++;
    logBlock(`  [diag] *** CONNECT recibido (#${STATS.connects}) -> el handshake fue aceptado ***\n`);
  } else {
    STATS.other[name] = (STATS.other[name] || 0) + 1;
  }
}

function serveFile(req, res, full) {
  const norm = path.normalize(full);
  if (!norm.startsWith(CONTENT_DIR) || !fs.existsSync(norm) || !fs.statSync(norm).isFile()) {
    logBlock(`  !! contenido no encontrado: ${full}\n`);
    return send(res, 404, JSON.stringify({ error: 'not found' }));
  }
  const size = fs.statSync(norm).size;
  let start = 0, end = size - 1, code = 200;
  const m = req.headers.range && /bytes=(\d*)-(\d*)/.exec(req.headers.range);
  if (m) {
    if (m[1]) start = parseInt(m[1], 10);
    if (m[2]) end = parseInt(m[2], 10);
    code = 206;
  }
  const headers = {
    'Content-Type': norm.endsWith('.json') ? 'application/json'
      : norm.endsWith('.xml') ? 'application/xml' : 'application/octet-stream',
    'Content-Length': end - start + 1,
    'Accept-Ranges': 'bytes'
  };
  if (code === 206) headers['Content-Range'] = `bytes ${start}-${end}/${size}`;
  logBlock(`  -> fichero ${path.basename(norm)} (${size} bytes, ${code})\n`);
  res.writeHead(code, headers);
  fs.createReadStream(norm, { start, end }).pipe(res);
}

const ENDPOINT_RE = /^\/([A-Za-z0-9_]+)\.json$/;

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    maybeReloadConfig();
    const body = Buffer.concat(chunks);
    const clean = (req.url || '/').split('?')[0];
    const base = CONFIG.apiBase || '';
    let rel = clean.startsWith(base) ? clean.slice(base.length) : clean;
    rel = rel.replace(/^\/+/, '');

    const headerLines = [];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      headerLines.push(`    ${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
    }
    logBlock(`\n================ ${req.method} ${req.url} ================\n` +
      `cliente: ${req.socket.remoteAddress}\n` +
      `cabeceras:\n${headerLines.join('\n')}\n` +
      `cuerpo (${body.length} bytes):\n${bodyText(body)}\n`);

    let parsed = {};
    try { parsed = JSON.parse(body.toString('utf8')); } catch (_) { /* no json */ }

    if (rel === '__log') {
      const data = fs.existsSync(LOG_FILE) ? fs.readFileSync(LOG_FILE) : Buffer.from('');
      return send(res, 200, data, 'text/plain; charset=utf-8');
    }
    if (rel === '__config') return send(res, 200, JSON.stringify(CONFIG, null, 2));
    if (rel === '__state') return send(res, 200, JSON.stringify(STATE, null, 2));
    if (rel === '__health') return send(res, 200, JSON.stringify({ ok: true }));
    if (rel === '__status') return send(res, 200, JSON.stringify(STATS, null, 2));
    if (rel === '__zones') return send(res, 200, JSON.stringify(ZONES));

    if (rel.startsWith('content/') || /\.(sla|xml|dat|sav)$/i.test(rel)) {
      return serveFile(req, res, path.join(CONTENT_DIR, rel));
    }

    const m = ENDPOINT_RE.exec('/' + rel);
    if (!m) {
      logBlock(`  !! ruta desconocida, devuelvo {} (200)\n`);
      return send(res, 200, '{}');
    }

    const name = m[1];
    noteRequest(name, req.socket.remoteAddress, body.toString('utf8'));
    const payload = responseFor(name, parsed, body.toString('utf8'));
    if ((name === 'Connect' || name === 'GetSettings') && payload.serverSettings) {
      logBlock(`  [ZONA] sirviendo currentZone="${payload.serverSettings.currentZone}"` +
        ` nextZone="${payload.serverSettings.nextZone}" -> la zona jugable cambia a esa\n`);
    }
    const json = JSON.stringify(payload);
    logBlock(`  -> respuesta ${name} (${json.length} B): ${json}\n`);
    send(res, 200, json);
  });
});

function localIPs() {
  const out = [];
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const i of ifaces[name] || []) {
      if (i.family === 'IPv4' && !i.internal) out.push(i.address);
    }
  }
  return out;
}

server.listen(CONFIG.port, CONFIG.host, () => {
  const base = CONFIG.apiBase || '';
  console.log('=========================================================');
  console.log(' Sonic Jump Fever 1.6.1 - servidor propio');
  console.log(' codigo: ' + CODE_VERSION);
  console.log('=========================================================');
  console.log(` escuchando en   http://${CONFIG.host}:${CONFIG.port}${base}`);
  console.log(' URL para el APK parcheado:');
  for (const ip of localIPs()) console.log(`    http://${ip}:${CONFIG.port}${base}`);
  console.log('');
  console.log(` ZONA ACTUAL     ${CONFIG.currentZone}`);
  console.log(` zona siguiente  ${CONFIG.nextZone}`);
  console.log(` zona anterior   ${CONFIG.previousZone}`);
  console.log(` formato fechas  ${CONFIG.dateTimeFormat}`);
  console.log('');
  console.log(` log             ${LOG_FILE}`);
  console.log(` ver por web     http://localhost:${CONFIG.port}/__log`);
  console.log(` respuestas      ${RESP_DIR}\\<Endpoint>.json`);
  console.log(' Ctrl+C para parar.');
  console.log('');
});
