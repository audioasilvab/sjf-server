#!/usr/bin/env node
/**
 * Cliente de prueba: simula la secuencia que hace el juego contra el servidor.
 *   node sjf-server/test-client.js [http://127.0.0.1:8443/SJF23]
 */
'use strict';

const crypto = require('crypto');

const BASE = process.argv[2] || 'http://127.0.0.1:8443/SJF23';
const HMAC_KEY = Buffer.from('PvQmck9?y+ZBjgAfqCpa8W67UhTu_D!S\u0000', 'latin1');
const NONCE_MAGIC = 0xbdc70e445308c215n;

async function post(endpoint, payload, rawBody) {
  const res = await fetch(BASE + endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'HL-Auth': 'test' },
    body: rawBody !== undefined ? rawBody : JSON.stringify(payload)
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (_) { /* no json */ }
  return { status: res.status, json, text };
}

function verifyChallenge(challengeB64, cid) {
  const decoded = Buffer.from(challengeB64, 'base64');
  if (decoded.length !== 42) return { ok: false, why: `len=${decoded.length} != 42` };
  const cidLe = Buffer.alloc(8);
  cidLe.writeBigUInt64LE(cid & 0xFFFFFFFFFFFFFFFFn, 0);
  const R = decoded.readBigUInt64LE(32);
  //  madd x10, x0, x10, xzr ; eor x10, x10, x12   (ver PROTOCOLO.md §3)
  const M = ((((R * NONCE_MAGIC) & 0xFFFFFFFFFFFFFFFFn) ^ cid)) & 0xFFFFFFFFFFFFFFFFn;
  const mLe = Buffer.alloc(8);
  mLe.writeBigUInt64LE(M, 0);
  const expect = crypto.createHmac('sha256', HMAC_KEY)
    .update(Buffer.concat([cidLe, mLe])).digest();
  return { ok: expect.equals(decoded.subarray(0, 32)) };
}

(async () => {
  let fails = 0;
  const check = (cond, label, extra = '') => {
    console.log(`${cond ? 'OK  ' : 'FALLA'} ${label}${extra ? '  ' + extra : ''}`);
    if (!cond) fails++;
  };

  // 1) Handshake. El cid es un entero de 64 bits: se envia como literal exacto
  // (igual que hace el juego) para comprobar que el servidor no pierde precision.
  const cid = BigInt(Math.floor(Math.random() * 1e15)) * 977n + 123456789n;
  const hsBody = `{"version":${0x10010017},"cid":${cid.toString()}}`;
  const hs = await post('/Handshake.json', null, hsBody);
  check(hs.status === 200 && hs.json, 'Handshake responde');
  check(hs.json && hs.json.status === 0, 'Handshake status = 0');
  const v = hs.json && verifyChallenge(hs.json.challenge, cid);
  check(v && v.ok, 'el reto pasa la verificacion HMAC del cliente',
    `(cid=${cid})` + (v && v.why ? ' ' + v.why : ''));
  check(hs.json && typeof hs.json.challengeToken === 'string', 'challengeToken presente');

  // 2) Connect
  const cn = await post('/Connect.json', {
    challengeToken: hs.json.challengeToken,
    response: 'xmF1bmN0aW9u',
    deviceId: 'test-device',
    mode: 0,
    numPlays: 0,
    numRings: 0,
    numRedRings: 0,
    xp: 0,
    lastPlayerId: 0
  });
  check(cn.status === 200 && cn.json.status === 0, 'Connect status = 0');
  check(cn.json.accessToken === undefined || typeof cn.json.accessToken === 'string',
    'Connect devuelve accessToken');
  check(cn.json.playerId > 0, 'Connect devuelve playerId');
  const zoneInConnect = cn.json.serverSettings && cn.json.serverSettings.currentZone;
  check(!!zoneInConnect, 'Connect incluye serverSettings.currentZone', zoneInConnect);

  // 3) GetSettings
  const gs = await post('/GetSettings.json', {});
  check(gs.json && gs.json.status === 0, 'GetSettings status = 0');
  const ss = gs.json && gs.json.serverSettings;
  check(!!ss, 'GetSettings devuelve serverSettings');
  if (ss) {
    for (const k of ['serverTime', 'currentRoundId', 'currentZone', 'expiryTime',
      'nextZone', 'nextRoundId', 'previousZone', 'previousRoundId']) {
      check(k in ss, `  serverSettings.${k}`, String(ss[k]));
    }
  }

  // 4) GetProfile
  const gp = await post('/GetProfile.json', {});
  check(gp.json && gp.json.status === 0, 'GetProfile status = 0');
  check(gp.json && gp.json.synchronizedPlayerState, 'GetProfile devuelve el estado del jugador');

  // 5) resto de endpoints
  for (const [ep, body] of [
    ['/PushProfile.json', {}], ['/GetScores.json', {}], ['/PostScore.json', { score: 1 }],
    ['/GetFriends.json', {}], ['/GetMessages.json', {}], ['/DeleteMessages.json', {}],
    ['/InviteFriend.json', {}], ['/SendGift.json', {}], ['/RequestEnergy.json', {}],
    ['/LogIAP.json', {}], ['/AwardRequestItem.json', {}]
  ]) {
    const r = await post(ep, body);
    check(r.status === 200 && r.json && r.json.status === 0, `${ep} status = 0`);
  }

  console.log('');
  console.log(fails === 0 ? 'TODAS LAS PRUEBAS PASAN' : `${fails} PRUEBAS FALLIDAS`);
  process.exitCode = fails === 0 ? 0 : 1;
})();
