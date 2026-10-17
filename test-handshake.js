#!/usr/bin/env node
/**
 * Comprueba que el `challenge` que genera el servidor pasaria la verificacion
 * del cliente. Reimplementa, paso a paso, lo que hace
 * network::ConnectedProfileManager::handshakeCompleteCallback en el .so:
 *
 *   1. Base64::decode(challenge)                    -> 42 bytes
 *   2. x12 = cid (int64 del jugador)
 *      x0  = decoded[32..40)                        (la ranura [x29+0x90])
 *      x10 = x0 * 0xbdc70e445308c215
 *      datos = u64le(x12) || u64le(x10)
 *   3. HMACSHA256(key = "PvQmck9?y+ZBjgAfqCpa8W67UhTu_D!S\0" (33 B), datos)
 *   4. compara 32 bytes con decoded[0..32)
 *
 * Uso: node sjf-server/test-handshake.js
 */
'use strict';

const crypto = require('crypto');

const HMAC_KEY = Buffer.from('PvQmck9?y+ZBjgAfqCpa8W67UhTu_D!S\u0000', 'latin1');
const NONCE_MAGIC = 0xbdc70e445308c215n;

// --- copia de la logica del servidor (server.js) --------------------------
function buildChallenge(cid) {
  const rBytes = crypto.randomBytes(8);
  const R = rBytes.readBigUInt64LE(0);
  const M = ((((R * NONCE_MAGIC) & 0xFFFFFFFFFFFFFFFFn) ^ cid)) & 0xFFFFFFFFFFFFFFFFn;
  const data = Buffer.alloc(16);
  data.writeBigUInt64LE(cid & 0xFFFFFFFFFFFFFFFFn, 0);
  data.writeBigUInt64LE(M, 8);
  const hmac = crypto.createHmac('sha256', HMAC_KEY).update(data).digest();
  return Buffer.concat([hmac, rBytes, Buffer.alloc(2)]).toString('base64');
}

// --- lo que hace el cliente ----------------------------------------------
function clientVerify(challengeB64, cid) {
  const decoded = Buffer.from(challengeB64, 'base64');
  if (decoded.length !== 42) {
    return { ok: false, why: `decodifica a ${decoded.length} bytes, el cliente exige 42` };
  }
  const cidLe = Buffer.alloc(8);
  cidLe.writeBigUInt64LE(cid & 0xFFFFFFFFFFFFFFFFn, 0);
  const R = decoded.readBigUInt64LE(32);            // bytes [32..40)
  //  madd x10, x0, x10, xzr   ; x10 = R * MAGIC
  //  eor  x10, x10, x12       ; x10 ^= cid
  const M = ((((R * NONCE_MAGIC) & 0xFFFFFFFFFFFFFFFFn) ^ cid)) & 0xFFFFFFFFFFFFFFFFn;
  const mLe = Buffer.alloc(8);
  mLe.writeBigUInt64LE(M, 0);
  const expect = crypto.createHmac('sha256', HMAC_KEY)
    .update(Buffer.concat([cidLe, mLe])).digest();
  const got = decoded.subarray(0, 32);
  return { ok: expect.equals(got), expected: expect.toString('hex'), got: got.toString('hex') };
}

// --- pruebas --------------------------------------------------------------
let fails = 0;
const cids = [0n, 1n, 0xDEADBEEFCAFEBABEn, 0xFFFFFFFFFFFFFFFFn,
  BigInt(Date.now()) * 1000003n & 0xFFFFFFFFFFFFFFFFn];

for (const cid of cids) {
  const challenge = buildChallenge(cid);
  const r = clientVerify(challenge, cid);
  const tag = r.ok ? 'OK  ' : 'FALLA';
  if (!r.ok) fails++;
  console.log(`${tag} cid=0x${cid.toString(16).padStart(16, '0')}  challenge=${challenge.slice(0, 24)}...  ${r.why || ''}`);
  if (!r.ok) console.log(`      esperado ${r.expected}\n      recibido ${r.got}`);
}

// caso negativo: un challenge manipulado debe fallar
const bad = Buffer.alloc(42, 7).toString('base64');
const rb = clientVerify(bad, 123n);
console.log(`${rb.ok ? 'FALLA' : 'OK  '} challenge invalido rechazado correctamente`);
if (rb.ok) fails++;

console.log('');
console.log(fails === 0 ? 'TODAS LAS PRUEBAS PASAN' : `${fails} PRUEBAS FALLIDAS`);
process.exit(fails === 0 ? 0 : 1);
