const crypto = require('crypto');
const express = require('express');

const router = express.Router();

// ============================================================
// CONSTANTES DEL PROTOCOLO (PROTOCOLO.md §3)
// ============================================================
// Clave de 32 bytes + NUL = 33 bytes (extraída del .so)
const HMAC_KEY = Buffer.concat([
  Buffer.from('PvQmck9?y+ZBjgAfqCpa8W67UhTu_D!S', 'ascii'),
  Buffer.from([0x00])
]);

// Constante del algoritmo
const MULT = 0xBDC70E445308C215n;

// ============================================================
// HELPERS
// ============================================================
function u64le(value) {
  // Acepta BigInt o Number, devuelve Buffer de 8 bytes little-endian
  const buf = Buffer.alloc(8);
  let v = BigInt(value) & 0xFFFFFFFFFFFFFFFFn;
  for (let i = 0; i < 8; i++) {
    buf[i] = Number(v & 0xFFn);
    v >>= 8n;
  }
  return buf;
}

function buildChallenge(cid) {
  // cid = BigInt con signo, tal como lo envió el cliente
  const cidU64 = BigInt.asUintN(64, cid);

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
    Buffer.from([0x00, 0x00])
  ]);

  return {
    challenge: challengeBuf.toString('base64'),
    challengeToken: crypto.randomBytes(16).toString('hex'),
    R, M, cidU64
  };
}

// ============================================================
// RUTA
// ============================================================
router.post('/Handshake.json', (req, res) => {
  const cid = req.cidExact;
  if (cid === null) {
    console.log(' No se pudo extraer cid del body');
    return res.status(400).json({ status: 1 });
  }

  console.log(` HANDSHAKE: cid=${cid}, version=0x${req.version.toString(16).toUpperCase()}`);

  const { challenge, challengeToken } = buildChallenge(cid);

  console.log(`   → challenge (${Buffer.from(challenge, 'base64').length} bytes): ${challenge.substring(0, 20)}...`);
  res.status(200).json({ status: 0, challengeToken, challenge });
});

module.exports = router;