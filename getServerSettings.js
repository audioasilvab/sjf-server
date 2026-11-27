const fs = require('fs');
const path = require('path');

const { ZONE_STATE, ROUND_DURATION_MS } = require('./config');

function pickNextZone(current) {
  const zones = ['mechanical_zone', 'blue_sky_zone', 'green_hill_zone', 'jungle_zone'];
  const idx = zones.indexOf(current);
  return zones[(idx + 1) % zones.length];
}

function tickRound() {
  const now = Date.now();
  if (now >= ZONE_STATE.startTime + ROUND_DURATION_MS) {
    // Rotar
    ZONE_STATE.previousRoundId = ZONE_STATE.roundId;
    ZONE_STATE.previousZone = ZONE_STATE.zone;

    ZONE_STATE.roundId = ZONE_STATE.nextRoundId + Math.floor(Math.random() * 350001)/* + parseInt(Math.random() * 100)*/;
    ZONE_STATE.zone = ZONE_STATE.nextZone;

    // Siguiente (puedes poner una lista/rotación real)
    ZONE_STATE.nextRoundId = ZONE_STATE.roundId + 1;
    ZONE_STATE.nextZone = pickNextZone(ZONE_STATE.zone);

    // Avanzar startTime en múltiplos exactos para no acumular drift
    while (now >= ZONE_STATE.startTime + ROUND_DURATION_MS) {
      ZONE_STATE.startTime += ROUND_DURATION_MS;
    }

    try {
    	fs.writeFileSync(path.join(__dirname, '/data/zone.json'), JSON.stringify(ZONE_STATE, null, 2), 'utf8');
	    console.log(' 💾 Partida guardada en save.json');
	  } catch (e) {
	    console.error(' Error al guardar:', e);
	  }

    console.log(` Ronda rotada → roundId=${ZONE_STATE.roundId}, zone=${ZONE_STATE.zone}`);
  }
}

function getServerSettings() {
  tickRound();

  return {
    serverTime: Date.now(),
    currentRoundId: ZONE_STATE.roundId,
    currentZone: ZONE_STATE.zone,
    expiryTime: ZONE_STATE.startTime + ROUND_DURATION_MS,
    nextZone: ZONE_STATE.nextZone,
    nextRoundId: ZONE_STATE.nextRoundId,
    previousZone: ZONE_STATE.previousZone,
    previousRoundId: ZONE_STATE.previousRoundId
  };
}

module.exports = { getServerSettings }