const fs = require('fs');
const path = require('path');

const PORT = 8443;
const HOST = '0.0.0.0';
const BASE_PATH = '/SJF23';
const ACCESS_TOKEN = 'devtoken';
const SETTINGS_URI = `${BASE_PATH}/GetSettings.json`;

const CONFIG_PATH = path.join(__dirname, '/data/zone.json');

console.log(CONFIG_PATH)

let ZONE_STATE = {};

try {
  ZONE_STATE = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  console.log(` Configuración cargada desde ${CONFIG_PATH}`);

} catch (err) {
  console.warn(`⚠ No se pudo cargar config.json (${err.message}); usando valores por defecto.`);

  ZONE_STATE = {
	  roundId: 1,
	  zone: 'mechanical_zone',
	  nextRoundId: 2,
	  nextZone: 'jungle_zone',
	  previousRoundId: 0,
	  previousZone: 'blue_sky_zone',
	  startTime: Date.now()
	};

	try {
    fs.writeFileSync(path.join(__dirname, '/data/zone.json'), JSON.stringify(ZONE_STATE, null, 2), 'utf8');
    console.log(' 💾 Partida guardada en save.json');
  } catch (e) {
    console.error(' Error al guardar:', e);
  }
}

const ROUND_DURATION_MS = 6 * 60 * 1000;
const GIFT_COOLDOWN_S = 6 * 60 * 1000;
const ENERGY_COOLDOWN_S = 6 * 60 * 1000;
const GIFT_REPLY_S = 120;
const ENERGY_REPLY_S = 180;
const MAX_FRIENDS = 50;

const GIFT_BOOSTER_MS = 6 * 60 * 1000;

const INITIAL_VERSION = 9;

var PLAYER;

try {
  const saved = JSON.parse(fs.readFileSync(path.join(__dirname, 'data/save.json'), 'utf8'));

  if (saved.state) {
    Object.assign(PLAYER.state, saved.state);   // Object.assign(destino, fuente)
  }
  console.log(' Partida cargada');
} catch (e) {
  console.log(' No hay partida guardada, empezando de cero.');

  PLAYER = {
		playerId: 1,
	  accessToken: ACCESS_TOKEN,
	  deviceId: '',
	  uniqueId: 'local-01',
	  cohortId: 0,
	  facebook: {
	  	firstName: 'Sonic Player',
	  	facebookId: '100001',
	  	facebookAccessToken: '',
	  	scope: 'public_profile,user_friends'
	  },
	  state: {
	  	lastUpdate: 0,
		  numRings: 0,
		  numRedRings: 0,
		  score: 0,
		  charTokenTime: 0,
		  numCharTokens: 0,
		  redRingTokenTime: 0,
		  numRedRingTokens: 0,
		  numChaoSearches: 0,
		  sonic: 0, tails: 0, knuckles: 0, amy: 0, blaze: 0,
		  vector: 0, shadow: 0, silver: 0, rouge: 0, cream: 0,
		  numGoldTotem: 0, numHoopBoost: 0, numPowerDoubler: 0,
		  numQuickFrenzy: 0, numRingStreak: 0, numTimeExtend: 0,
		  numAnimalDoubler: 0,
		  doubleRings: true,
		  currentRoundId: 0,
		  spinState: 0,
		  lastFreeSpin: 0,
		  pointsPending: 0,
		  chaoStates: [],
		  awardFlags: 0,
		  energyCount: 0,
		  energyRechargeTime: 0,
		  lastRateVersion: 0,
		  version: INITIAL_VERSION,
		  ftueState: 7,
		  miscData0: 0,
		  miscData1: 0,
		  numConsecutiveLogins: 0,
		  lastLogin: Date.now()
	  },
	  crc: 0
	}

	try {
    fs.writeFileSync(path.join(__dirname, '/data/save.json'), JSON.stringify(PLAYER, null, 2), 'utf8');
    console.log(' Partida guardada en save.json');
  } catch (e) {
    console.error(' Error al guardar:', e);
  }
}



module.exports = {
  PORT,
  HOST,
  BASE_PATH,
  ACCESS_TOKEN,
  ZONE_STATE,
  PLAYER,
  ROUND_DURATION_MS,
  SETTINGS_URI,
}