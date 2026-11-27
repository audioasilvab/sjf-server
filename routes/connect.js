const express = require('express');
const router = express.Router();

const { PLAYER, ACCESS_TOKEN, SETTINGS_URI } = require('../config');

const { getServerSettings } = require('../getServerSettings');

router.post('/Connect.json', (req, res) => {
  const body = req.body || {};

  //PLAYER.deviceId = body.deviceId;
  PLAYER.facebook.firstName = body.firstName;
  PLAYER.facebook.facebookId = body.facebookId;
  PLAYER.facebook.facebookAccessToken = body.facebookAccessToken;
  PLAYER.state.lastLogin = Date.now();
  PLAYER.state.lastUpdate = PLAYER.state.lastLogin;

  console.log(` CONNECT: playerId=${PLAYER.playerId}` +
    (PLAYER.facebookId ? `, facebookId=${PLAYER.facebookId}` : ''));

  res.status(200).json({
    status: 0,
    playerId: PLAYER.playerId,
    isNewAccount: false,
    lastLogin: PLAYER.state.lastLogin,
    accessToken: ACCESS_TOKEN,
    uniqueId: PLAYER.uniqueId,
    cohortId: PLAYER.cohortId,
    settingsUri: SETTINGS_URI,
    serverSettings: getServerSettings(),
    lastUpdate: PLAYER.state.lastUpdate,
    numRings: PLAYER.state.numRings,
    numRedRings: PLAYER.state.numRedRings,
    score: PLAYER.state.score,
    version: PLAYER.state.version
  });
});

module.exports = router;