const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const { ACCESS_TOKEN } = require('../config');

router.post('/GetProfile.json', (req, res) => {
  const dir = path.join(__dirname, '../data');
  const file = path.join(dir, 'savedata.json');

  const profile = JSON.parse(fs.readFileSync(file, 'utf8'));

  console.log('-- Loaded successfully');

  res.status(200).json({ status: 0, crc: profile.crc, accessToken: ACCESS_TOKEN, synchronizedPlayerState: profile.synchronizedPlayerState });
});

router.post('/PushProfile.json', (req, res) => {
  const dir = path.join(__dirname, '../data');
  const file = path.join(dir, 'savedata.json');

  fs.writeFileSync(file, JSON.stringify(req.body, null, 2), 'utf8');

  console.log('-- Saved successfully')

  res.status(200).json({ status: 0, lastUpdate: Date.now(), numRings: 0, numRedRings: 0, score: 0, version: 9, accessToken: ACCESS_TOKEN });
});

module.exports = router;