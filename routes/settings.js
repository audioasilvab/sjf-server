const express = require('express');
const router = express.Router();

const { getServerSettings } = require('../getServerSettings');

router.get(`/GetSettings.json`, (req, res) => {
  console.log(' GetSettings');
  res.status(200).json({
    status: 0,
    serverSettings: getServerSettings()
  });
});

module.exports = router;