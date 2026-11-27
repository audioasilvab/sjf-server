const express = require('express');
const router = express.Router();

const { ACCESS_TOKEN } = require('../config');

router.post('/GetMessages.json', (req, res) => {
  let pending = []

  res.status(200).json({ status: 0, messages: pending, accessToken: ACCESS_TOKEN });
});

module.exports = router;