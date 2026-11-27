const express = require('express');
const router = express.Router();

router.post(`/InviteFriend.json`, (req, res) => {
  res.status(200).json({ status: 0, invited: [], accessToken: ACCESS_TOKEN });
})

module.exports = router;