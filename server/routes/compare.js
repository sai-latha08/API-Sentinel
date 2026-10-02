const express = require('express');
const router = express.Router();
const compareController = require('../controllers/compareController');
const { authenticateToken } = require('../middleware/auth');

router.post('/', authenticateToken, compareController.compareScans);

module.exports = router;
