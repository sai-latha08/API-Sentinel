const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');
const { authenticateToken } = require('../middleware/auth');

router.get('/:id', authenticateToken, reportController.getReportData);

module.exports = router;
