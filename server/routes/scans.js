const express = require('express');
const router = express.Router();
const scanController = require('../controllers/scanController');
const upload = require('../middleware/upload');
const { authenticateToken } = require('../middleware/auth');

router.post('/upload', authenticateToken, upload.single('specFile'), scanController.createScanFromFile);
router.post('/raw', authenticateToken, scanController.createScanFromRaw);
router.get('/', authenticateToken, scanController.getAllScans);
router.get('/samples', scanController.getSampleSpecs);
router.get('/:id', authenticateToken, scanController.getScanById);
router.delete('/:id', authenticateToken, scanController.deleteScan);

module.exports = router;
