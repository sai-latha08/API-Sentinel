const { compareScansEngine } = require('../services/securityEngineClient');
const { dbStore } = require('../services/db');

exports.compareScans = async (req, res, next) => {
  try {
    const { baseScanId, targetScanId } = req.body;

    if (!baseScanId || !targetScanId) {
      return res.status(400).json({ error: 'Both baseScanId and targetScanId are required.' });
    }

    const baseScan = await dbStore.getScanById(baseScanId);
    const targetScan = await dbStore.getScanById(targetScanId);

    if (!baseScan || !targetScan) {
      return res.status(404).json({ error: 'One or both scan records could not be found.' });
    }

    const comparison = await compareScansEngine(baseScan, targetScan);

    res.json({
      success: true,
      comparison: {
        baseScan: {
          id: baseScan._id || baseScan.id,
          apiTitle: baseScan.apiTitle,
          fileName: baseScan.fileName,
          riskScore: baseScan.riskScore,
          riskLevel: baseScan.riskLevel,
          findingCount: baseScan.findingCount,
          createdAt: baseScan.createdAt
        },
        targetScan: {
          id: targetScan._id || targetScan.id,
          apiTitle: targetScan.apiTitle,
          fileName: targetScan.fileName,
          riskScore: targetScan.riskScore,
          riskLevel: targetScan.riskLevel,
          findingCount: targetScan.findingCount,
          createdAt: targetScan.createdAt
        },
        ...comparison
      }
    });
  } catch (err) {
    next(err);
  }
};
