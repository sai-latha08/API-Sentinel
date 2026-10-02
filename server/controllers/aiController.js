const { askSentinelAI } = require('../services/securityEngineClient');
const { dbStore } = require('../services/db');

exports.askSentinel = async (req, res, next) => {
  try {
    const { query, findingId, endpoint, scanId } = req.body;

    if (!query || !query.trim()) {
      return res.status(400).json({ error: 'Question query cannot be empty.' });
    }

    let contextData = null;
    if (scanId) {
      const scan = await dbStore.getScanById(scanId);
      if (scan) {
        contextData = {
          findings: scan.findings,
          endpoints: scan.endpoints,
          riskScore: scan.riskScore,
          apiTitle: scan.apiTitle
        };
      }
    }

    const aiResponse = await askSentinelAI(query, findingId, endpoint, contextData);

    res.json({
      success: true,
      data: aiResponse
    });
  } catch (err) {
    next(err);
  }
};
