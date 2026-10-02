const { dbStore } = require('../services/db');

exports.getReportData = async (req, res, next) => {
  try {
    const { id } = req.params;
    const scan = await dbStore.getScanById(id);
    if (!scan) {
      return res.status(404).json({ error: 'Scan record not found.' });
    }

    const report = {
      meta: {
        reportId: `RPT-${(scan._id || scan.id).toString().slice(-6).toUpperCase()}`,
        generatedAt: new Date().toISOString(),
        scanDate: scan.createdAt,
        product: 'API Sentinel Enterprise Posture Platform'
      },
      api: {
        title: scan.apiTitle,
        version: scan.apiVersion,
        fileName: scan.fileName,
        format: scan.specFormat,
        endpointCount: scan.endpointCount,
        servers: scan.servers || []
      },
      securityScore: {
        score: scan.riskScore,
        level: scan.riskLevel,
        severitySummary: scan.severitySummary,
        categoryScores: scan.categoryScores,
        breakdown: scan.scoreBreakdown
      },
      executiveSummary: scan.executiveSummary,
      criticalFindings: (scan.findings || []).filter(f => f.severity === 'CRITICAL'),
      highFindings: (scan.findings || []).filter(f => f.severity === 'HIGH'),
      mediumFindings: (scan.findings || []).filter(f => f.severity === 'MEDIUM'),
      lowFindings: (scan.findings || []).filter(f => f.severity === 'LOW' || f.severity === 'INFO'),
      allFindings: scan.findings || [],
      endpoints: scan.endpoints || [],
      recommendations: scan.recommendations || [],
      methodology: {
        framework: 'OWASP API Security Top 10 (2023)',
        scoringModel: 'OWASP Multi-Factor Risk Rating Methodology',
        staticAnalysisRules: 26,
        confidenceThreshold: 0.70
      }
    };

    res.json({
      success: true,
      report
    });
  } catch (err) {
    next(err);
  }
};
