const fs = require('fs');
const path = require('path');
const { dbStore } = require('../services/db');
const { analyzeSpecification } = require('../services/securityEngineClient');

// Sample specs loading helper
function loadSampleSpec(fileName) {
  const fullPath = path.join(__dirname, '..', '..', 'sample-specs', fileName);
  if (fs.existsSync(fullPath)) {
    return fs.readFileSync(fullPath, 'utf8');
  }
  return null;
}

exports.createScanFromFile = async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No specification file uploaded. Please select a JSON or YAML file.' });
    }

    const fileContent = req.file.buffer.toString('utf8');
    const fileName = req.file.originalname;
    const fileType = fileName.endsWith('.yaml') || fileName.endsWith('.yml') ? 'yaml' : 'json';
    const projectId = req.body.projectId || 'proj_default';

    // Send to Python Security Engine for real parsing & analysis
    const analysisResult = await analyzeSpecification(fileContent, fileName, fileType);

    // Persist full scan to DB
    const scanRecord = await dbStore.createScan({
      projectId,
      fileName,
      fileType,
      specFormat: analysisResult.spec_format,
      apiTitle: analysisResult.api_title,
      apiVersion: analysisResult.api_version,
      description: analysisResult.description,
      servers: analysisResult.servers,
      endpointCount: analysisResult.total_endpoints,
      findingCount: analysisResult.total_findings,
      riskScore: analysisResult.risk_score,
      riskLevel: analysisResult.risk_level,
      severitySummary: analysisResult.severity_summary,
      categoryScores: analysisResult.category_scores,
      executiveSummary: analysisResult.executive_summary,
      scoreBreakdown: analysisResult.score_breakdown,
      recommendations: analysisResult.recommendations,
      attackSurface: analysisResult.attack_surface,
      findings: analysisResult.findings,
      endpoints: analysisResult.endpoints,
      status: 'COMPLETED',
      createdBy: req.user ? req.user.email : 'demo@apisentinel.dev'
    });

    res.status(201).json({
      success: true,
      message: 'Security analysis completed successfully.',
      scan: scanRecord
    });
  } catch (err) {
    next(err);
  }
};

exports.createScanFromRaw = async (req, res, next) => {
  try {
    const { specContent, fileName = 'pasted_spec.json', fileType = 'json', projectId = 'proj_default' } = req.body;

    if (!specContent || !specContent.trim()) {
      return res.status(400).json({ error: 'Specification content cannot be empty.' });
    }

    // Send to Python Security Engine for real parsing & analysis
    const analysisResult = await analyzeSpecification(specContent, fileName, fileType);

    // Persist full scan to DB
    const scanRecord = await dbStore.createScan({
      projectId,
      fileName,
      fileType,
      specFormat: analysisResult.spec_format,
      apiTitle: analysisResult.api_title,
      apiVersion: analysisResult.api_version,
      description: analysisResult.description,
      servers: analysisResult.servers,
      endpointCount: analysisResult.total_endpoints,
      findingCount: analysisResult.total_findings,
      riskScore: analysisResult.risk_score,
      riskLevel: analysisResult.risk_level,
      severitySummary: analysisResult.severity_summary,
      categoryScores: analysisResult.category_scores,
      executiveSummary: analysisResult.executive_summary,
      scoreBreakdown: analysisResult.score_breakdown,
      recommendations: analysisResult.recommendations,
      attackSurface: analysisResult.attack_surface,
      findings: analysisResult.findings,
      endpoints: analysisResult.endpoints,
      status: 'COMPLETED',
      createdBy: req.user ? req.user.email : 'demo@apisentinel.dev'
    });

    res.status(201).json({
      success: true,
      message: 'Security analysis completed successfully.',
      scan: scanRecord
    });
  } catch (err) {
    next(err);
  }
};

exports.getAllScans = async (req, res, next) => {
  try {
    const { projectId } = req.query;
    const scans = await dbStore.getScans(projectId);
    res.json({
      success: true,
      count: scans.length,
      scans
    });
  } catch (err) {
    next(err);
  }
};

exports.getScanById = async (req, res, next) => {
  try {
    const { id } = req.params;
    const scan = await dbStore.getScanById(id);
    if (!scan) {
      return res.status(404).json({ error: 'Scan record not found.' });
    }
    res.json({
      success: true,
      scan
    });
  } catch (err) {
    next(err);
  }
};

exports.deleteScan = async (req, res, next) => {
  try {
    const { id } = req.params;
    const deleted = await dbStore.deleteScan(id);
    if (!deleted) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    res.json({
      success: true,
      message: 'Scan deleted successfully.'
    });
  } catch (err) {
    next(err);
  }
};

exports.getSampleSpecs = async (req, res) => {
  try {
    const samples = [
      {
        id: 'ecommerce_vuln',
        name: 'ShopSentinel E-Commerce API (Vulnerable Sample)',
        description: 'Realistic e-commerce API containing BOLA/IDOR, unauthenticated admin routes, passwordHash exposure, and SSRF webhooks.',
        fileName: 'vulnerable_ecommerce_api.json',
        fileType: 'json',
        content: loadSampleSpec('vulnerable_ecommerce_api.json')
      },
      {
        id: 'banking_secure',
        name: 'Apex Secure FinTech Banking API (Hardened)',
        description: 'OWASP-compliant banking API with OAuth2, strict schemas, rate-limiting headers, and zero unauthenticated paths.',
        fileName: 'secure_banking_api.yaml',
        fileType: 'yaml',
        content: loadSampleSpec('secure_banking_api.yaml')
      },
      {
        id: 'postman_fleet',
        name: 'CloudFleet Microservices (Postman Collection v2.1)',
        description: 'Postman collection format demonstrating multi-folder parsing and telemetry access controls.',
        fileName: 'postman_microservices_collection.json',
        fileType: 'json',
        content: loadSampleSpec('postman_microservices_collection.json')
      }
    ];

    res.json({
      success: true,
      samples
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load sample specifications.' });
  }
};
