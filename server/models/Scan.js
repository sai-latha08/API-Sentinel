const mongoose = require('mongoose');

const ScanSchema = new mongoose.Schema({
  projectId: { type: String, default: 'default' },
  projectName: { type: String, default: 'Default Project' },
  fileName: { type: String, required: true },
  fileType: { type: String, default: 'json' },
  specFormat: { type: String, default: 'openapi_3' },
  apiTitle: { type: String, default: 'API Specification' },
  apiVersion: { type: String, default: '1.0.0' },
  description: { type: String, default: '' },
  servers: [{ type: String }],
  endpointCount: { type: Number, default: 0 },
  findingCount: { type: Number, default: 0 },
  riskScore: { type: Number, required: true },
  riskLevel: { type: String, default: 'Moderate' },
  severitySummary: {
    CRITICAL: { type: Number, default: 0 },
    HIGH: { type: Number, default: 0 },
    MEDIUM: { type: Number, default: 0 },
    LOW: { type: Number, default: 0 },
    INFO: { type: Number, default: 0 }
  },
  categoryScores: { type: Map, of: Number, default: {} },
  executiveSummary: { type: String, default: '' },
  scoreBreakdown: { type: mongoose.Schema.Types.Mixed, default: {} },
  recommendations: [{ type: mongoose.Schema.Types.Mixed }],
  attackSurface: { type: mongoose.Schema.Types.Mixed, default: { nodes: [], edges: [] } },
  findings: [{ type: mongoose.Schema.Types.Mixed }],
  endpoints: [{ type: mongoose.Schema.Types.Mixed }],
  status: { type: String, enum: ['PENDING', 'PROCESSING', 'COMPLETED', 'FAILED'], default: 'COMPLETED' },
  createdBy: { type: String, default: 'system' },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.models.Scan || mongoose.model('Scan', ScanSchema);
