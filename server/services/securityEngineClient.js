const axios = require('axios');

const SECURITY_ENGINE_URL = process.env.SECURITY_ENGINE_URL || 'http://127.0.0.1:8000';

const client = axios.create({
  baseURL: SECURITY_ENGINE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json'
  }
});

async function checkEngineHealth() {
  try {
    const res = await client.get('/health');
    return res.data;
  } catch (err) {
    return { status: 'offline', error: err.message };
  }
}

async function analyzeSpecification(specContent, fileName = 'api_spec', fileType = 'json') {
  try {
    const response = await client.post('/analyze', {
      spec_content: specContent,
      file_name: fileName,
      file_type: fileType
    });
    return response.data;
  } catch (err) {
    if (err.response && err.response.data && err.response.data.detail) {
      throw new Error(`Security Engine: ${err.response.data.detail}`);
    }
    throw new Error(`Failed to communicate with Security Analysis Engine at ${SECURITY_ENGINE_URL}: ${err.message}`);
  }
}

async function askSentinelAI(query, findingId = null, endpoint = null, contextData = null) {
  try {
    const response = await client.post('/ai/ask', {
      query,
      finding_id: findingId,
      endpoint,
      context_data: contextData
    });
    return response.data;
  } catch (err) {
    if (err.response && err.response.data && err.response.data.detail) {
      throw new Error(err.response.data.detail);
    }
    throw new Error(`AI Service Error: ${err.message}`);
  }
}

async function compareScansEngine(baseScan, targetScan) {
  try {
    const response = await client.post('/compare', {
      base_scan: baseScan,
      target_scan: targetScan
    });
    return response.data;
  } catch (err) {
    throw new Error(`Comparison Error: ${err.message}`);
  }
}

module.exports = {
  checkEngineHealth,
  analyzeSpecification,
  askSentinelAI,
  compareScansEngine
};
