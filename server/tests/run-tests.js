const assert = require('assert');
const { dbStore } = require('../services/db');

async function runTests() {
  console.log('🧪 Starting API Sentinel Backend Tests...');

  // Test 1: Memory/DB Store Project creation
  const project = await dbStore.createProject({
    name: 'Integration Test Project',
    description: 'Testing store persistence',
    owner: 'test@sentinel.dev'
  });
  assert(project.name === 'Integration Test Project', 'Project creation failed');
  console.log('✅ Project creation passed');

  // Test 2: Scan Creation & Retrieval
  const scan = await dbStore.createScan({
    projectId: project._id || project.id,
    fileName: 'test_spec.json',
    fileType: 'json',
    specFormat: 'openapi_3',
    apiTitle: 'Test API',
    riskScore: 75,
    riskLevel: 'High Risk',
    endpointCount: 12,
    findingCount: 5,
    severitySummary: { CRITICAL: 1, HIGH: 2, MEDIUM: 2, LOW: 0, INFO: 0 },
    status: 'COMPLETED'
  });
  assert(scan.riskScore === 75, 'Scan riskScore assertion failed');
  console.log('✅ Scan persistence passed');

  const retrieved = await dbStore.getScanById(scan._id || scan.id);
  assert(retrieved !== null, 'Scan retrieval failed');
  console.log('✅ Scan retrieval passed');

  console.log('🎉 All backend tests passed successfully!');
  process.exit(0);
}

runTests().catch(err => {
  console.error('❌ Backend test failed:', err);
  process.exit(1);
});
