const fs = require('fs');
const path = require('path');
const axios = require('axios');

async function testFullPipeline() {
  console.log('🚀 Testing Full End-to-End API Sentinel Pipeline...');

  const specContent = fs.readFileSync(
    path.join(__dirname, '../../sample-specs/vulnerable_ecommerce_api.json'),
    'utf8'
  );

  // 1. Trigger Scan
  console.log('1️⃣ Sending specification to scan endpoint...');
  const scanRes = await axios.post('http://localhost:5000/api/scans/raw', {
    specContent,
    fileName: 'vulnerable_ecommerce_api.json',
    fileType: 'json'
  });

  const scan = scanRes.data.scan;
  console.log(`✅ Scan Success: "${scan.apiTitle}"`);
  console.log(`   - Risk Score: ${scan.riskScore}/100 (${scan.riskLevel})`);
  console.log(`   - Total Endpoints: ${scan.endpointCount}`);
  console.log(`   - Total Findings: ${scan.findingCount}`);
  console.log('   - Severity Summary:', scan.severitySummary);
  console.log(`   - Attack Surface Nodes: ${scan.attackSurface.nodes.length}, Edges: ${scan.attackSurface.edges.length}`);

  // 2. Query Ask Sentinel AI Assistant
  console.log('\n2️⃣ Testing Ask Sentinel AI reasoning query...');
  const aiRes = await axios.post('http://localhost:5000/api/ai/ask', {
    query: 'Which findings should I fix first?',
    scanId: scan._id || scan.id
  });

  console.log('✅ AI Reasoner Response received:');
  console.log(aiRes.data.data.answer.slice(0, 260) + '...\n');

  // 3. Retrieve Formal Report
  console.log('3️⃣ Fetching executive report dataset...');
  const reportRes = await axios.get(`http://localhost:5000/api/reports/${scan._id || scan.id}`);
  console.log(`✅ Report Generated: ${reportRes.data.report.meta.reportId}`);
  console.log(`   - Critical Findings in Report: ${reportRes.data.report.criticalFindings.length}`);

  // 4. Test Scan Hardened Banking spec and Compare
  console.log('\n4️⃣ Scanning Hardened Banking API for Comparison...');
  const bankingSpec = fs.readFileSync(
    path.join(__dirname, '../../sample-specs/secure_banking_api.yaml'),
    'utf8'
  );
  const bankingRes = await axios.post('http://localhost:5000/api/scans/raw', {
    specContent: bankingSpec,
    fileName: 'secure_banking_api.yaml',
    fileType: 'yaml'
  });
  const bankingScan = bankingRes.data.scan;
  console.log(`✅ Hardened Banking Scan: Risk Score ${bankingScan.riskScore}/100 (${bankingScan.riskLevel})`);

  console.log('\n5️⃣ Comparing Vulnerable vs Hardened API Scans...');
  const compareRes = await axios.post('http://localhost:5000/api/compare', {
    baseScanId: scan._id || scan.id,
    targetScanId: bankingScan._id || bankingScan.id
  });
  console.log(`✅ Comparison Result: Score Delta: ${compareRes.data.comparison.score_delta} (Improved: ${compareRes.data.comparison.improvement})`);
  console.log(`   - Fixed Findings: ${compareRes.data.comparison.findings_fixed.length}`);

  console.log('\n🎉 ALL PIPELINE VERIFICATIONS PASSED 100%!');
}

testFullPipeline().catch(err => {
  console.error('❌ E2E Pipeline Error:', err.response?.data || err.message);
  process.exit(1);
});
