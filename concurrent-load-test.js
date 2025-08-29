#!/usr/bin/env node
/**
 * Concurrent Load Test - 10 Simultaneous Scans
 * Tests scanner performance, resource usage, and database connection handling
 */

const axios = require('axios');
const { performance } = require('perf_hooks');

const SCANNER_URL = 'http://localhost:8080';
const CONCURRENT_SCANS = 10;

// Test domains with different characteristics
const TEST_DOMAINS = [
  'example.com',
  'github.com', 
  'stackoverflow.com',
  'httpbin.org',
  'httpstat.us',
  'postman-echo.com',
  'reqres.in',
  'jsonplaceholder.typicode.com',
  'dog.ceo',
  'cat-fact.herokuapp.com'
];

class LoadTester {
  constructor() {
    this.results = [];
    this.startTime = null;
    this.endTime = null;
  }

  async runSingleScan(domain, scanIndex) {
    const scanId = `LOAD_TEST_${scanIndex}_${Date.now()}`;
    const startTime = performance.now();
    
    console.log(`🚀 Starting scan ${scanIndex + 1}: ${domain} (${scanId})`);
    
    try {
      const response = await axios.post(`${SCANNER_URL}/scan`, {
        domain: domain,
        scan_id: scanId
      }, {
        timeout: 300000 // 5 minute timeout
      });
      
      const endTime = performance.now();
      const duration = Math.round(endTime - startTime);
      
      const result = {
        scanIndex: scanIndex + 1,
        domain,
        scanId,
        duration,
        status: 'success',
        response: response.data
      };
      
      console.log(`✅ Scan ${scanIndex + 1} completed: ${domain} in ${duration}ms`);
      return result;
      
    } catch (error) {
      const endTime = performance.now();
      const duration = Math.round(endTime - startTime);
      
      const result = {
        scanIndex: scanIndex + 1,
        domain,
        scanId,
        duration,
        status: 'error',
        error: error.message
      };
      
      console.log(`❌ Scan ${scanIndex + 1} failed: ${domain} - ${error.message}`);
      return result;
    }
  }

  async runConcurrentScans() {
    console.log(`\n🎯 Starting ${CONCURRENT_SCANS} concurrent scans...\n`);
    
    this.startTime = performance.now();
    
    // Create promises for all concurrent scans
    const scanPromises = Array.from({ length: CONCURRENT_SCANS }, (_, index) => {
      const domain = TEST_DOMAINS[index % TEST_DOMAINS.length];
      return this.runSingleScan(domain, index);
    });
    
    // Wait for all scans to complete
    this.results = await Promise.all(scanPromises);
    this.endTime = performance.now();
    
    return this.results;
  }

  generateReport() {
    const totalDuration = Math.round(this.endTime - this.startTime);
    const successfulScans = this.results.filter(r => r.status === 'success');
    const failedScans = this.results.filter(r => r.status === 'error');
    
    const avgScanTime = successfulScans.length > 0 
      ? Math.round(successfulScans.reduce((sum, r) => sum + r.duration, 0) / successfulScans.length)
      : 0;
    
    const minScanTime = successfulScans.length > 0 
      ? Math.min(...successfulScans.map(r => r.duration))
      : 0;
    
    const maxScanTime = successfulScans.length > 0 
      ? Math.max(...successfulScans.map(r => r.duration))
      : 0;

    console.log(`\n📊 CONCURRENT LOAD TEST RESULTS`);
    console.log(`════════════════════════════════════════`);
    console.log(`Total Test Duration: ${totalDuration}ms (${(totalDuration/1000/60).toFixed(1)}m)`);
    console.log(`Concurrent Scans: ${CONCURRENT_SCANS}`);
    console.log(`Successful: ${successfulScans.length}/${CONCURRENT_SCANS} (${((successfulScans.length/CONCURRENT_SCANS)*100).toFixed(1)}%)`);
    console.log(`Failed: ${failedScans.length}/${CONCURRENT_SCANS} (${((failedScans.length/CONCURRENT_SCANS)*100).toFixed(1)}%)`);
    console.log(`\n⏱️  TIMING ANALYSIS:`);
    console.log(`Average Scan Time: ${avgScanTime}ms (${(avgScanTime/1000).toFixed(1)}s)`);
    console.log(`Fastest Scan: ${minScanTime}ms (${(minScanTime/1000).toFixed(1)}s)`);
    console.log(`Slowest Scan: ${maxScanTime}ms (${(maxScanTime/1000).toFixed(1)}s)`);
    
    if (failedScans.length > 0) {
      console.log(`\n❌ FAILED SCANS:`);
      failedScans.forEach(scan => {
        console.log(`  ${scan.scanIndex}. ${scan.domain}: ${scan.error}`);
      });
    }
    
    console.log(`\n✅ SUCCESSFUL SCANS:`);
    successfulScans.forEach(scan => {
      const findings = scan.response?.findings_count || 0;
      console.log(`  ${scan.scanIndex}. ${scan.domain}: ${(scan.duration/1000).toFixed(1)}s, ${findings} findings`);
    });

    return {
      totalDuration,
      concurrentScans: CONCURRENT_SCANS,
      successRate: (successfulScans.length / CONCURRENT_SCANS) * 100,
      avgScanTime,
      minScanTime,
      maxScanTime,
      results: this.results
    };
  }
}

// Health check before starting
async function checkHealth() {
  try {
    const response = await axios.get(`${SCANNER_URL}/health`);
    console.log(`✅ Scanner health check passed`);
    console.log(`Database: ${response.data.database || 'Unknown'}`);
    console.log(`Modules: ${response.data.modules || 'Unknown'} operational`);
    return true;
  } catch (error) {
    console.error(`❌ Health check failed: ${error.message}`);
    console.error(`Make sure scanner is running: npm run dev`);
    return false;
  }
}

// Main execution
async function main() {
  console.log(`🔬 CONCURRENT LOAD TEST - 10 Simultaneous Scans`);
  console.log(`Scanner: ${SCANNER_URL}`);
  console.log(`Test Domains: ${TEST_DOMAINS.slice(0, 5).join(', ')} + 5 more`);
  
  // Health check
  const isHealthy = await checkHealth();
  if (!isHealthy) {
    process.exit(1);
  }
  
  // Run the load test
  const tester = new LoadTester();
  await tester.runConcurrentScans();
  
  // Generate and display report
  const report = tester.generateReport();
  
  console.log(`\n💾 Test completed! Check database with:`);
  console.log(`psql scanner_local -c "SELECT scan_id, domain, status, findings_count FROM scans WHERE scan_id LIKE 'LOAD_TEST_%' ORDER BY created_at DESC LIMIT 15;"`);
  
  // Exit with appropriate code
  process.exit(report.successRate === 100 ? 0 : 1);
}

if (require.main === module) {
  main().catch(console.error);
}

module.exports = LoadTester;