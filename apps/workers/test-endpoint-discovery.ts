import { config } from 'dotenv';
config({ path: '../../.env' });

import { runEndpointDiscovery } from './modules/endpointDiscovery.js';

const TEST_DOMAIN = 'vulnerable-test-site.vercel.app';
const TEST_SCAN_ID = `endpoint-test-${Date.now()}`;

async function testEndpointDiscovery() {
  console.log('========================================');
  console.log('ENDPOINT DISCOVERY DETAILED TEST');
  console.log(`Domain: ${TEST_DOMAIN}`);
  console.log(`Scan ID: ${TEST_SCAN_ID}`);
  console.log('========================================\n');
  
  // Set up periodic status logging
  const statusInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    console.log(`[STATUS] Still running... ${elapsed}s elapsed`);
  }, 10000); // Log every 10 seconds
  
  const startTime = Date.now();
  
  try {
    console.log('[START] Beginning endpoint discovery...\n');
    
    const result = await runEndpointDiscovery({ 
      domain: TEST_DOMAIN, 
      scanId: TEST_SCAN_ID 
    });
    
    const duration = Date.now() - startTime;
    clearInterval(statusInterval);
    
    console.log('\n========================================');
    console.log('ENDPOINT DISCOVERY COMPLETED');
    console.log('========================================');
    console.log(`Duration: ${duration}ms (${Math.floor(duration/1000)}s)`);
    console.log(`Findings: ${result}`);
    
  } catch (error: any) {
    const duration = Date.now() - startTime;
    clearInterval(statusInterval);
    
    console.error('\n========================================');
    console.error('ENDPOINT DISCOVERY FAILED');
    console.error('========================================');
    console.error(`Duration: ${duration}ms (${Math.floor(duration/1000)}s)`);
    console.error(`Error: ${error.message}`);
    console.error(`Stack: ${error.stack}`);
  }
}

// Run the test
testEndpointDiscovery().catch(console.error);