import { config } from 'dotenv';
config({ path: '../../.env' });

import { executeScan } from './scan/executeScan.js';

const TEST_DOMAIN = 'vulnerable-test-site.vercel.app';

async function runTimingTest() {
  console.log('========================================');
  console.log('MODULE TIMING TEST');
  console.log(`Domain: ${TEST_DOMAIN}`);
  console.log('========================================\n');
  
  console.log('Starting scan...\n');
  
  const startTime = Date.now();
  
  try {
    const result = await executeScan({
      scan_id: `timing-test-${Date.now()}`,
      domain: TEST_DOMAIN,
      companyName: 'Test Company'
    });
    
    console.log('\n========================================');
    console.log('SCAN COMPLETED SUCCESSFULLY');
    console.log('========================================\n');
    
    // The timing info will be printed by executeScan itself
    // Just show the metadata summary
    if (result.metadata) {
      console.log(`Total modules: ${result.metadata.modules_completed + result.metadata.modules_failed}`);
      console.log(`Successful: ${result.metadata.modules_completed}`);
      console.log(`Failed: ${result.metadata.modules_failed}`);
      console.log(`Total time: ${result.metadata.duration_ms}ms`);
      
      if (result.metadata.module_timings) {
        console.log('\n========== DETAILED TIMING ==========');
        const sortedTimings = Object.entries(result.metadata.module_timings)
          .sort((a, b) => (b[1] as number) - (a[1] as number));
        
        sortedTimings.forEach(([module, time]) => {
          console.log(`${module.padEnd(30)} ${time.toString().padStart(6)}ms`);
        });
        console.log('=====================================');
      }
    }
    
    // Show findings count per module
    console.log('\n========== FINDINGS PER MODULE ==========');
    Object.entries(result.results).forEach(([module, data]) => {
      if (typeof data === 'number') {
        console.log(`${module.padEnd(30)} ${data} findings`);
      } else if (data && typeof data === 'object' && 'error' in data) {
        console.log(`${module.padEnd(30)} ERROR: ${(data as any).error}`);
      } else {
        console.log(`${module.padEnd(30)} completed`);
      }
    });
    
  } catch (error: any) {
    console.error('\n❌ SCAN FAILED:', error.message);
    console.error(error.stack);
  }
  
  const totalTime = Date.now() - startTime;
  console.log(`\n⏱️  Total execution time: ${totalTime}ms`);
}

// Run the test
runTimingTest().catch(console.error);