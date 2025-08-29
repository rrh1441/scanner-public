#!/usr/bin/env npx tsx

import { config } from 'dotenv';
config({ path: '.env' });

import { runBreachDirectoryProbe } from './apps/workers/modules/breachDirectoryProbe.js';
import { runShodanScan } from './apps/workers/modules/shodan.js';
import { runDocumentExposure } from './apps/workers/modules/documentExposure.js';
import { runWhoisWrapper } from './apps/workers/modules/whoisWrapper.js';
import { runAiPathFinder } from './apps/workers/modules/aiPathFinder.js';
import { runEndpointDiscovery } from './apps/workers/modules/endpointDiscovery.js';
import { runTechStackScan } from './apps/workers/modules/techStackScan.js';
import { runAbuseIntelScan } from './apps/workers/modules/abuseIntelScan.js';
import { runAccessibilityScan } from './apps/workers/modules/accessibilityScan.js';
import { runNucleiLegacy as runNuclei } from './apps/workers/modules/nuclei.js';
import { runTlsScan } from './apps/workers/modules/tlsScan.js';
import { runSpfDmarc } from './apps/workers/modules/spfDmarc.js';
import { runClientSecretScanner } from './apps/workers/modules/clientSecretScanner.js';
import { runBackendExposureScanner } from './apps/workers/modules/backendExposureScanner.js';
import { runConfigExposureScanner } from './apps/workers/modules/configExposureScanner.js';
import { runDenialWalletScan } from './apps/workers/modules/denialWalletScan.js';
import { runAssetCorrelator } from './apps/workers/modules/assetCorrelator.js';

const TEST_DOMAIN = 'vulnerable-test-site.vercel.app';
const TEST_SCAN_ID = `test-${Date.now()}`;
const TIMEOUT_MS = 30000; // 30 second timeout per module

interface ModuleTest {
  name: string;
  func: () => Promise<any>;
  requiresDomain: boolean;
}

const modules: ModuleTest[] = [
  { name: 'breach_directory_probe', func: () => runBreachDirectoryProbe({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'shodan_scan', func: () => runShodanScan({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID, companyName: 'Test' }), requiresDomain: true },
  { name: 'document_exposure', func: () => runDocumentExposure({ companyName: 'Test', domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'whois_wrapper', func: () => runWhoisWrapper({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'ai_path_finder', func: () => runAiPathFinder({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'endpoint_discovery', func: () => runEndpointDiscovery({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'tech_stack_scan', func: () => runTechStackScan({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'abuse_intel_scan', func: () => runAbuseIntelScan({ scanId: TEST_SCAN_ID }), requiresDomain: false },
  { name: 'accessibility_scan', func: () => runAccessibilityScan({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'nuclei', func: () => runNuclei({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'tls_scan', func: () => runTlsScan({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'spf_dmarc', func: () => runSpfDmarc({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'client_secret_scanner', func: () => runClientSecretScanner({ scanId: TEST_SCAN_ID }), requiresDomain: false },
  { name: 'backend_exposure_scanner', func: () => runBackendExposureScanner({ scanId: TEST_SCAN_ID }), requiresDomain: false },
  { name: 'config_exposure', func: () => runConfigExposureScanner({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'denial_wallet_scan', func: () => runDenialWalletScan({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }), requiresDomain: true },
  { name: 'asset_correlator', func: () => runAssetCorrelator({ scanId: TEST_SCAN_ID, domain: TEST_DOMAIN, tier: 'tier1' }), requiresDomain: true },
];

async function testModule(module: ModuleTest): Promise<{ name: string; status: string; time: number; error?: string; findings?: number }> {
  const startTime = Date.now();
  
  try {
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Timeout')), TIMEOUT_MS)
    );
    
    const result = await Promise.race([
      module.func(),
      timeoutPromise
    ]);
    
    const duration = Date.now() - startTime;
    const findings = typeof result === 'number' ? result : 0;
    
    return {
      name: module.name,
      status: 'SUCCESS',
      time: duration,
      findings
    };
  } catch (error: any) {
    const duration = Date.now() - startTime;
    return {
      name: module.name,
      status: error.message === 'Timeout' ? 'TIMEOUT' : 'FAILED',
      time: duration,
      error: error.message
    };
  }
}

async function runSystematicTest() {
  console.log('========================================');
  console.log('SYSTEMATIC MODULE TEST');
  console.log(`Domain: ${TEST_DOMAIN}`);
  console.log(`Scan ID: ${TEST_SCAN_ID}`);
  console.log(`Timeout: ${TIMEOUT_MS}ms per module`);
  console.log('========================================\n');

  const results = [];
  
  // Test each module individually
  console.log('Testing modules individually...\n');
  
  for (const module of modules) {
    process.stdout.write(`Testing ${module.name.padEnd(30)} ... `);
    const result = await testModule(module);
    results.push(result);
    
    if (result.status === 'SUCCESS') {
      console.log(`✅ ${result.time}ms (${result.findings} findings)`);
    } else if (result.status === 'TIMEOUT') {
      console.log(`⏱️  TIMEOUT after ${result.time}ms`);
    } else {
      console.log(`❌ FAILED after ${result.time}ms: ${result.error}`);
    }
  }
  
  // Summary
  console.log('\n========================================');
  console.log('SUMMARY');
  console.log('========================================\n');
  
  const successful = results.filter(r => r.status === 'SUCCESS');
  const failed = results.filter(r => r.status === 'FAILED');
  const timedOut = results.filter(r => r.status === 'TIMEOUT');
  
  console.log(`✅ Successful: ${successful.length}/${modules.length}`);
  console.log(`❌ Failed: ${failed.length}/${modules.length}`);
  console.log(`⏱️  Timed out: ${timedOut.length}/${modules.length}\n`);
  
  // Performance ranking
  console.log('Performance Ranking (successful modules):');
  console.log('------------------------------------------');
  successful
    .sort((a, b) => a.time - b.time)
    .forEach((r, i) => {
      console.log(`${(i + 1).toString().padStart(2)}. ${r.name.padEnd(30)} ${r.time.toString().padStart(6)}ms`);
    });
  
  if (failed.length > 0) {
    console.log('\nFailed Modules:');
    console.log('---------------');
    failed.forEach(r => {
      console.log(`- ${r.name}: ${r.error}`);
    });
  }
  
  if (timedOut.length > 0) {
    console.log('\nTimed Out Modules (>${TIMEOUT_MS}ms):');
    console.log('-----------------------------');
    timedOut.forEach(r => {
      console.log(`- ${r.name}`);
    });
  }
  
  // Total time
  const totalTime = results.reduce((sum, r) => sum + r.time, 0);
  console.log(`\nTotal sequential time: ${totalTime}ms`);
  console.log(`Average time per module: ${Math.round(totalTime / modules.length)}ms`);
  
  // If running in parallel, max time would be:
  const maxTime = Math.max(...results.map(r => r.time));
  console.log(`If run in parallel, estimated time: ${maxTime}ms`);
}

// Run the test
runSystematicTest().catch(console.error);