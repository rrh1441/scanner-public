import { runEndpointDiscovery } from '../modules/endpointDiscovery.js';
import { runTlsScan } from '../modules/tlsScan.js';
import { runSpfDmarc } from '../modules/spfDmarc.js';
import { runConfigExposureScanner } from '../modules/configExposureScanner.js';
import { runInfostealerProbe } from '../modules/infostealerProbe.js';
import { runShodanScan } from '../modules/shodan.js';
import { runDocumentExposure } from '../modules/documentExposure.js';
import { runWhoisWrapper } from '../modules/whoisWrapper.js';
// import { runAiPathFinder } from '../modules/aiPathFinder.js'; // Moved to Tier 2
import { runTechStackScan } from '../modules/techStackScan.js';
import { runAbuseIntelScan } from '../modules/abuseIntelScan.js';
import { runAccessibilityLightweight } from '../modules/accessibilityLightweight.js';
// import { runNucleiLegacy as runNuclei } from '../modules/nuclei.js'; // Moved to Tier 2
import { executeModule as runLightweightCveCheck } from '../modules/lightweightCveCheck.js';
import { runClientSecretScanner } from '../modules/clientSecretScanner.js';
import { runBackendExposureScanner } from '../modules/backendExposureScanner.js';
import { runDenialWalletScan } from '../modules/denialWalletScan.js';
import { runAssetCorrelator } from '../modules/assetCorrelator.js';

export interface ScanJob {
  scan_id: string;
  domain: string;
  companyName?: string;
}

export interface ScanResult {
  scan_id: string;
  domain: string;
  results: Record<string, unknown>;
  metadata?: {
    duration_ms: number;
    modules_completed: number;
    modules_failed: number;
    module_timings?: Record<string, number>;
  };
}

export async function executeScan(job: ScanJob): Promise<ScanResult> {
  const { domain, scan_id } = job;
  const companyName = job.companyName || domain.split('.')[0] || 'Unknown';
  const startTime = Date.now();
  const moduleTimings: Record<string, number> = {};

  // Helper function to time module execution
  const timeModule = async (moduleName: string, moduleFunc: Promise<any>) => {
    const moduleStart = Date.now();
    try {
      const result = await moduleFunc;
      const duration = Date.now() - moduleStart;
      moduleTimings[moduleName] = duration;
      console.log(`[TIMING] ${moduleName}: ${duration}ms`);
      return { success: true, data: result, module: moduleName };
    } catch (err: any) {
      const duration = Date.now() - moduleStart;
      moduleTimings[moduleName] = duration;
      console.log(`[TIMING] ${moduleName}: ${duration}ms (failed)`);
      return { success: false, error: err.message, module: moduleName };
    }
  };

  // Optimized staged execution to prevent network congestion
  // Stage 1: Fast scans and foundation modules (including tech stack for dependencies)
  console.log('[SCAN] Stage 1: Running fast scans and tech detection');
  const stage1Results = await Promise.all([
    timeModule('shodan_scan', runShodanScan({ domain, scanId: scan_id, companyName })),
    timeModule('whois_wrapper', runWhoisWrapper({ domain, scanId: scan_id })),
    timeModule('spf_dmarc', runSpfDmarc({ domain, scanId: scan_id })),
    timeModule('tech_stack_scan', runTechStackScan({ domain, scanId: scan_id })), // Moved to Stage 1 - other modules depend on this
    timeModule('abuse_intel_scan', runAbuseIntelScan({ scanId: scan_id })),
    timeModule('client_secret_scanner', runClientSecretScanner({ scanId: scan_id })),
    timeModule('backend_exposure_scanner', runBackendExposureScanner({ scanId: scan_id })),
    timeModule('denial_wallet_scan', runDenialWalletScan({ domain, scanId: scan_id })),
    timeModule('accessibility_lightweight', runAccessibilityLightweight({ domain, scanId: scan_id })), 
  ]);

  // Stage 2: Medium network intensity (run with limited concurrency and rate limiting)
  console.log('[SCAN] Stage 2: Running medium intensity scans');
  const stage2Results = [];
  
  // Run infostealer probe with rate limiting (LeakCheck API is valuable - 3 hits per second max)
  console.log('[SCAN] Running infostealer probe with rate limiting...');
  await new Promise(resolve => setTimeout(resolve, Math.random() * 2000)); // Random delay 0-2s
  stage2Results.push(await timeModule('infostealer_probe', runInfostealerProbe({ domain, scanId: scan_id })));
  
  // Run config exposure scanner (less API intensive)
  stage2Results.push(await timeModule('config_exposure', runConfigExposureScanner({ domain, scanId: scan_id })));

  // Stage 3: High network intensity (run sequentially to avoid overwhelming target)
  console.log('[SCAN] Stage 3: Running intensive scans sequentially');
  const stage3Results = [];
  
  // TLS scan first (usually has good caching)
  stage3Results.push(await timeModule('tls_scan', runTlsScan({ domain, scanId: scan_id })));
  
  // Then endpoint discovery (most intensive)
  stage3Results.push(await timeModule('endpoint_discovery', runEndpointDiscovery({ domain, scanId: scan_id })));
  
  // Run CVE check after tech stack scan to analyze detected technologies  
  stage3Results.push(await timeModule('lightweight_cve_check', (async () => {
    // Get tech stack artifacts from database for CVE analysis
    const { LocalStore } = await import('../core/localStore.js');
    const store = new LocalStore();
    const dbResult = await store.query(
      'SELECT metadata FROM artifacts WHERE scan_id = $1 AND type = $2', 
      [scan_id, 'technology']
    );
    const techArtifacts = dbResult.rows.map((row: any) => ({type: 'technology_detection', data: row.metadata}));
    
    const cveResult = await runLightweightCveCheck({ 
      scanId: scan_id, 
      domain, 
      artifacts: techArtifacts 
    });
    return cveResult.findings ? cveResult.findings.length : 0;
  })()));

  // Combine all results
  const scanPromises = [...stage1Results, ...stage2Results, ...stage3Results];

  console.log(`[executeScan] Completed all ${scanPromises.length} modules in staged execution`);
  
  // scanPromises now contains all the completed results from our staged execution
  const results = [...scanPromises]; // Create mutable copy
  
  // Run asset correlator after all other modules complete
  const assetStart = Date.now();
  try {
    await runAssetCorrelator({ scanId: scan_id, domain, tier: 'tier1' });
    const assetDuration = Date.now() - assetStart;
    moduleTimings['asset_correlator'] = assetDuration;
    console.log(`[TIMING] asset_correlator: ${assetDuration}ms`);
    results.push({ success: true, data: 0, module: 'asset_correlator' }); // Returns void, so we use 0
  } catch (err: any) {
    const assetDuration = Date.now() - assetStart;
    moduleTimings['asset_correlator'] = assetDuration;
    console.log(`[TIMING] asset_correlator: ${assetDuration}ms (failed)`);
    console.error('Asset correlator failed:', err.message);
    results.push({ success: false, error: err.message, module: 'asset_correlator' });
  }

  // Tier2 modules (optional, high-resource modules moved here to reduce main scan load)
  // These modules are moved out of main scan to prevent job stalling and resource exhaustion
  // TODO: Run document_exposure in separate Tier2 scan process to avoid overwhelming Stage2
  console.log('[SCAN] Skipping Tier2 modules (document_exposure) to prevent job stalling');
  console.log('[SCAN] Note: Run Tier2 scan separately for document exposure analysis');
  
  // Count successes and failures
  const modulesCompleted = results.filter(r => r.success).length;
  const modulesFailed = results.filter(r => !r.success).length;
  
  // Log any failures
  results.filter(r => !r.success).forEach(r => {
    console.error(`Module ${r.module} failed:`, (r as any).error);
  });

  // Transform results into the expected format
  const resultMap: Record<string, unknown> = {};
  for (const result of results) {
    // Use the module name directly as the key since we already have full names
    resultMap[result.module] = result.success ? (result as any).data : { error: (result as any).error };
  }

  // Print timing summary
  const totalDuration = Date.now() - startTime;
  console.log('\n========== MODULE TIMING SUMMARY ==========');
  const sortedTimings = Object.entries(moduleTimings).sort((a, b) => b[1] - a[1]);
  sortedTimings.forEach(([module, time]) => {
    console.log(`${module.padEnd(30)} ${time.toString().padStart(6)}ms`);
  });
  console.log('============================================');
  console.log(`TOTAL SCAN TIME:               ${totalDuration}ms`);
  console.log(`Modules completed: ${modulesCompleted}, failed: ${modulesFailed}\n`);

  return {
    scan_id,
    domain,
    results: resultMap,
    metadata: {
      duration_ms: totalDuration,
      modules_completed: modulesCompleted,
      modules_failed: modulesFailed,
      module_timings: moduleTimings,
    },
  };
}