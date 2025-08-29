import { config } from 'dotenv';
import { Firestore } from '@google-cloud/firestore';
import { insertArtifact as insertArtifactGCP } from './core/artifactStoreGCP.js';
import { runShodanScan } from './modules/shodan.js';
import { runDocumentExposure } from './modules/documentExposure.js';
import { runClientSecretScanner } from './modules/clientSecretScanner.js';
import { runTlsScan } from './modules/tlsScan.js';
// import { runNucleiLegacy as runNuclei } from './modules/nuclei.js'; // Moved to Tier 2
import { executeModule as runLightweightCveCheck } from './modules/lightweightCveCheck.js';
import { runSpfDmarc } from './modules/spfDmarc.js';
import { runEndpointDiscovery } from './modules/endpointDiscovery.js';
import { runTechStackScan } from './modules/techStackScan.js';
import { runAbuseIntelScan } from './modules/abuseIntelScan.js';
import { runAccessibilityScan } from './modules/accessibilityScan.js';
import { runInfostealerProbe } from './modules/infostealerProbe.js';
import { runAssetCorrelator } from './modules/assetCorrelator.js';
import { runConfigExposureScanner } from './modules/configExposureScanner.js';
import { runBackendExposureScanner } from './modules/backendExposureScanner.js';
import { runDenialWalletScan } from './modules/denialWalletScan.js';
import { runAiPathFinder } from './modules/aiPathFinder.js';
import { runWhoisWrapper } from './modules/whoisWrapper.js';

// Module timeout wrapper
async function runModuleWithTimeout<T>(
  moduleName: string,
  moduleFunction: () => Promise<T>,
  timeoutMs: number,
  scanId: string
): Promise<T> {
  const startTime = Date.now();
  
  let timeoutHandle: NodeJS.Timeout | undefined;
  
  try {
    return await Promise.race([
      moduleFunction().then(result => {
        const duration = Date.now() - startTime;
        log(`[${moduleName}] COMPLETED - duration=${duration}ms scan_id=${scanId}`);
        if (timeoutHandle) clearTimeout(timeoutHandle);
        return result;
      }).catch(error => {
        const duration = Date.now() - startTime;
        log(`[${moduleName}] FAILED - error="${error.message}" duration=${duration}ms scan_id=${scanId}`);
        if (timeoutHandle) clearTimeout(timeoutHandle);
        throw error;
      }),
      new Promise<T>((_, reject) => {
        timeoutHandle = setTimeout(() => {
          log(`[${moduleName}] TIMEOUT - ${timeoutMs}ms exceeded scan_id=${scanId}`);
          reject(new Error(`Module ${moduleName} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      })
    ]);
  } catch (error) {
    if (timeoutHandle) clearTimeout(timeoutHandle);
    throw error;
  }
}

config();

// Initialize Firestore
const firestore = new Firestore();

function log(...args: any[]) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [worker]`, ...args);
}

// Use the GCP artifact store
const insertArtifact = insertArtifactGCP;

// Update scan status in Firestore
async function updateScanStatus(scanId: string, updates: any) {
  try {
    await firestore.collection('scans').doc(scanId).set({
      ...updates,
      updated_at: new Date().toISOString()
    }, { merge: true });
  } catch (error) {
    log(`Failed to update scan ${scanId}:`, error);
  }
}

interface ScanJob {
  scanId: string;
  companyName: string;
  domain: string;
  createdAt: string;
}

// Tier configuration
const TIER_1_MODULES = [
  'config_exposure',
  'document_exposure',
  'shodan',
  'breach_directory_probe',
  'whois_wrapper',  // Added: domain registration data
  'ai_path_finder',  // Added: AI-powered discovery (run early to inform others)
  'endpoint_discovery',
  'tech_stack_scan',
  'abuse_intel_scan',
  'accessibility_scan',
  'lightweight_cve_check',  // Replaced nuclei with fast CVE checker
  'tls_scan',
  'spf_dmarc',
  'client_secret_scanner',
  'backend_exposure_scanner',
  'denial_wallet_scan'  // Added: cloud cost exploitation
];

export async function processScan(job: ScanJob) {
  const { scanId, companyName, domain } = job;
  
  log(`Processing scan ${scanId} for ${companyName} (${domain})`);
  
  try {
    // Update scan status
    await updateScanStatus(scanId, {
      status: 'processing',
      started_at: new Date().toISOString()
    });
    
    const activeModules = TIER_1_MODULES;
    let totalFindings = 0;
    
    // Run modules in parallel where possible
    const parallelModules: { [key: string]: Promise<number> } = {};
    
    // Independent modules
    if (activeModules.includes('breach_directory_probe')) {
      log(`[breach_directory_probe] STARTING - scan_id=${scanId}`);
      parallelModules.breach_directory_probe = runModuleWithTimeout('breach_directory_probe', 
        () => runInfostealerProbe({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('shodan')) {
      log(`[shodan] STARTING - scan_id=${scanId}`);
      parallelModules.shodan = runModuleWithTimeout('shodan', 
        () => runShodanScan({ domain, scanId, companyName }), 
        3 * 60 * 1000, scanId);
    }
    // dns_twist moved to Tier 2 - no longer runs in Tier 1
    if (activeModules.includes('document_exposure')) {
      log(`[document_exposure] STARTING - scan_id=${scanId}`);
      parallelModules.document_exposure = runModuleWithTimeout('document_exposure', 
        () => runDocumentExposure({ companyName, domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('whois_wrapper')) {
      log(`[whois_wrapper] STARTING - scan_id=${scanId}`);
      parallelModules.whois_wrapper = runModuleWithTimeout('whois_wrapper', 
        () => runWhoisWrapper({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('ai_path_finder')) {
      log(`[ai_path_finder] STARTING - scan_id=${scanId}`);
      parallelModules.ai_path_finder = runModuleWithTimeout('ai_path_finder', 
        () => runAiPathFinder({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('endpoint_discovery')) {
      log(`[endpoint_discovery] STARTING - scan_id=${scanId}`);
      parallelModules.endpoint_discovery = runModuleWithTimeout('endpoint_discovery', 
        () => runEndpointDiscovery({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('tls_scan')) {
      log(`[tls_scan] STARTING - scan_id=${scanId}`);
      parallelModules.tls_scan = runModuleWithTimeout('tls_scan', 
        () => runTlsScan({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('spf_dmarc')) {
      log(`[spf_dmarc] STARTING - scan_id=${scanId}`);
      parallelModules.spf_dmarc = runModuleWithTimeout('spf_dmarc', 
        () => runSpfDmarc({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('config_exposure')) {
      log(`[config_exposure] STARTING - scan_id=${scanId}`);
      parallelModules.config_exposure = runModuleWithTimeout('config_exposure', 
        () => runConfigExposureScanner({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    
    // Wait for endpoint discovery first
    let endpointResults = 0;
    if (parallelModules.endpoint_discovery) {
      endpointResults = await parallelModules.endpoint_discovery;
      log(`Endpoint discovery completed: ${endpointResults} findings`);
      delete parallelModules.endpoint_discovery;
      totalFindings += endpointResults;
    }
    
    // Then run dependent modules
    if (activeModules.includes('lightweight_cve_check')) {
      log(`[lightweight_cve_check] STARTING - scan_id=${scanId}`);
      parallelModules.lightweight_cve_check = runModuleWithTimeout('lightweight_cve_check', 
        async () => {
          const result = await runLightweightCveCheck({ scanId, domain, artifacts: [] });
          // Return the count of findings for compatibility
          return result.findings ? result.findings.length : 0;
        }, 
        30 * 1000, scanId);  // 30 second timeout for fast CVE check
    }
    if (activeModules.includes('tech_stack_scan')) {
      log(`[tech_stack_scan] STARTING - scan_id=${scanId}`);
      parallelModules.tech_stack_scan = runModuleWithTimeout('tech_stack_scan', 
        () => runTechStackScan({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('abuse_intel_scan')) {
      log(`[abuse_intel_scan] STARTING - scan_id=${scanId}`);
      parallelModules.abuse_intel_scan = runModuleWithTimeout('abuse_intel_scan', 
        () => runAbuseIntelScan({ scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('client_secret_scanner')) {
      log(`[client_secret_scanner] STARTING - scan_id=${scanId}`);
      parallelModules.client_secret_scanner = runModuleWithTimeout('client_secret_scanner', 
        () => runClientSecretScanner({ scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('backend_exposure_scanner')) {
      log(`[backend_exposure_scanner] STARTING - scan_id=${scanId}`);
      parallelModules.backend_exposure_scanner = runModuleWithTimeout('backend_exposure_scanner', 
        () => runBackendExposureScanner({ scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('accessibility_scan')) {
      log(`[accessibility_scan] STARTING - scan_id=${scanId}`);
      parallelModules.accessibility_scan = runModuleWithTimeout('accessibility_scan', 
        () => runAccessibilityScan({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('denial_wallet_scan')) {
      log(`[denial_wallet_scan] STARTING - scan_id=${scanId}`);
      parallelModules.denial_wallet_scan = runModuleWithTimeout('denial_wallet_scan', 
        () => runDenialWalletScan({ domain, scanId }), 
        3 * 60 * 1000, scanId);
    }
    
    // Wait for all modules with graceful degradation
    let completedModules = 0;
    const totalModules = Object.keys(parallelModules).length;
    
    for (const [moduleName, promise] of Object.entries(parallelModules)) {
      try {
        const results = await promise;
        completedModules++;
        totalFindings += results;
        log(`[SCAN_PROGRESS] ${completedModules}/${totalModules} modules completed - ${moduleName} found ${results} findings - scan_id=${scanId}`);
      } catch (error) {
        completedModules++;
        log(`[${moduleName}] FAILED - ${(error as Error).message} - CONTINUING SCAN - scan_id=${scanId}`);
        log(`[SCAN_PROGRESS] ${completedModules}/${totalModules} modules completed - ${moduleName} FAILED but scan continues - scan_id=${scanId}`);
        
        await insertArtifact({
          type: 'scan_error',
          val_text: `Module ${moduleName} failed: ${(error as Error).message}`,
          severity: 'MEDIUM',
          meta: { scan_id: scanId, module: moduleName }
        });
      }
    }
    
    // Run asset correlator
    try {
      await runAssetCorrelator({ scanId, domain, tier: 'tier1' });
      log('Asset correlation completed');
    } catch (error) {
      log('Asset correlation failed:', error);
    }
    
    // Update scan completion
    await updateScanStatus(scanId, {
      status: 'completed',
      completed_at: new Date().toISOString(),
      total_findings: totalFindings
    });
    
    log(`✅ Scan completed: ${totalFindings} total findings`);
    
  } catch (error) {
    log(`❌ Scan failed:`, error);
    
    await updateScanStatus(scanId, {
      status: 'failed',
      error: (error as Error).message,
      failed_at: new Date().toISOString()
    });
    
    await insertArtifact({
      type: 'scan_error',
      val_text: `Scan failed: ${(error as Error).message}`,
      severity: 'CRITICAL',
      meta: { scan_id: scanId }
    });
    
    throw error;
  }
}

// Export for use by worker-pubsub.ts
// The main entry point is now handled by worker-pubsub.ts which listens to Pub/Sub messages