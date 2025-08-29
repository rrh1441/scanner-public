/*
 * =============================================================================
 * MODULE: nuclei.ts (Consolidated v4)
 * =============================================================================
 * This module runs the Nuclei vulnerability scanner against a set of targets
 * for comprehensive vulnerability detection including general misconfigurations
 * and specific CVE verification.
 *
 * CONSOLIDATION: All Nuclei execution now flows through this single module to
 * eliminate redundant scans. Other modules (cveVerifier, securityAnalysis, 
 * dbPortScan) now pass their requirements to this central coordinator.
 *
 * Key Features:
 * 1.  **Unified Execution:** Single Nuclei run with combined templates
 * 2.  **CVE Integration:** Accepts specific CVE IDs for targeted verification
 * 3.  **Technology-aware Scanning:** Uses technology-specific Nuclei tags
 * 4.  **Workflow Execution:** Runs advanced multi-step workflows for detected tech
 * 5.  **Concurrency & Structure:** Parallel scans with tag-based and workflow phases
 * =============================================================================
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { getEpssScores } from '../util/epss.js';
import { logLegacy as log } from '../core/logger.js';
import { 
  runNuclei as runNucleiWrapper, 
  runTwoPassScan
} from '../util/nucleiWrapper.js';

const MAX_CONCURRENT_SCANS = 4;

// REFACTOR: Workflow base path is now configurable.
const WORKFLOW_BASE_PATH = process.env.NUCLEI_WORKFLOWS_PATH || './workflows';
const TECH_TO_WORKFLOW_MAP: Record<string, string> = {
    'wordpress': 'wordpress-workflow.yaml', // Store only the filename
    'jira': 'jira-workflow.yaml'
};

// Enhanced interface to support CVE-specific scanning
interface NucleiScanRequest {
  domain: string;
  scanId?: string;
  targets?: { url: string; tech?: string[] }[];
  // New: CVE-specific scanning parameters
  cveIds?: string[];
  specificTemplates?: string[];
  requesterModule?: string; // Track which module requested the scan
}

interface ConsolidatedScanResult {
  totalFindings: number;
  generalFindings: number;
  cveFindings: number;
  cveResults?: Map<string, { verified: boolean; exploitable: boolean; details?: any }>;
}

async function validateDependencies(): Promise<boolean> {
  try {
    await runNucleiWrapper({ version: true });
    return true;
  } catch {
    return false;
  }
}

async function processNucleiResults(results: any[], scanId: string, category: 'general' | 'cve' | 'workflow', templateContext?: string): Promise<number> {
  // Collect all CVE IDs for batch EPSS fetching
  const cveIds: string[] = [];
  for (const vuln of results) {
    const templateId = vuln['template-id'] || vuln.template || 'unknown';
    const name = vuln.info?.name || vuln.name || templateId;
    const cveMatch = templateId.match(/(CVE-\d{4}-\d+)/i) || 
                     name.match(/(CVE-\d{4}-\d+)/i);
    if (cveMatch) {
      cveIds.push(cveMatch[1].toUpperCase());
    }
  }
  
  // Fetch EPSS scores for all CVEs
  let epssScores = new Map<string, number>();
  if (cveIds.length > 0) {
    try {
      epssScores = await getEpssScores(cveIds);
      log(`[nuclei] Fetched EPSS scores for ${epssScores.size} CVEs`);
    } catch (error) {
      log(`[nuclei] Failed to fetch EPSS scores:`, (error as Error).message);
    }
  }
  
  let count = 0;
  
  for (const vuln of results) {
    try {
      const severity = vuln.info?.severity?.toUpperCase() || 'MEDIUM';
      const templateId = vuln['template-id'] || vuln.templateID || 'unknown';
      const name = vuln.info?.name || templateId;
      
      // Enhanced metadata for consolidated results
      const meta: any = {
        scan_id: scanId,
        scan_module: 'nuclei_consolidated',
        category,
        template_id: templateId,
        nuclei_type: vuln.type || 'vulnerability'
      };
      
      if (templateContext) {
        meta.template_context = templateContext;
      }
      
      // Extract CVE ID if this is a CVE-specific finding
      const cveMatch = templateId.match(/(CVE-\d{4}-\d+)/i) || 
                      name.match(/(CVE-\d{4}-\d+)/i);
      if (cveMatch) {
        meta.cve_id = cveMatch[1].toUpperCase();
        meta.verified_cve = true;
        
        // Add EPSS score if available
        const epssScore = epssScores.get(meta.cve_id);
        if (epssScore !== undefined) {
          meta.epss_score = epssScore;
        }
      }

      const artifactId = await insertArtifact({
        type: category === 'cve' ? 'verified_cve' : 'vuln',
        val_text: name,
        severity: severity as any,
        src_url: vuln.host || vuln.url,
        meta
      });

      let recommendation = 'Review and remediate the vulnerability immediately.';
      if (severity === 'CRITICAL') {
        recommendation = 'URGENT: This critical vulnerability requires immediate patching and investigation.';
      } else if (meta.cve_id) {
        recommendation = `CVE ${meta.cve_id} has been actively verified. Check for patches and apply immediately.`;
      }

      await insertFinding(
        artifactId,
        meta.cve_id ? 'VERIFIED_CVE' : 'VULNERABILITY',
        recommendation,
        vuln.info?.description || `Nuclei template ${templateId} detected a vulnerability`,
        vuln.curl_command || undefined
      );

      count++;
    } catch (error) {
      log(`[nuclei] Failed to process result:`, error);
    }
  }
  
  return count;
}

async function runNucleiTagScan(target: { url: string; tech?: string[] }, scanId?: string): Promise<number> {
  log(`[nuclei] [Tag Scan] Running enhanced two-pass scan on ${target.url}`);
  
  try {
    const result = await runTwoPassScan(target.url, {
      retries: 2,
      concurrency: Number(process.env.NUCLEI_CONCURRENCY) || 32,
      scanId: scanId
    });

    if (result.totalPersistedCount !== undefined) {
      log(`[nuclei] [Tag Scan] Completed for ${target.url}: ${result.totalPersistedCount} findings persisted as artifacts`);
      return result.totalPersistedCount;
    } else {
      // Fallback to manual processing if persistedCount not available
      const generalCount = await processNucleiResults(result.baselineResults, scanId!, 'general');
      const techCount = await processNucleiResults(result.techSpecificResults, scanId!, 'general');
      return generalCount + techCount;
    }
  } catch (error) {
    log(`[nuclei] [Tag Scan] Exception for ${target.url}:`, (error as Error).message);
    return 0;
  }
}

async function runNucleiWorkflow(target: { url: string }, workflowFileName: string, scanId?: string): Promise<number> {
  // Construct full path from base path and filename.
  const workflowPath = path.join(WORKFLOW_BASE_PATH, workflowFileName);
  
  log(`[nuclei] [Workflow Scan] Running workflow '${workflowPath}' on ${target.url}`);
  
  try {
    await fs.access(workflowPath);
  } catch {
    log(`[nuclei] [Workflow Scan] SKIPPING: Workflow file not found at ${workflowPath}`);
    return 0;
  }

  try {
    const result = await runNucleiWrapper({
      url: target.url,
      templates: [workflowPath],
      timeout: 180, // 3 minutes for headless operations
      scanId: scanId // Pass scanId for artifact persistence
    });

    if (!result.success) {
      log(`[nuclei] [Workflow Scan] Failed for ${target.url}: exit code ${result.exitCode}`);
      return 0;
    }

    if (result.stderr) {
      log(`[nuclei] [Workflow Scan] stderr for ${target.url}:`, result.stderr);
    }

    // Use persistedCount if available, otherwise fall back to manual processing
    if (scanId && result.persistedCount !== undefined) {
      log(`[nuclei] [Workflow Scan] Completed for ${target.url}: ${result.persistedCount} findings persisted as artifacts`);
      return result.persistedCount;
    } else {
      return await processNucleiResults(result.results, scanId!, 'workflow', workflowPath);
    }
  } catch (error) {
    log(`[nuclei] [Workflow Scan] Exception for ${target.url} with workflow ${workflowPath}:`, (error as Error).message);
    return 0;
  }
}

// NEW: CVE-specific scanning function
async function runNucleiCVEScan(
  targets: { url: string; tech?: string[] }[],
  cveIds: string[],
  scanId?: string
): Promise<{ count: number; results: Map<string, any> }> {
  if (!cveIds.length || !targets.length) {
    return { count: 0, results: new Map() };
  }

  log(`[nuclei] [CVE Scan] Running CVE verification for ${cveIds.length} CVEs on ${targets.length} targets`);
  
  const cveResults = new Map<string, any>();
  let totalCount = 0;

  // Build CVE templates - look for templates matching CVE IDs
  const cveTemplates = cveIds.map(cve => `cves/${cve.toLowerCase()}.yaml`);
  
  for (const target of targets.slice(0, 3)) { // Limit to top 3 targets for CVE verification
    try {
      const result = await runNucleiWrapper({
        url: target.url,
        templates: cveTemplates,
        timeout: 60, // 1 minute timeout for CVE verification
        concurrency: 5,
        scanId: scanId
      });

      if (result.success && result.results) {
        for (const finding of result.results) {
          // Extract CVE ID from template or finding
          const cveMatch = finding['template-id']?.match(/(CVE-\d{4}-\d+)/i) || 
                          finding.info?.name?.match(/(CVE-\d{4}-\d+)/i);
          
          if (cveMatch) {
            const cveId = cveMatch[1].toUpperCase();
            cveResults.set(cveId, {
              verified: true,
              exploitable: finding.info.severity === 'critical' || finding.info.severity === 'high',
              details: finding,
              target: target.url
            });
          }
        }
        
        // Process findings for artifacts
        if (scanId) {
          totalCount += await processNucleiResults(result.results, scanId, 'cve');
        }
      }
    } catch (error) {
      log(`[nuclei] [CVE Scan] Failed for ${target.url}:`, (error as Error).message);
    }
  }

  // Mark CVEs that weren't found as tested but not exploitable
  for (const cveId of cveIds) {
    if (!cveResults.has(cveId)) {
      cveResults.set(cveId, {
        verified: false,
        exploitable: false,
        tested: true
      });
    }
  }

  log(`[nuclei] [CVE Scan] Completed: ${totalCount} findings, ${cveResults.size} CVEs tested`);
  return { count: totalCount, results: cveResults };
}

// ENHANCED: Main export function with CVE consolidation
export async function runNuclei(request: NucleiScanRequest): Promise<ConsolidatedScanResult> {
  const { domain, scanId, targets, cveIds, specificTemplates, requesterModule } = request;
  
  log(`[nuclei] Starting consolidated vulnerability scan for ${domain}` + 
      (requesterModule ? ` (requested by ${requesterModule})` : ''));
  
  if (!(await validateDependencies())) {
    await insertArtifact({
      type: 'scan_error', 
      val_text: 'Nuclei binary not found, scan aborted.', 
      severity: 'HIGH', 
      meta: { scan_id: scanId, scan_module: 'nuclei_consolidated' }
    });
    return { totalFindings: 0, generalFindings: 0, cveFindings: 0 };
  }

  const scanTargets = targets?.length ? targets : [{ url: `https://${domain}` }];
  let generalFindings = 0;
  let cveFindings = 0;
  let cveResults = new Map<string, any>();
  
  // Phase 1: General vulnerability scanning (if not CVE-only request)
  if (!cveIds || cveIds.length === 0) {
    log(`[nuclei] --- Phase 1: General Vulnerability Scanning ---`);
    for (let i = 0; i < scanTargets.length; i += MAX_CONCURRENT_SCANS) {
      const chunk = scanTargets.slice(i, i + MAX_CONCURRENT_SCANS);
      const results = await Promise.all(chunk.map(target => {
        return runNucleiTagScan(target, scanId);
      }));
      generalFindings += results.reduce((a, b) => a + b, 0);
    }
  }

  // Phase 2: CVE-specific verification (if CVEs provided)
  if (cveIds && cveIds.length > 0) {
    log(`[nuclei] --- Phase 2: CVE Verification (${cveIds.length} CVEs) ---`);
    const cveResult = await runNucleiCVEScan(scanTargets, cveIds, scanId);
    cveFindings = cveResult.count;
    cveResults = cveResult.results;
  }

  // Phase 3: Technology-specific workflows (if not CVE-only request)
  if (!cveIds || cveIds.length === 0) {
    log(`[nuclei] --- Phase 3: Technology Workflows ---`);
    for (const target of scanTargets) {
      const detectedTech = new Set(target.tech?.map(t => t.toLowerCase()) || []);
      for (const tech in TECH_TO_WORKFLOW_MAP) {
        if (detectedTech.has(tech)) {
          generalFindings += await runNucleiWorkflow(target, TECH_TO_WORKFLOW_MAP[tech], scanId);
        }
      }
    }
  }

  const totalFindings = generalFindings + cveFindings;
  
  log(`[nuclei] Consolidated scan completed. General: ${generalFindings}, CVE: ${cveFindings}, Total: ${totalFindings}`);
  
  return {
    totalFindings,
    generalFindings,
    cveFindings,
    cveResults
  };
}

// Legacy compatibility export
export async function runNucleiLegacy(job: { domain: string; scanId?: string; targets?: { url: string; tech?: string[] }[] }): Promise<number> {
  const result = await runNuclei({
    domain: job.domain,
    scanId: job.scanId,
    targets: job.targets,
    requesterModule: 'legacy_worker'
  });
  return result.totalFindings;
}
