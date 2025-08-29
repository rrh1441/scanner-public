/**
 * OWASP ZAP Web Application Security Scanner Integration
 * 
 * Provides comprehensive web application security testing using OWASP ZAP baseline scanner.
 * Integrates with asset classification system for smart targeting.
 * Designed for dedicated ZAP worker architecture with pay-per-second economics.
 */

import { spawn } from 'node:child_process';
import { readFile, unlink, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as rootLog } from '../core/logger.js';
import { isNonHtmlAsset } from '../util/nucleiWrapper.js';
import { executeModule, fileOperation } from '../util/errorHandler.js';

// Enhanced logging
const log = (...args: unknown[]) => rootLog('[zapScan]', ...args);

interface ZAPVulnerability {
  alert: string;
  name: string;
  riskdesc: string;
  confidence: string;
  riskcode: string;
  desc: string;
  instances: ZAPInstance[];
  solution: string;
  reference: string;
  cweid: string;
  wascid: string;
  sourceid: string;
}

interface ZAPInstance {
  uri: string;
  method: string;
  param: string;
  attack: string;
  evidence: string;
}

interface ZAPScanResult {
  site: ZAPSite[];
}

interface ZAPSite {
  name: string;
  host: string;
  port: string;
  ssl: boolean;
  alerts: ZAPVulnerability[];
}

// Configuration
const ZAP_DOCKER_IMAGE = 'zaproxy/zap-stable';
const ZAP_TIMEOUT_MS = 180_000; // 3 minutes per target
const MAX_ZAP_TARGETS = 5;      // Limit targets for performance
const ARTIFACTS_DIR = './artifacts'; // Directory for ZAP outputs

/**
 * Main ZAP scanning function
 */
export async function runZAPScan(job: { 
  domain: string; 
  scanId: string 
}): Promise<number> {
  const { domain, scanId } = job;
  
  return executeModule('zapScan', async () => {
    log(`Starting OWASP ZAP web application security scan for ${domain}`);

    // Check if Docker is available for ZAP
    if (!await isDockerAvailable()) {
      log(`Docker not available for ZAP scanning - skipping web application scan`);
      
      await insertArtifact({
        type: 'scan_warning',
        val_text: `Docker not available - ZAP web application security testing skipped`,
        severity: 'LOW',
        meta: {
          scan_id: scanId,
          scan_module: 'zapScan',
          reason: 'docker_unavailable'
        }
      });
      
      return 0;
    }

    // Ensure ZAP Docker image is available
    await ensureZAPImage();

    // Get high-value web application targets
    const targets = await getZAPTargets(scanId, domain);
    if (targets.length === 0) {
      log(`No suitable web targets found for ZAP scanning`);
      return 0;
    }

    log(`Found ${targets.length} high-value web targets for ZAP scanning`);

    // Execute ZAP baseline scan for each target
    let totalFindings = 0;
    
    for (const target of targets) {
      try {
        const findings = await executeZAPBaseline(target.url, target.assetType, scanId);
        totalFindings += findings;
      } catch (error) {
        log(`ZAP scan failed for ${target.url}: ${(error as Error).message}`);
        
        // Create error artifact for failed ZAP scan
        await insertArtifact({
          type: 'scan_error',
          val_text: `ZAP scan failed for ${target.url}: ${(error as Error).message}`,
          severity: 'MEDIUM',
          meta: {
            scan_id: scanId,
            scan_module: 'zapScan',
            target_url: target.url,
            asset_type: target.assetType,
            error_message: (error as Error).message
          }
        });
      }
    }
    
    // Create summary artifact
    await insertArtifact({
      type: 'zap_scan_summary',
      val_text: `ZAP scan completed: ${totalFindings} web application vulnerabilities found across ${targets.length} targets`,
      severity: totalFindings > 5 ? 'HIGH' : totalFindings > 0 ? 'MEDIUM' : 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'zapScan',
        domain,
        total_vulnerabilities: totalFindings,
        targets_scanned: targets.length,
        targets: targets.map(t => ({ url: t.url, asset_type: t.assetType }))
      }
    });

    log(`ZAP scan completed: ${totalFindings} web application vulnerabilities found`);
    return totalFindings;
    
  }, { scanId, target: domain });
}

/**
 * Check if Docker is available
 */
async function isDockerAvailable(): Promise<boolean> {
  try {
    const result = await new Promise<boolean>((resolve) => {
      const dockerProcess = spawn('docker', ['--version'], { stdio: 'pipe' });
      dockerProcess.on('exit', (code) => {
        resolve(code === 0);
      });
      dockerProcess.on('error', () => {
        resolve(false);
      });
    });
    return result;
  } catch {
    return false;
  }
}

/**
 * Ensure ZAP Docker image is available
 */
async function ensureZAPImage(): Promise<void> {
  try {
    log(`Ensuring ZAP Docker image ${ZAP_DOCKER_IMAGE} is available`);
    
    await new Promise<void>((resolve, reject) => {
      // Try to pull the image, but don't fail if it already exists
      const pullProcess = spawn('docker', ['pull', ZAP_DOCKER_IMAGE], { 
        stdio: ['ignore', 'pipe', 'pipe'] 
      });
      
      pullProcess.on('exit', (code) => {
        if (code === 0) {
          log(`ZAP Docker image pulled successfully`);
          resolve();
        } else {
          // Image might already exist, try to verify
          const inspectProcess = spawn('docker', ['image', 'inspect', ZAP_DOCKER_IMAGE], {
            stdio: 'pipe'
          });
          
          inspectProcess.on('exit', (inspectCode) => {
            if (inspectCode === 0) {
              log(`ZAP Docker image already available`);
              resolve();
            } else {
              reject(new Error(`Failed to pull or find ZAP Docker image`));
            }
          });
        }
      });
      
      pullProcess.on('error', reject);
    });
  } catch (error) {
    log(`Warning: Could not ensure ZAP Docker image: ${(error as Error).message}`);
    // Don't fail completely, image might still work
  }
}

/**
 * Get high-value web application targets using existing asset classification
 */
async function getZAPTargets(scanId: string, domain: string): Promise<Array<{url: string, assetType: string}>> {
  try {
    // Get discovered endpoints from endpointDiscovery
    // Pool query removed for GCP migration - starting fresh
    const rows: any[] = [];
    const result = { rows: [] };    
    const discoveredUrls = rows.map(r => r.src_url);
    
    // If no discovered endpoints, use high-value defaults
    const urls = discoveredUrls.length > 0 ? discoveredUrls : [
      `https://${domain}`,
      `https://www.${domain}`,
      `https://app.${domain}`,
      `https://admin.${domain}`,
      `https://portal.${domain}`,
      `https://api.${domain}/docs`, // API documentation often has web interfaces
      `https://${domain}/admin`,
      `https://${domain}/login`,
      `https://${domain}/dashboard`
    ];
    
    // Filter for web applications (HTML assets only)
    const targets = urls
      .filter(url => !isNonHtmlAsset(url))
      .map(url => ({
        url,
        assetType: 'html' // All remaining URLs after filtering are HTML assets
      }))
      .slice(0, MAX_ZAP_TARGETS);
    
    log(`Identified ${targets.length} ZAP targets from ${urls.length} discovered URLs`);
    
    return targets;
  } catch (error) {
    log(`Error discovering ZAP targets: ${(error as Error).message}`);
    // Fallback to basic targets
    return [
      { url: `https://${domain}`, assetType: 'html' },
      { url: `https://www.${domain}`, assetType: 'html' }
    ];
  }
}

/**
 * Execute ZAP baseline scan against target
 */
async function executeZAPBaseline(target: string, assetType: string, scanId: string): Promise<number> {
  const outputFileName = `zap_report_${Date.now()}.json`;
  const outputFile = `${ARTIFACTS_DIR}/${outputFileName}`;
  
  // Ensure artifacts directory exists
  const dirOperation = async () => {
    if (!existsSync(ARTIFACTS_DIR)) {
      await mkdir(ARTIFACTS_DIR, { recursive: true });
    }
  };

  const dirResult = await fileOperation(dirOperation, {
    moduleName: 'zapScan',
    operation: 'createDirectory',
    target: ARTIFACTS_DIR
  });

  if (!dirResult.success) {
    throw new Error(`Failed to create artifacts directory: ${(dirResult as any).error}`);
  }

  log(`Running ZAP baseline scan for ${target}`);
  
  // Generate unique container name for tracking
  const containerName = `zap-scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  
  const zapArgs = [
    'run', '--rm',
    '--name', containerName,
    '-v', `${process.cwd()}/${ARTIFACTS_DIR}:/zap/wrk/:rw`,
    ZAP_DOCKER_IMAGE,
    'zap-baseline.py',
    '-t', target,
    '-J', outputFileName, // JSON output
    '-x', outputFileName.replace('.json', '.xml'), // XML output (backup)
    '-d', // Include response details
    '-I', // Don't return failure codes
    '-r', outputFileName.replace('.json', '.html') // HTML report
  ];

  log(`ZAP command: docker ${zapArgs.join(' ')}`);
  
  return new Promise<number>((resolve, reject) => {
    const zapProcess = spawn('docker', zapArgs, {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: ZAP_TIMEOUT_MS
    });

    let stdout = '';
    let stderr = '';

    zapProcess.stdout?.on('data', (data) => {
      stdout += data.toString();
      log(`ZAP stdout: ${data.toString().trim()}`);
    });

    zapProcess.stderr?.on('data', (data) => {
      stderr += data.toString();
      log(`ZAP stderr: ${data.toString().trim()}`);
    });

    zapProcess.on('exit', async (code, signal) => {
      log(`ZAP process exited with code ${code}, signal ${signal}`);
      
      // Clean up Docker container after process exits
      const cleanup = spawn('docker', ['rm', '-f', containerName], { stdio: 'ignore' });
      cleanup.on('error', () => {
        // Ignore cleanup errors - container might already be gone
      });
      
      // Check if output file was created
      if (existsSync(outputFile)) {
        try {
          const findings = await parseZAPResults(outputFile, target, assetType, scanId);
          
          // Clean up the output file
          const cleanupResult = await fileOperation(
            () => unlink(outputFile),
            {
              moduleName: 'zapScan',
              operation: 'cleanupFile',
              target: outputFile
            }
          );

          if (!cleanupResult.success) {
            log(`Failed to cleanup ZAP output file: ${(cleanupResult as any).error}`);
          }
          
          resolve(findings);
        } catch (error) {
          reject(new Error(`Failed to parse ZAP results: ${(error as Error).message}`));
        }
      } else {
        reject(new Error(`ZAP scan failed - no output file generated. Exit code: ${code}`));
      }
    });

    zapProcess.on('error', (error) => {
      reject(new Error(`ZAP process error: ${error.message}`));
    });

    zapProcess.on('timeout', () => {
      log(`ZAP scan timeout after ${ZAP_TIMEOUT_MS}ms, attempting container cleanup`);
      
      // Kill the ZAP process
      zapProcess.kill('SIGKILL');
      
      // Also attempt to stop and remove the Docker container
      const cleanup = spawn('docker', ['stop', containerName], { stdio: 'ignore' });
      cleanup.on('exit', () => {
        spawn('docker', ['rm', '-f', containerName], { stdio: 'ignore' });
      });
      
      reject(new Error(`ZAP scan timeout after ${ZAP_TIMEOUT_MS}ms`));
    });
  });
}

/**
 * Parse ZAP JSON results and create findings
 */
async function parseZAPResults(outputFile: string, target: string, assetType: string, scanId: string): Promise<number> {
  const parseOperation = async () => {
    const content = await readFile(outputFile, 'utf-8');
    return JSON.parse(content) as ZAPScanResult;
  };

  const result = await fileOperation(parseOperation, {
    moduleName: 'zapScan',
    operation: 'parseResults',
    target: outputFile
  });

  if (!result.success) {
    throw new Error(`Failed to parse ZAP results: ${(result as any).error}`);
  }

  const zapResult = result.data;
  let findingsCount = 0;

  for (const site of zapResult.site || []) {
    for (const alert of site.alerts || []) {
      // Create artifact for each vulnerability
      const severity = escalateSeverityForAsset(
        mapZAPRiskToSeverity(alert.riskcode),
        assetType
      );

      const artifactId = await insertArtifact({
        type: 'zap_vulnerability',
        val_text: `ZAP detected ${alert.name} on ${target}`,
        severity,
        meta: {
          scan_id: scanId,
          scan_module: 'zapScan',
          target_url: target,
          asset_type: assetType,
          alert_name: alert.name,
          risk_code: alert.riskcode,
          confidence: alert.confidence,
          cwe_id: alert.cweid,
          wasc_id: alert.wascid,
          instances: alert.instances?.length || 0
        }
      });

      // Build detailed description with instances
      let description = alert.desc;
      if (alert.instances && alert.instances.length > 0) {
        description += '\n\nInstances:\n';
        alert.instances.slice(0, 3).forEach((instance, idx) => {
          description += `${idx + 1}. ${instance.method} ${instance.uri}`;
          if (instance.param) description += ` (param: ${instance.param})`;
          if (instance.evidence) description += ` - Evidence: ${instance.evidence.slice(0, 100)}`;
          description += '\n';
        });
        
        if (alert.instances.length > 3) {
          description += `... and ${alert.instances.length - 3} more instances`;
        }
      }

      await insertFinding(
        artifactId,
        'WEB_APPLICATION_VULNERABILITY',
        alert.solution || 'Review and remediate according to ZAP recommendations',
        description
      );

      findingsCount++;
    }
  }

  log(`Parsed ${findingsCount} vulnerabilities from ZAP results for ${target}`);
  return findingsCount;
}

/**
 * Map ZAP risk codes to severity levels
 */
function mapZAPRiskToSeverity(riskCode: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  switch (riskCode) {
    case '3': return 'HIGH';     // ZAP High -> Our High
    case '2': return 'MEDIUM';   // ZAP Medium -> Our Medium
    case '1': return 'LOW';      // ZAP Low -> Our Low
    case '0': return 'INFO';     // ZAP Info -> Our Info
    default: return 'LOW';
  }
}

/**
 * Escalate severity for critical asset types (admin panels, customer portals, etc.)
 */
function escalateSeverityForAsset(
  baseSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
  assetType: string
): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  // Critical assets get severity escalation
  const criticalAssetPatterns = [
    'admin', 'portal', 'customer', 'management', 
    'backend', 'control', 'dashboard'
  ];
  
  const isCriticalAsset = criticalAssetPatterns.some(pattern => 
    assetType.toLowerCase().includes(pattern)
  );
  
  if (!isCriticalAsset) {
    return baseSeverity;
  }
  
  // Escalate for critical assets
  switch (baseSeverity) {
    case 'HIGH': return 'CRITICAL';
    case 'MEDIUM': return 'HIGH';
    case 'LOW': return 'MEDIUM';
    default: return baseSeverity; // Keep INFO and CRITICAL as-is
  }
}

