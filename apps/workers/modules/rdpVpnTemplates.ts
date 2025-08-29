/**
 * RDP/VPN Templates Module
 * 
 * Uses Nuclei templates to detect exposed RDP services and vulnerable VPN portals
 * including FortiNet, Palo Alto GlobalProtect, and other remote access solutions.
 */

import * as fs from 'node:fs/promises';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as rootLog } from '../core/logger.js';
import { runNuclei, createTargetsFile, cleanupFile } from '../util/nucleiWrapper.js';

// Configuration constants
const NUCLEI_TIMEOUT_MS = 300_000; // 5 minutes
const MAX_TARGETS = 50;
const CONCURRENCY = 6;

// Enhanced logging
const log = (...args: unknown[]) => rootLog('[rdpVpnTemplates]', ...args);

// RDP and VPN specific Nuclei templates
const RDP_VPN_TEMPLATES = [
  'network/rdp-detect.yaml',
  'network/rdp-bluekeep-detect.yaml',
  'vulnerabilities/fortinet/fortinet-fortigate-cve-2018-13379.yaml',
  'vulnerabilities/fortinet/fortinet-fortigate-cve-2019-5591.yaml',
  'vulnerabilities/fortinet/fortinet-fortigate-cve-2020-12812.yaml',
  'vulnerabilities/paloalto/paloalto-globalprotect-cve-2019-1579.yaml',
  'vulnerabilities/paloalto/paloalto-globalprotect-cve-2020-2021.yaml',
  'vulnerabilities/citrix/citrix-adc-cve-2019-19781.yaml',
  'vulnerabilities/pulse/pulse-connect-secure-cve-2019-11510.yaml',
  'technologies/rdp-detect.yaml',
  'technologies/vpn-detect.yaml'
];

// EPSS threshold for double severity
const HIGH_EPSS_THRESHOLD = 0.7;

interface NucleiResult {
  template: string;
  'template-url': string;
  'template-id': string;
  'template-path': string;
  info: {
    name: string;
    author: string[];
    tags: string[];
    description?: string;
    reference?: string[];
    severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    classification?: {
      'cvss-metrics'?: string;
      'cvss-score'?: number;
      'cve-id'?: string;
      'cwe-id'?: string;
      epss?: {
        score: number;
        percentile: number;
      };
    };
  };
  type: string;
  host: string;
  'matched-at': string;
  'extracted-results'?: string[];
  'curl-command'?: string;
  matcher?: {
    name: string;
    status: number;
  };
  timestamp: string;
}

interface RdpVpnScanSummary {
  totalTargets: number;
  rdpExposed: number;
  vpnVulnerabilities: number;
  criticalFindings: number;
  highEpssFindings: number;
  templatesExecuted: number;
}

/**
 * Get target URLs from discovered artifacts
 */
async function getTargetUrls(scanId: string, domain: string): Promise<string[]> {
  const targets = new Set<string>();
  
  try {
    // Get URLs from previous scans
    // Pool query removed for GCP migration - starting fresh
    const urlRows: any[] = [];
    const urlResult = { rows: urlRows };    
    urlRows.forEach((row: any) => {
      targets.add(row.val_text.trim());
    });
    
    // Get hostnames and subdomains to construct URLs
    // Pool query removed for GCP migration - starting fresh
    const hostRows: any[] = [];
    const hostResult = { rows: hostRows };    
    const hosts = new Set([domain]);
    hostRows.forEach((row: any) => {
      hosts.add(row.val_text.trim());
    });
    
    // Generate common RDP/VPN URLs
    const rdpVpnPaths = [
      '', // Root domain
      '/remote',
      '/vpn',
      '/rdp',
      '/citrix',
      '/pulse',
      '/fortinet',
      '/globalprotect',
      '/portal',
      '/dana-na',
      '/remote/login'
    ];
    
    hosts.forEach(host => {
      // Try both HTTP and HTTPS
      ['https', 'http'].forEach(protocol => {
        rdpVpnPaths.forEach(path => {
          const url = `${protocol}://${host}${path}`;
          targets.add(url);
        });
      });
    });
    
    log(`Generated ${targets.size} target URLs for RDP/VPN scanning`);
    return Array.from(targets).slice(0, MAX_TARGETS);
    
  } catch (error) {
    log(`Error getting target URLs: ${(error as Error).message}`);
    return [];
  }
}

/**
 * Run Nuclei with RDP/VPN templates
 */
async function runNucleiRdpVpn(targets: string[]): Promise<NucleiResult[]> {
  if (targets.length === 0) {
    return [];
  }
  
  try {
    // Create temporary targets file
    const targetsFile = await createTargetsFile(targets, 'nuclei-rdpvpn-targets');
    
    log(`Running Nuclei with ${RDP_VPN_TEMPLATES.length} RDP/VPN templates against ${targets.length} targets`);
    
    // Use the standardized nuclei wrapper with specific RDP/VPN templates
    const result = await runNuclei({
      targetList: targetsFile,
      templates: RDP_VPN_TEMPLATES,
      retries: 2,
      concurrency: CONCURRENCY,
      headless: true // RDP/VPN portals may need headless for login detection
    });
    
    // Cleanup targets file
    await cleanupFile(targetsFile);
    
    if (!result.success) {
      log(`Nuclei RDP/VPN scan failed with exit code ${result.exitCode}`);
      return [];
    }
    
    // Enhanced stderr logging - capture full output for better debugging
    if (result.stderr) {
      log(`Nuclei stderr: ${result.stderr}`);
    }
    
    log(`Nuclei RDP/VPN scan completed: ${result.results.length} findings`);
    return result.results as NucleiResult[];
    
  } catch (error) {
    log(`Nuclei RDP/VPN scan failed: ${(error as Error).message}`);
    return [];
  }
}

/**
 * Analyze Nuclei result and determine finding type and severity
 */
function analyzeNucleiResult(result: NucleiResult): {
  findingType: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  isHighEpss: boolean;
  description: string;
  evidence: string;
} {
  const tags = result.info.tags || [];
  const cveId = result.info.classification?.['cve-id'];
  const epssScore = result.info.classification?.epss?.score || 0;
  const templateName = result.info.name;
  const host = result.host;
  
  let findingType = 'EXPOSED_SERVICE';
  let severity = result.info.severity.toUpperCase() as 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  let isHighEpss = epssScore >= HIGH_EPSS_THRESHOLD;
  
  // Determine specific finding type
  if (tags.includes('rdp') || templateName.toLowerCase().includes('rdp')) {
    findingType = 'EXPOSED_RDP';
  } else if (cveId && (tags.includes('vpn') || tags.includes('fortinet') || tags.includes('paloalto'))) {
    findingType = 'UNPATCHED_VPN_CVE';
    
    // Double severity for high EPSS VPN CVEs
    if (isHighEpss) {
      const severityMap = { 'INFO': 'LOW', 'LOW': 'MEDIUM', 'MEDIUM': 'HIGH', 'HIGH': 'CRITICAL', 'CRITICAL': 'CRITICAL' };
      severity = severityMap[severity] as typeof severity;
    }
  } else if (tags.includes('vpn') || templateName.toLowerCase().includes('vpn')) {
    findingType = 'EXPOSED_VPN';
  }
  
  const description = `${templateName} detected on ${host}${cveId ? ` (${cveId})` : ''}`;
  const evidence = `Template: ${result['template-id']} | URL: ${result['matched-at']}${epssScore > 0 ? ` | EPSS: ${epssScore.toFixed(3)}` : ''}`;
  
  return {
    findingType,
    severity,
    isHighEpss,
    description,
    evidence
  };
}

/**
 * Main RDP/VPN templates scan function
 */
export async function runRdpVpnTemplates(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;
  const startTime = Date.now();
  
  log(`Starting RDP/VPN templates scan for domain="${domain}"`);
  
  try {
    // Get target URLs
    const targets = await getTargetUrls(scanId, domain);
    
    if (targets.length === 0) {
      log('No targets found for RDP/VPN scanning');
      return 0;
    }
    
    // Run Nuclei with RDP/VPN templates
    const nucleiResults = await runNucleiRdpVpn(targets);
    
    if (nucleiResults.length === 0) {
      log('No RDP/VPN vulnerabilities detected');
      return 0;
    }
    
    // Analyze results
    const summary: RdpVpnScanSummary = {
      totalTargets: targets.length,
      rdpExposed: 0,
      vpnVulnerabilities: 0,
      criticalFindings: 0,
      highEpssFindings: 0,
      templatesExecuted: RDP_VPN_TEMPLATES.length
    };
    
    // Create summary artifact
    const artifactId = await insertArtifact({
      type: 'rdp_vpn_scan_summary',
      val_text: `RDP/VPN scan: ${nucleiResults.length} remote access issues found`,
      severity: nucleiResults.some(r => r.info.severity === 'critical') ? 'CRITICAL' : 
               nucleiResults.some(r => r.info.severity === 'high') ? 'HIGH' : 'MEDIUM',
      meta: {
        scan_id: scanId,
        scan_module: 'rdpVpnTemplates',
        domain,
        summary,
        total_results: nucleiResults.length,
        scan_duration_ms: Date.now() - startTime
      }
    });
    
    let findingsCount = 0;
    
    // Process each Nuclei result
    for (const result of nucleiResults) {
      const analysis = analyzeNucleiResult(result);
      
      // Update summary statistics
      if (analysis.findingType === 'EXPOSED_RDP') summary.rdpExposed++;
      if (analysis.findingType === 'UNPATCHED_VPN_CVE') summary.vpnVulnerabilities++;
      if (analysis.severity === 'CRITICAL') summary.criticalFindings++;
      if (analysis.isHighEpss) summary.highEpssFindings++;
      
      await insertFinding(
        artifactId,
        analysis.findingType,
        analysis.description,
        analysis.evidence
      );
      
      findingsCount++;
    }
    
    const duration = Date.now() - startTime;
    log(`RDP/VPN templates scan completed: ${findingsCount} findings in ${duration}ms`);
    
    return findingsCount;
    
  } catch (error) {
    const errorMsg = (error as Error).message;
    log(`RDP/VPN templates scan failed: ${errorMsg}`);
    
    await insertArtifact({
      type: 'scan_error',
      val_text: `RDP/VPN templates scan failed: ${errorMsg}`,
      severity: 'MEDIUM',
      meta: {
        scan_id: scanId,
        scan_module: 'rdpVpnTemplates',
        scan_duration_ms: Date.now() - startTime
      }
    });
    
    return 0;
  }
}