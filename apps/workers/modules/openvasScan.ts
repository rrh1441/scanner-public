/**
 * OpenVAS/Greenbone CE Integration Module
 * 
 * Provides enterprise-grade vulnerability scanning using OpenVAS/Greenbone Community Edition.
 * This serves as a more comprehensive alternative to Nuclei for deep vulnerability assessment.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { writeFile, unlink } from 'fs/promises';
import { randomBytes } from 'crypto';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { securityWrapper } from '../core/securityWrapper.js';

const execFileAsync = promisify(execFile);

interface OpenVASConfig {
  host: string;
  port: number;
  username: string;
  password: string;
  timeout: number;
}

interface OpenVASVulnerability {
  id: string;
  name: string;
  severity: number;
  description: string;
  solution: string;
  host: string;
  port: string;
  threat: string;
  family: string;
  cvss_base: number;
  cve_ids: string[];
}

interface OpenVASScanResult {
  task_id: string;
  report_id: string;
  vulnerabilities: OpenVASVulnerability[];
  scan_start: string;
  scan_end: string;
  hosts_scanned: number;
  total_vulnerabilities: number;
}

function log(...args: any[]) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [openvas]`, ...args);
}

/**
 * Main OpenVAS scanning function
 */
export async function runOpenVASScan(job: { 
  domain: string; 
  scanId: string 
}): Promise<number> {
  const { domain, scanId } = job;
  log(`Starting OpenVAS vulnerability scan for ${domain}`);

  // Check if OpenVAS is available and configured
  const config = await validateOpenVASConfiguration();
  if (!config) {
    log(`OpenVAS not available or configured - skipping scan`);
    
    await insertArtifact({
      type: 'scan_warning',
      val_text: `OpenVAS vulnerability scanner not configured - comprehensive vulnerability scanning unavailable`,
      severity: 'LOW',
      meta: {
        scan_id: scanId,
        scan_module: 'openvasScan',
        reason: 'scanner_unavailable'
      }
    });
    
    return 0;
  }

  try {
    // Discover targets from previous scans
    const targets = await discoverScanTargets(domain, scanId);
    if (targets.length === 0) {
      log(`No targets discovered for OpenVAS scan`);
      return 0;
    }

    log(`Discovered ${targets.length} targets for vulnerability scanning`);

    // Execute OpenVAS scan via GVM tools
    const scanResult = await executeOpenVASScan(targets, config, scanId);
    
    // Process and store findings
    const findingsCount = await processScanResults(scanResult, scanId, domain);
    
    // Create summary artifact
    await insertArtifact({
      type: 'scan_summary',
      val_text: `OpenVAS scan completed: ${findingsCount} vulnerabilities found across ${scanResult.hosts_scanned} hosts`,
      severity: findingsCount > 10 ? 'HIGH' : findingsCount > 0 ? 'MEDIUM' : 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'openvasScan',
        total_vulnerabilities: scanResult.total_vulnerabilities,
        hosts_scanned: scanResult.hosts_scanned,
        scan_duration: scanResult.scan_end ? 
          new Date(scanResult.scan_end).getTime() - new Date(scanResult.scan_start).getTime() : 0
      }
    });

    log(`OpenVAS scan completed: ${findingsCount} vulnerabilities found`);
    return findingsCount;

  } catch (error) {
    log(`OpenVAS scan failed: ${(error as Error).message}`);
    
    await insertArtifact({
      type: 'scan_error',
      val_text: `OpenVAS vulnerability scan failed: ${(error as Error).message}`,
      severity: 'MEDIUM',
      meta: {
        scan_id: scanId,
        scan_module: 'openvasScan',
        error: true,
        error_message: (error as Error).message
      }
    });
    
    return 0;
  }
}

/**
 * Validate OpenVAS configuration and availability
 */
async function validateOpenVASConfiguration(): Promise<OpenVASConfig | null> {
  const requiredEnvVars = [
    'OPENVAS_HOST',
    'OPENVAS_USERNAME', 
    'OPENVAS_PASSWORD'
  ];

  // Check if all required environment variables are set
  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      log(`Missing required environment variable: ${envVar}`);
      return null;
    }
  }

  const config: OpenVASConfig = {
    host: process.env.OPENVAS_HOST!,
    port: parseInt(process.env.OPENVAS_PORT || '9390'),
    username: process.env.OPENVAS_USERNAME!,
    password: process.env.OPENVAS_PASSWORD!,
    timeout: parseInt(process.env.OPENVAS_TIMEOUT || '1800') * 1000 // Convert to ms
  };

  // Test connectivity to OpenVAS
  try {
    await execFileAsync('gvm-cli', [
      '--gmp-username', config.username,
      '--gmp-password', config.password,
      '--gmp-host', config.host,
      '--gmp-port', config.port.toString(),
      '--xml', '<get_version/>'
    ], { timeout: 10000 });

    log(`OpenVAS connection validated successfully`);
    return config;

  } catch (error) {
    log(`OpenVAS connection test failed: ${(error as Error).message}`);
    return null;
  }
}

/**
 * Discover scan targets from previous discovery modules
 */
async function discoverScanTargets(domain: string, scanId: string): Promise<string[]> {
  // In a real implementation, this would query the artifact store
  // for IP addresses and hosts discovered by previous modules
  
  // For now, return the primary domain and common variations
  const targets = [
    domain,
    `www.${domain}`,
    `mail.${domain}`,
    `ftp.${domain}`,
    `admin.${domain}`,
    `api.${domain}`
  ];

  // Filter out duplicates and invalid targets
  return [...new Set(targets)].slice(0, 10); // Limit to 10 targets for performance
}

/**
 * Execute OpenVAS scan using GVM tools
 */
async function executeOpenVASScan(
  targets: string[], 
  config: OpenVASConfig, 
  scanId: string
): Promise<OpenVASScanResult> {
  const taskName = `DealBrief-${scanId}-${Date.now()}`;
  const targetList = targets.join(', ');

  try {
    // Create target
    log(`Creating OpenVAS target: ${targetList}`);
    const createTargetXML = `
      <create_target>
        <name>${taskName}-target</name>
        <hosts>${targetList}</hosts>
        <comment>DealBrief automated scan target for ${scanId}</comment>
      </create_target>
    `;

    const { stdout: targetResponse } = await execFileAsync('gvm-cli', [
      '--gmp-username', config.username,
      '--gmp-password', config.password,
      '--gmp-host', config.host,
      '--gmp-port', config.port.toString(),
      '--xml', createTargetXML
    ], { timeout: 30000 });

    const targetId = extractIdFromResponse(targetResponse);
    if (!targetId) {
      throw new Error('Failed to create OpenVAS target');
    }

    // Create task with Full and fast scan config
    log(`Creating OpenVAS task: ${taskName}`);
    const createTaskXML = `
      <create_task>
        <name>${taskName}</name>
        <target id="${targetId}"/>
        <config id="daba56c8-73ec-11df-a475-002264764cea"/>
        <comment>DealBrief automated vulnerability scan</comment>
      </create_task>
    `;

    const { stdout: taskResponse } = await execFileAsync('gvm-cli', [
      '--gmp-username', config.username,
      '--gmp-password', config.password,
      '--gmp-host', config.host,
      '--gmp-port', config.port.toString(),
      '--xml', createTaskXML
    ], { timeout: 30000 });

    const taskId = extractIdFromResponse(taskResponse);
    if (!taskId) {
      throw new Error('Failed to create OpenVAS task');
    }

    // Start task
    log(`Starting OpenVAS task: ${taskId}`);
    const startTaskXML = `<start_task task_id="${taskId}"/>`;
    
    await execFileAsync('gvm-cli', [
      '--gmp-username', config.username,
      '--gmp-password', config.password,
      '--gmp-host', config.host,
      '--gmp-port', config.port.toString(),
      '--xml', startTaskXML
    ], { timeout: 30000 });

    // Monitor task progress
    const reportId = await monitorTaskProgress(taskId, config);
    
    // Get scan results
    const vulnerabilities = await getScanResults(reportId, config);

    return {
      task_id: taskId,
      report_id: reportId,
      vulnerabilities,
      scan_start: new Date().toISOString(),
      scan_end: new Date().toISOString(),
      hosts_scanned: targets.length,
      total_vulnerabilities: vulnerabilities.length
    };

  } catch (error) {
    log(`OpenVAS scan execution failed: ${(error as Error).message}`);
    throw error;
  }
}

/**
 * Monitor OpenVAS task progress
 */
async function monitorTaskProgress(taskId: string, config: OpenVASConfig): Promise<string> {
  const maxWaitTime = config.timeout;
  const pollInterval = 30000; // 30 seconds
  const startTime = Date.now();

  log(`Monitoring OpenVAS task progress: ${taskId}`);

  while (Date.now() - startTime < maxWaitTime) {
    try {
      const getTaskXML = `<get_tasks task_id="${taskId}"/>`;
      
      const { stdout: taskStatus } = await execFileAsync('gvm-cli', [
        '--gmp-username', config.username,
        '--gmp-password', config.password,
        '--gmp-host', config.host,
        '--gmp-port', config.port.toString(),
        '--xml', getTaskXML
      ], { timeout: 30000 });

      // Parse task status
      if (taskStatus.includes('Done')) {
        const reportId = extractReportIdFromTask(taskStatus);
        if (reportId) {
          log(`OpenVAS task completed: ${taskId}, report: ${reportId}`);
          return reportId;
        }
      } else if (taskStatus.includes('Running')) {
        const progress = extractProgressFromTask(taskStatus);
        log(`OpenVAS scan progress: ${progress}%`);
      }

      // Wait before next poll
      await new Promise(resolve => setTimeout(resolve, pollInterval));

    } catch (error) {
      log(`Error monitoring task progress: ${(error as Error).message}`);
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }
  }

  throw new Error(`OpenVAS scan timeout after ${maxWaitTime}ms`);
}

/**
 * Get scan results from OpenVAS report
 */
async function getScanResults(reportId: string, config: OpenVASConfig): Promise<OpenVASVulnerability[]> {
  try {
    log(`Retrieving OpenVAS scan results: ${reportId}`);
    
    const getReportXML = `<get_reports report_id="${reportId}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"/>`;
    
    const { stdout: reportData } = await execFileAsync('gvm-cli', [
      '--gmp-username', config.username,
      '--gmp-password', config.password,
      '--gmp-host', config.host,
      '--gmp-port', config.port.toString(),
      '--xml', getReportXML
    ], { 
      timeout: 60000,
      maxBuffer: 50 * 1024 * 1024 // 50MB buffer for large reports
    });

    return parseOpenVASReport(reportData);

  } catch (error) {
    log(`Failed to retrieve scan results: ${(error as Error).message}`);
    return [];
  }
}

/**
 * Parse OpenVAS XML report into structured vulnerabilities
 */
function parseOpenVASReport(xmlData: string): OpenVASVulnerability[] {
  const vulnerabilities: OpenVASVulnerability[] = [];
  
  // Basic XML parsing (in production, use a proper XML parser)
  const resultRegex = /<result[^>]*>(.*?)<\/result>/gs;
  let match;

  while ((match = resultRegex.exec(xmlData)) !== null) {
    const resultXML = match[1];
    
    try {
      const vulnerability: OpenVASVulnerability = {
        id: extractXMLValue(resultXML, 'nvt', 'oid') || 'unknown',
        name: extractXMLValue(resultXML, 'name') || 'Unknown Vulnerability',
        severity: parseFloat(extractXMLValue(resultXML, 'severity') || '0'),
        description: extractXMLValue(resultXML, 'description') || '',
        solution: extractXMLValue(resultXML, 'solution') || '',
        host: extractXMLValue(resultXML, 'host') || '',
        port: extractXMLValue(resultXML, 'port') || '',
        threat: extractXMLValue(resultXML, 'threat') || 'Unknown',
        family: extractXMLValue(resultXML, 'family') || 'General',
        cvss_base: parseFloat(extractXMLValue(resultXML, 'cvss_base') || '0'),
        cve_ids: extractCVEIds(resultXML)
      };

      // Only include actual vulnerabilities (not just informational)
      if (vulnerability.severity > 0) {
        vulnerabilities.push(vulnerability);
      }

    } catch (parseError) {
      log(`Failed to parse vulnerability result: ${parseError}`);
    }
  }

  log(`Parsed ${vulnerabilities.length} vulnerabilities from OpenVAS report`);
  return vulnerabilities;
}

/**
 * Process scan results and create artifacts/findings
 */
async function processScanResults(
  scanResult: OpenVASScanResult, 
  scanId: string, 
  domain: string
): Promise<number> {
  let findingsCount = 0;

  // Group vulnerabilities by severity for better organization
  const severityGroups = {
    critical: scanResult.vulnerabilities.filter(v => v.severity >= 9.0),
    high: scanResult.vulnerabilities.filter(v => v.severity >= 7.0 && v.severity < 9.0),
    medium: scanResult.vulnerabilities.filter(v => v.severity >= 4.0 && v.severity < 7.0),
    low: scanResult.vulnerabilities.filter(v => v.severity > 0 && v.severity < 4.0)
  };

  // Process each severity group
  for (const [severityLevel, vulnerabilities] of Object.entries(severityGroups)) {
    if (vulnerabilities.length === 0) continue;

    // Create artifacts for each unique vulnerability
    for (const vuln of vulnerabilities) {
      const artifactId = await insertArtifact({
        type: 'openvas_vulnerability',
        val_text: `${vuln.name} (CVSS: ${vuln.cvss_base})`,
        severity: mapSeverityToLevel(vuln.severity),
        src_url: `${vuln.host}:${vuln.port}`,
        meta: {
          scan_id: scanId,
          scan_module: 'openvasScan',
          vulnerability_id: vuln.id,
          cvss_score: vuln.cvss_base,
          threat_level: vuln.threat,
          vulnerability_family: vuln.family,
          cve_ids: vuln.cve_ids,
          openvas_data: vuln
        }
      });

      // Create corresponding finding
      await insertFinding(
        artifactId,
        'OPENVAS_VULNERABILITY',
        vuln.description.slice(0, 250) + (vuln.description.length > 250 ? '...' : ''),
        `Host: ${vuln.host}:${vuln.port} | CVSS: ${vuln.cvss_base} | Solution: ${vuln.solution.slice(0, 200)}`
      );

      findingsCount++;
    }
  }

  return findingsCount;
}

/**
 * Helper functions for XML parsing
 */
function extractIdFromResponse(xmlResponse: string): string | null {
  const match = xmlResponse.match(/id="([^"]+)"/);
  return match ? match[1] : null;
}

function extractReportIdFromTask(taskXML: string): string | null {
  const match = taskXML.match(/<last_report.*?id="([^"]+)"/);
  return match ? match[1] : null;
}

function extractProgressFromTask(taskXML: string): string {
  const match = taskXML.match(/<progress>(\d+)<\/progress>/);
  return match ? match[1] : '0';
}

function extractXMLValue(xml: string, tag: string, attribute?: string): string | null {
  if (attribute) {
    const regex = new RegExp(`<${tag}[^>]*${attribute}="([^"]*)"`, 'i');
    const match = xml.match(regex);
    return match ? match[1] : null;
  } else {
    const regex = new RegExp(`<${tag}[^>]*>(.*?)<\/${tag}>`, 'is');
    const match = xml.match(regex);
    return match ? match[1].trim() : null;
  }
}

function extractCVEIds(xml: string): string[] {
  const cveRegex = /CVE-\d{4}-\d+/g;
  const matches = xml.match(cveRegex);
  return matches ? [...new Set(matches)] : [];
}

function mapSeverityToLevel(severity: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  if (severity >= 9.0) return 'CRITICAL';
  if (severity >= 7.0) return 'HIGH';
  if (severity >= 4.0) return 'MEDIUM';
  if (severity > 0) return 'LOW';
  return 'INFO';
}