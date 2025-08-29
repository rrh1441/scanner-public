/**
 * Enhanced Nuclei v3.4.5 TypeScript Wrapper with Official ProjectDiscovery Two-Pass Scanning
 * 
 * Provides a clean interface for all modules to use the unified nuclei script.
 * Implements official ProjectDiscovery two-pass scanning approach:
 * 1. Baseline scan: misconfiguration,default-logins,exposed-panels,exposure,tech
 * 2. Common vulnerabilities + tech-specific: cve,panel,xss,wordpress,wp-plugin,osint,lfi,rce + detected tech tags
 * 
 * Uses NUCLEI_PREFERRED_CHROME_PATH environment variable for Chrome integration.
 * Reference: https://docs.projectdiscovery.io/templates/introduction
 */

import { spawn } from 'node:child_process';
import * as fs from 'node:fs/promises';
import { logLegacy as rootLog } from '../core/logger.js';
import { insertArtifact } from '../core/artifactStore.js';

// Base flags applied to every Nuclei execution for consistency
export const NUCLEI_BASE_FLAGS = [
  '-silent',
  '-jsonl'
];

// ═══════════════════════════════════════════════════════════════════════════════
// Two-Pass Scanning Configuration
// ═══════════════════════════════════════════════════════════════════════════════

// Baseline tags run on EVERY target for general security assessment (Official ProjectDiscovery)
export const BASELINE_TAGS = [
  'misconfiguration',
  'default-logins', 
  'exposed-panels',
  'exposure',
  'tech'
];

// Common vulnerability tags for second pass (Official ProjectDiscovery)
export const COMMON_VULN_TAGS = [
  'cve',
  'panel',
  'xss',
  'wordpress',
  'wp-plugin',
  'osint',
  'lfi',
  'rce'
];

// Technology-specific tag mapping (Official ProjectDiscovery Documentation)
export const TECH_TAG_MAPPING: Record<string, string[]> = {
  // Web Servers
  'apache': ['apache'],
  'nginx': ['nginx'],
  'httpd': ['apache'], // Apache httpd
  
  // Programming Languages
  'php': ['php'],
  
  // Content Management Systems  
  'wordpress': ['wordpress', 'wp-plugin', 'wp-theme'],
  'drupal': ['drupal'],
  'joomla': ['joomla'],
  'magento': ['magento'],
  
  // Application Servers
  'tomcat': ['tomcat', 'jboss'],
  'jboss': ['tomcat', 'jboss'],
  'weblogic': ['tomcat', 'jboss'], // Map to available tags
  
  // JavaScript Frameworks
  'nodejs': ['nodejs', 'express'],
  'node.js': ['nodejs', 'express'],
  'express': ['nodejs', 'express'],
  
  // Databases
  'mysql': ['mysql'],
  'mariadb': ['mysql'],
  'postgresql': ['postgresql'],
  'postgres': ['postgresql'],
  
  // Search & Analytics
  'elasticsearch': ['elastic', 'kibana'],
  'elastic': ['elastic', 'kibana'],
  'kibana': ['elastic', 'kibana']
};

interface NucleiOptions {
  // Target specification
  url?: string;
  targetList?: string;
  
  // Template specification  
  templates?: string[];
  tags?: string[];
  
  // Output options
  output?: string;
  jsonl?: boolean;
  silent?: boolean;
  verbose?: boolean;
  
  // Execution options
  concurrency?: number;
  timeout?: number;
  retries?: number;
  
  // Browser options
  headless?: boolean;
  
  // Security options
  followRedirects?: boolean;
  maxRedirects?: number;
  
  // Performance options
  rateLimit?: number;
  bulkSize?: number;
  disableClustering?: boolean;
  
  // Debug options
  stats?: boolean;
  debug?: boolean;
  version?: boolean;
  
  // Environment
  httpProxy?: string;
  
  // Persistence options
  scanId?: string;
}

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

interface NucleiExecutionResult {
  results: NucleiResult[];
  stdout: string;
  stderr: string;
  exitCode: number;
  success: boolean;
  persistedCount?: number; // Number of findings persisted as artifacts
}

interface TwoPassScanResult {
  baselineResults: NucleiResult[];
  techSpecificResults: NucleiResult[];
  detectedTechnologies: string[];
  totalFindings: number;
  scanDurationMs: number;
  totalPersistedCount?: number; // Total artifacts persisted across both passes
}

/**
 * Enhanced logging function
 */
const log = (...args: unknown[]) => rootLog('[nucleiWrapper]', ...args);

/**
 * Check if URL is non-HTML asset that should be skipped for web vulnerability scanning
 */
export function isNonHtmlAsset(url: string): boolean {
  try {
    const urlObj = new URL(url);
    const pathname = urlObj.pathname.toLowerCase();
    const hostname = urlObj.hostname.toLowerCase();
    
    // File extension patterns that never return HTML
    const nonHtmlExtensions = /\.(js|css|png|jpg|jpeg|gif|svg|ico|pdf|zip|exe|dmg|mp4|mp3|woff|woff2|ttf|eot)$/i;
    if (nonHtmlExtensions.test(pathname)) return true;
    
    // API endpoints that return JSON/XML, not HTML
    const apiPatterns = [
      /\/api[\/\?]/,
      /\/v\d+[\/\?]/,
      /\.json[\/\?]?$/,
      /\.xml[\/\?]?$/,
      /\/rest[\/\?]/,
      /\/graphql[\/\?]/,
      /player_api/,
      /analytics/,
      /tracking/
    ];
    if (apiPatterns.some(pattern => pattern.test(pathname))) return true;
    
    // CDN and static asset domains
    const cdnPatterns = [
      'cdn.',
      'static.',
      'assets.',
      'media.',
      'img.',
      'js.',
      'css.',
      'fonts.',
      'maxcdn.bootstrapcdn.com',
      'cdnjs.cloudflare.com',
      'unpkg.com',
      'jsdelivr.net'
    ];
    if (cdnPatterns.some(pattern => hostname.includes(pattern))) return true;
    
    return false;
  } catch {
    return false; // Invalid URL, let it through for safety
  }
}

/**
 * Filter URLs to only include those suitable for web vulnerability scanning
 */
export function filterWebVulnUrls(urls: string[]): { webUrls: string[]; skippedCount: number } {
  const webUrls = urls.filter(url => !isNonHtmlAsset(url));
  return {
    webUrls,
    skippedCount: urls.length - webUrls.length
  };
}

/**
 * Gate Nuclei templates based on detected technologies
 */
export function gateTemplatesByTech(detectedTechnologies: string[], allTemplates: string[]): string[] {
  if (detectedTechnologies.length === 0) {
    // No tech detected, run basic templates only
    return allTemplates.filter(template => 
      !template.includes('wordpress') &&
      !template.includes('drupal') &&
      !template.includes('joomla') &&
      !template.includes('magento')
    );
  }
  
  // Run all templates if we detected relevant technologies
  const hasWordPress = detectedTechnologies.some(tech => 
    tech.toLowerCase().includes('wordpress') || tech.toLowerCase().includes('wp'));
  const hasDrupal = detectedTechnologies.some(tech => 
    tech.toLowerCase().includes('drupal'));
  
  let gatedTemplates = [...allTemplates];
  
  // Remove WordPress templates if no WordPress detected
  if (!hasWordPress) {
    gatedTemplates = gatedTemplates.filter(template => 
      !template.includes('wordpress') && !template.includes('wp-plugin'));
  }
  
  // Remove Drupal templates if no Drupal detected
  if (!hasDrupal) {
    gatedTemplates = gatedTemplates.filter(template => 
      !template.includes('drupal'));
  }
  
  return gatedTemplates;
}

/**
 * Create artifacts for Nuclei results like other modules
 */
async function createNucleiArtifacts(results: NucleiResult[], scanId: string): Promise<number> {
  let count = 0;
  
  for (const result of results) {
    try {
      // Map Nuclei severity to our severity levels
      const severity = mapNucleiSeverityToArtifactSeverity(result.info?.severity || 'info');
      
      await insertArtifact({
        type: 'nuclei_vulnerability',
        val_text: `${result.info?.name || result['template-id']} - ${result['matched-at'] || result.host}`,
        severity: severity,
        src_url: result['matched-at'] || result.host,
        meta: {
          scan_id: scanId,
          scan_module: 'nuclei',
          template_id: result['template-id'],
          template_path: result['template-path'],
          nuclei_data: result
        }
      });
      
      count++;
    } catch (error) {
      log(`Failed to create artifact for Nuclei result: ${result['template-id']}`);
    }
  }
  
  return count;
}

/**
 * Map Nuclei severity levels to our artifact severity levels
 */
function mapNucleiSeverityToArtifactSeverity(nucleiSeverity: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  switch (nucleiSeverity.toLowerCase()) {
    case 'critical': return 'CRITICAL';
    case 'high': return 'HIGH'; 
    case 'medium': return 'MEDIUM';
    case 'low': return 'LOW';
    case 'info':
    default: return 'INFO';
  }
}

/**
 * Execute Nuclei using the unified wrapper script
 */
export async function runNuclei(options: NucleiOptions): Promise<NucleiExecutionResult> {
  // Build arguments using base flags
  const args: string[] = [...NUCLEI_BASE_FLAGS];
  
  // Version check - simple validation that doesn't require target
  if (options.version) {
    args.length = 0; // Clear base flags for version check
    args.push('-version');
  }
  
  if (options.url) {
    args.push('-u', options.url);
  }
  
  if (options.targetList) {
    args.push('-list', options.targetList);
  }
  
  if (options.templates && options.templates.length > 0) {
    for (const template of options.templates) {
      args.push('-t', template);
    }
  }
  
  if (options.tags && options.tags.length > 0) {
    args.push('-tags', options.tags.join(','));
  }
  
  if (options.output) {
    args.push('-o', options.output);
  }
  
  if (options.verbose) {
    args.push('-v');
  }
  
  if (options.concurrency) {
    args.push('-c', options.concurrency.toString());
  }
  
  if (options.timeout) {
    args.push('-timeout', options.timeout.toString());
  }
  
  if (options.retries) {
    args.push('-retries', options.retries.toString());
  }
  
  // Conditionally add headless flags only when needed
  if (options.headless) {
    args.push('-headless');
    // Always use system-chrome when headless for reliability in Docker
    args.push('-system-chrome');
  }
  
  let artifactsCreated = 0;
  
  // Template updates handled by Cloud Run scheduled job
  
  log(`Executing nuclei: /usr/local/bin/nuclei ${args.join(' ')}`);
  
  let stdout = '';
  let stderr = '';
  let exitCode = 0;
  let success = false;
  
  // Use spawn to capture JSON-L output with streaming parsing
  await new Promise<void>((resolve, reject) => {
    const nucleiProcess = spawn('/usr/local/bin/nuclei', args, {
      stdio: 'pipe', // Always capture output to parse JSON-L results
      detached: true, // Start in new process group for proper cleanup
      env: { 
        ...process.env, 
        NO_COLOR: '1',
        // This is crucial for running headless Chrome in Docker
        NUCLEI_DISABLE_SANDBOX: 'true',
        // Force IPv4 for Go binaries to prevent IPv6 DNS hangs
        GODEBUG: 'netdns=go+v4'
      }
    });
    
    let stdoutBuffer = '';
    
    // Stream JSON-L parsing to capture results even on timeout
    if (nucleiProcess.stdout) {
      nucleiProcess.stdout.on('data', (data) => {
        const chunk = data.toString();
        stdout += chunk;
        stdoutBuffer += chunk;
        
        // Parse complete JSON lines as they arrive
        const lines = stdoutBuffer.split('\n');
        stdoutBuffer = lines.pop() || ''; // Keep incomplete line in buffer
        
        for (const line of lines) {
          if (line.trim() && line.startsWith('{')) {
            try {
              const result = JSON.parse(line) as NucleiResult;
              results.push(result);
              log(`Streaming result: ${result['template-id']} on ${result.host}`);
            } catch (parseError) {
              // Skip malformed JSON lines
            }
          }
        }
      });
    }
    
    if (nucleiProcess.stderr) {
      nucleiProcess.stderr.on('data', (data) => {
        stderr += data.toString();
      });
    }
    
    nucleiProcess.on('exit', (code) => {
      exitCode = code || 0;
      clearTimeout(timeoutHandle); // Clear timeout when process exits normally
      
      // Exit code 1 is normal for "findings found", not an error
      // Exit codes > 1 are actual errors
      if (exitCode <= 1) {
        success = true;
        resolve();
      } else {
        success = false;
        reject(new Error(`Nuclei exited with code ${exitCode}`));
      }
    });
    
    nucleiProcess.on('error', (error) => {
      clearTimeout(timeoutHandle); // Clear timeout on error
      reject(error);
    });
    
    // Set timeout with smart tiered system based on scan type
    const defaultTimeoutSeconds = 180; // 3 minutes fallback
    let timeoutMs: number;
    
    if (options.headless) {
      // Deep-dive scans with headless Chrome need more time
      timeoutMs = Number(process.env.NUCLEI_HEADLESS_TIMEOUT_MS) || 90000; // 90s default for headless
      log(`Using headless timeout: ${timeoutMs}ms`);
    } else {
      // Baseline scans can be faster
      timeoutMs = Number(process.env.NUCLEI_BASELINE_TIMEOUT_MS) || 45000; // 45s default for baseline
      log(`Using baseline timeout: ${timeoutMs}ms`);
    }
    
    // Allow manual override via options
    if (options.timeout) {
      timeoutMs = options.timeout * 1000;
      log(`Manual timeout override: ${timeoutMs}ms`);
    }
    
    const gracePeriodMs = 3000; // 3 seconds grace period after SIGTERM
    
    const timeoutHandle = setTimeout(() => {
      log(`Nuclei execution timed out after ${timeoutMs}ms, sending SIGTERM`);
      nucleiProcess.kill('SIGTERM');
      
      // Grace period for cleanup, then SIGKILL
      const killHandle = setTimeout(() => {
        if (!nucleiProcess.killed && nucleiProcess.pid) {
          log(`Nuclei did not exit gracefully, sending SIGKILL`);
          try {
            // Kill the process group to ensure child processes are cleaned up
            process.kill(-nucleiProcess.pid, 'SIGKILL');
          } catch (error) {
            log(`Failed to kill process group: ${error}`);
            // Fallback to killing just the main process
            nucleiProcess.kill('SIGKILL');
          }
        }
        reject(new Error(`Nuclei execution timed out after ${timeoutMs}ms`));
      }, gracePeriodMs);
      
      // Clean up kill handle if process exits normally
      nucleiProcess.once('exit', () => {
        clearTimeout(killHandle);
      });
    }, timeoutMs);
  });
  
  // Log stderr if present (may contain warnings)
  if (stderr) {
    log(`Nuclei stderr: ${stderr}`);
  }
  
  // Parse JSONL results from stdout
  const results: NucleiResult[] = [];
  
  if (stdout.trim()) {
    const lines = stdout.trim().split('\n').filter(line => line.trim());
    
    for (const line of lines) {
      // Skip non-JSON lines (banners, warnings, etc.)
      if (!line.startsWith('{')) continue;
      
      try {
        const result = JSON.parse(line) as NucleiResult;
        results.push(result);
      } catch (parseError) {
        log(`Failed to parse Nuclei result line: ${line.slice(0, 200)}`);
      }
    }
  }
  
  // Create artifacts if scanId is provided
  if (options.scanId && results.length > 0) {
    artifactsCreated = await createNucleiArtifacts(results, options.scanId);
    // Nuclei execution completed - verbose logging removed
  }
  
  return {
    results,
    stdout,
    stderr,
    exitCode,
    success,
    persistedCount: artifactsCreated // Track created artifacts
  };
}

/**
 * Convenience function for simple URL scanning with tags
 */
export async function scanUrl(
  url: string, 
  tags: string[], 
  options: Partial<NucleiOptions> = {}
): Promise<NucleiExecutionResult> {
  return runNuclei({
    url,
    tags,
    retries: 2,
    concurrency: Number(process.env.NUCLEI_CONCURRENCY) || 32,
    ...options
  });
}

/**
 * Convenience function for scanning a list of targets
 */
export async function scanTargetList(
  targetFile: string,
  templates: string[],
  options: Partial<NucleiOptions> = {}
): Promise<NucleiExecutionResult> {
  return runNuclei({
    targetList: targetFile,
    templates,
    retries: 2,
    concurrency: Number(process.env.NUCLEI_CONCURRENCY) || 32,
    ...options
  });
}

/**
 * Create a temporary targets file from array of URLs
 */
export async function createTargetsFile(targets: string[], prefix = 'nuclei-targets'): Promise<string> {
  const filename = `/tmp/${prefix}-${Date.now()}.txt`;
  await fs.writeFile(filename, targets.join('\n'));
  return filename;
}

/**
 * Cleanup temporary files
 */
export async function cleanupFile(filepath: string): Promise<void> {
  try {
    await fs.unlink(filepath);
  } catch (error) {
    // Ignore cleanup errors
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Two-Pass Scanning Implementation
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Extract technology names from baseline scan results
 */
export function extractTechnologies(baselineResults: NucleiResult[]): string[] {
  const technologies = new Set<string>();
  
  for (const result of baselineResults) {
    const tags = result.info?.tags || [];
    const templateId = result['template-id'] || '';
    const name = result.info?.name?.toLowerCase() || '';
    
    // Extract from tags
    for (const tag of tags) {
      const lowerTag = tag.toLowerCase();
      if (TECH_TAG_MAPPING[lowerTag]) {
        technologies.add(lowerTag);
      }
    }
    
    // Extract from template ID and name
    const textToCheck = `${templateId} ${name}`.toLowerCase();
    for (const tech of Object.keys(TECH_TAG_MAPPING)) {
      if (textToCheck.includes(tech)) {
        technologies.add(tech);
      }
    }
    
    // Extract from extracted results (version info, etc.)
    const extractedResults = result['extracted-results'] || [];
    for (const extracted of extractedResults) {
      if (typeof extracted === 'string') {
        const lowerExtracted = extracted.toLowerCase();
        for (const tech of Object.keys(TECH_TAG_MAPPING)) {
          if (lowerExtracted.includes(tech)) {
            technologies.add(tech);
          }
        }
      }
    }
  }
  
  return Array.from(technologies);
}

/**
 * Build technology-specific tags based on detected technologies
 * Uses official ProjectDiscovery two-pass approach:
 * 1. Baseline (already run)
 * 2. Common vulnerabilities + technology-specific (combined)
 */
export function buildTechSpecificTags(detectedTechnologies: string[]): string[] {
  const techTags = new Set<string>();
  
  // Add common vulnerability tags (run once per host after baseline)
  COMMON_VULN_TAGS.forEach(tag => techTags.add(tag));
  
  // Add technology-specific tags only for detected technologies
  for (const tech of detectedTechnologies) {
    const tags = TECH_TAG_MAPPING[tech.toLowerCase()];
    if (tags) {
      tags.forEach(tag => techTags.add(tag));
    }
  }
  
  return Array.from(techTags);
}

/**
 * Perform two-pass nuclei scan: baseline + technology-specific
 */
export async function runTwoPassScan(
  target: string,
  options: Partial<NucleiOptions> = {}
): Promise<TwoPassScanResult> {
  const startTime = Date.now();
  log(`Starting two-pass scan for ${target}`);
  
  // ─────────────── PASS 1: Baseline Scan ───────────────
  log(`Pass 1: Running baseline scan with tags: ${BASELINE_TAGS.join(',')}`);
  
  const baselineScan = await runNuclei({
    url: target,
    tags: BASELINE_TAGS,
    retries: 2,
    concurrency: Number(process.env.NUCLEI_CONCURRENCY) || 32,
    headless: false, // Baseline scan faster without headless - tech detection works fine
    ...options
  });
  
  // Check if baseline scan timed out cleanly (indicates page loading issues)
  const baselineTimedOut = !baselineScan.success && baselineScan.stderr?.includes('timeout');
  
  if (!baselineScan.success) {
    log(`Baseline scan failed for ${target}: exit code ${baselineScan.exitCode}`);
    return {
      baselineResults: [],
      techSpecificResults: [],
      detectedTechnologies: [],
      totalFindings: 0,
      scanDurationMs: Date.now() - startTime
    };
  }
  
  // ─────────────── Technology Detection ───────────────
  const detectedTechnologies = extractTechnologies(baselineScan.results);
  log(`Detected technologies: ${detectedTechnologies.join(', ') || 'none'}`);
  
  // Always run second pass with common vulnerability tags, even if no specific tech detected
  const techTags = detectedTechnologies.length > 0 
    ? buildTechSpecificTags(detectedTechnologies)
    : COMMON_VULN_TAGS; // Just common vulns if no tech detected
  
  // Gate templates based on detected technologies
  const gatedTags = gateTemplatesByTech(detectedTechnologies, techTags);
  
  // ─────────────── PASS 2: Common Vulnerabilities + Tech-Specific Scan ───────────────
  
  // Skip headless pass if baseline timed out (page doesn't load properly)
  const shouldSkipHeadless = baselineTimedOut && isNonHtmlAsset(target);
  
  if (shouldSkipHeadless) {
    log(`Pass 2: Skipping headless scan for ${target} - baseline timeout on non-HTML asset`);
    const totalFindings = baselineScan.results.length;
    const totalPersistedCount = baselineScan.persistedCount || 0;
    
    // Two-pass scan completed (headless skipped) - verbose logging removed
    
    return {
      baselineResults: baselineScan.results,
      techSpecificResults: [],
      detectedTechnologies,
      totalFindings,
      scanDurationMs: Date.now() - startTime,
      totalPersistedCount
    };
  }
  
  log(`Pass 2: Running common vulnerability + tech-specific scan with gated tags: ${gatedTags.join(',')}`);
  
  const techScan = await runNuclei({
    url: target,
    tags: gatedTags,
    retries: 2,
    concurrency: Number(process.env.NUCLEI_CONCURRENCY) || 32,
    headless: true, // Enable headless for CVE/tech-specific scans that need browser interaction
    ...options
  });
  
  if (!techScan.success) {
    log(`Common vulnerability + tech-specific scan failed for ${target}: exit code ${techScan.exitCode}`);
  }
  
  const totalFindings = baselineScan.results.length + (techScan.success ? techScan.results.length : 0);
  const totalPersistedCount = (baselineScan.persistedCount || 0) + (techScan.persistedCount || 0);
  
  if (options.scanId) {
    log(`Two-pass scan completed: ${totalPersistedCount} findings persisted as artifacts (baseline: ${baselineScan.persistedCount || 0}, common+tech: ${techScan.persistedCount || 0})`);
  } else {
    log(`Two-pass scan completed: ${totalFindings} total findings (baseline: ${baselineScan.results.length}, common+tech: ${techScan.success ? techScan.results.length : 0})`);
  }
  
  return {
    baselineResults: baselineScan.results,
    techSpecificResults: techScan.success ? techScan.results : [],
    detectedTechnologies,
    totalFindings,
    scanDurationMs: Date.now() - startTime,
    totalPersistedCount
  };
}

/**
 * Perform two-pass scan on multiple targets
 */
export async function runTwoPassScanMultiple(
  targets: string[],
  options: Partial<NucleiOptions> = {}
): Promise<TwoPassScanResult> {
  const startTime = Date.now();
  log(`Starting two-pass scan for ${targets.length} targets`);
  
  const allBaselineResults: NucleiResult[] = [];
  const allTechResults: NucleiResult[] = [];
  const allDetectedTechs = new Set<string>();
  
  for (const target of targets) {
    try {
      const result = await runTwoPassScan(target, options);
      allBaselineResults.push(...result.baselineResults);
      allTechResults.push(...result.techSpecificResults);
      result.detectedTechnologies.forEach(tech => allDetectedTechs.add(tech));
    } catch (error) {
      log(`Failed to scan ${target}: ${(error as Error).message}`);
    }
  }
  
  return {
    baselineResults: allBaselineResults,
    techSpecificResults: allTechResults,
    detectedTechnologies: Array.from(allDetectedTechs),
    totalFindings: allBaselineResults.length + allTechResults.length,
    scanDurationMs: Date.now() - startTime
  };
}

/**
 * Enhanced scan function that automatically uses two-pass approach
 */
export async function scanUrlEnhanced(
  url: string,
  options: Partial<NucleiOptions> = {}
): Promise<TwoPassScanResult> {
  return runTwoPassScan(url, options);
}

/**
 * Enhanced scan function for target lists with two-pass approach
 */
export async function scanTargetListEnhanced(
  targetFile: string,
  options: Partial<NucleiOptions> = {}
): Promise<TwoPassScanResult> {
  // Read targets from file
  const targetsContent = await fs.readFile(targetFile, 'utf-8');
  const targets = targetsContent.split('\n').filter(line => line.trim());
  
  return runTwoPassScanMultiple(targets, options);
}