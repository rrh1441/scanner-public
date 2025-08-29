This file is a merged representation of the entire codebase, combined into a single document by Repomix.

<file_summary>
This section contains a summary of this file.

<purpose>
This file contains a packed representation of the entire repository's contents.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.
</purpose>

<file_format>
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  - File path as an attribute
  - Full contents of the file
</file_format>

<usage_guidelines>
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.
</usage_guidelines>

<notes>
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)
</notes>

</file_summary>

<directory_structure>
abuseIntelScan.ts
accessibilityScan.ts
adversarialMediaScan.ts
aiPathFinder.ts
assetCorrelator.ts
breachDirectoryProbe.ts
censysPlatformScan.ts
clientSecretScanner.ts
cveVerifier.ts
dbPortScan.ts
denialWalletScan.ts
dnsTwist.ts
documentExposure.ts
emailBruteforceSurface.ts
endpointDiscovery.ts
nuclei.ts
openvasScan.ts
rateLimitScan.ts
rdpVpnTemplates.ts
scanGitRepos.ts
shodan.ts
spfDmarc.ts
spiderFoot.ts
targetDiscovery.ts
techStackScan.ts
tierConfig.ts
tlsScan.ts
trufflehog.ts
webArchiveScanner.ts
whoisWrapper.ts
zapScan.ts
</directory_structure>

<files>
This section contains the contents of the repository's files.

<file path="abuseIntelScan.ts">
/**
 * AbuseIntel-GPT Module
 * 
 * Autonomous scanner module for DealBrief's artifact pipeline that checks IP addresses
 * against AbuseIPDB v2 API for reputation and abuse intelligence.
 */

import axios from 'axios';
import { insertArtifact, insertFinding, pool } from '../core/artifactStore.js';
import { log as rootLog } from '../core/logger.js';
import { executeModule, apiCall, errorHandler } from '../util/errorHandler.js';

// Configuration constants
const ABUSEIPDB_ENDPOINT = 'https://api.abuseipdb.com/api/v2/check';
const RATE_LIMIT_DELAY_MS = 2000; // 30 requests/minute = 2 second intervals
const JITTER_MS = 200; // ±200ms jitter
const REQUEST_TIMEOUT_MS = 10000;


// Risk assessment thresholds
const SUSPICIOUS_THRESHOLD = 25;
const MALICIOUS_THRESHOLD = 70;

// Enhanced logging
const log = (...args: unknown[]) => rootLog('[abuseIntelScan]', ...args);

interface AbuseIPDBResponse {
  ipAddress: string;
  isPublic: boolean;
  ipVersion: number;
  isWhitelisted: boolean;
  abuseConfidenceScore: number;
  countryCode: string;
  usageType: string;
  isp: string;
  domain: string;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt: string | null;
}

interface RiskAssessment {
  confidence: number;
  findingType: 'SUSPICIOUS_IP' | 'MALICIOUS_IP';
  severity: 'MEDIUM' | 'HIGH';
  description: string;
  evidence: AbuseIPDBResponse;
  recommendation: string;
}

interface IPArtifact {
  id: number;
  val_text: string; // The IP address
  meta: Record<string, any>;
}

interface ScanMetrics {
  totalIPs: number;
  suspicious: number;
  malicious: number;
  errors: number;
  scanTimeMs: number;
}

/**
 * Jittered delay to respect rate limits and avoid thundering herd
 */
async function jitteredDelay(): Promise<void> {
  const delay = RATE_LIMIT_DELAY_MS + (Math.random() * JITTER_MS * 2 - JITTER_MS);
  await new Promise(resolve => setTimeout(resolve, delay));
}

/**
 * Query artifact store for all IP artifacts from the current scan
 */
async function getIPArtifacts(scanId: string): Promise<IPArtifact[]> {
  try {
    const { rows } = await pool.query(
      `SELECT id, val_text, meta 
       FROM artifacts 
       WHERE type = 'ip' AND meta->>'scan_id' = $1`,
      [scanId]
    );
    
    log(`Found ${rows.length} IP artifacts for scan ${scanId}`);
    return rows;
  } catch (error) {
    log(`Error querying IP artifacts: ${(error as Error).message}`);
    return [];
  }
}

/**
 * Check if IP address is valid (IPv4 or IPv6)
 */
function isValidIP(ip: string): boolean {
  // Basic IPv4 regex
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  // Basic IPv6 regex (simplified)
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
  
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

/**
 * Check single IP against AbuseIPDB with retries and error handling
 */
async function checkAbuseIPDB(ip: string): Promise<RiskAssessment | null> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    throw new Error('ABUSEIPDB_API_KEY environment variable not set');
  }

  if (!isValidIP(ip)) {
    log(`Skipping invalid IP: ${ip}`);
    return null;
  }

  // Use standardized API call with retry logic
  const result = await apiCall(async () => {
    log(`Checking IP ${ip} with AbuseIPDB`);
    
    const response = await axios.get(ABUSEIPDB_ENDPOINT, {
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
        verbose: ''
      },
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      },
      timeout: REQUEST_TIMEOUT_MS
    });

    return response.data.data as AbuseIPDBResponse;
  }, {
    moduleName: 'abuseIntelScan',
    operation: 'checkAbuseIPDB',
    target: ip
  });
  
  if (!result.success) {
    log(`Failed to check IP ${ip}: ${result.error}`);
    return null;
  }
  
  const data = result.data;
      
      // Only generate findings for IPs with material risk
      if (data.abuseConfidenceScore < SUSPICIOUS_THRESHOLD) {
        log(`IP ${ip} is clean (confidence: ${data.abuseConfidenceScore}%)`);
        return null;
      }

      // Determine risk level and finding type
      const isMalicious = data.abuseConfidenceScore >= MALICIOUS_THRESHOLD;
      const findingType = isMalicious ? 'MALICIOUS_IP' : 'SUSPICIOUS_IP';
      const severity = isMalicious ? 'HIGH' : 'MEDIUM';
      
      // Generate actionable description
      const description = `${ip} has ${data.abuseConfidenceScore}% abuse confidence (${data.totalReports} reports from ${data.numDistinctUsers} users)`;
      
      // Generate specific recommendation
      let recommendation = '';
      if (isMalicious) {
        recommendation = `Block ${ip} immediately. Consider firewall rules and monitoring for related activity.`;
      } else {
        recommendation = `Monitor ${ip} for suspicious activity. Consider rate limiting or enhanced logging.`;
      }

  log(`IP ${ip} flagged as ${findingType} (confidence: ${data.abuseConfidenceScore}%)`);
  
  return {
    confidence: data.abuseConfidenceScore,
    findingType,
    severity,
    description,
    evidence: data,
    recommendation
  };
}

/**
 * Deduplicate IPs within the same scan
 */
function deduplicateIPs(artifacts: IPArtifact[]): IPArtifact[] {
  const seen = new Set<string>();
  return artifacts.filter(artifact => {
    const ip = artifact.val_text.trim();
    if (seen.has(ip)) {
      log(`Skipping duplicate IP: ${ip}`);
      return false;
    }
    seen.add(ip);
    return true;
  });
}

/**
 * Main scan function - processes all IP artifacts for the given scan
 */
export async function runAbuseIntelScan(job: { scanId: string }): Promise<number> {
  const { scanId } = job;
  
  return executeModule('abuseIntelScan', async () => {
    log(`Starting AbuseIPDB scan for scanId=${scanId}`);
    
    // Check for API key first
    if (!process.env.ABUSEIPDB_API_KEY) {
      log('ABUSEIPDB_API_KEY not configured, emitting warning and exiting gracefully');
      
      await insertArtifact({
        type: 'scan_warning',
        val_text: 'AbuseIPDB scan skipped - API key not configured',
        severity: 'LOW',
        meta: {
          scan_id: scanId,
          scan_module: 'abuseIntelScan',
          reason: 'missing_api_key'
        }
      });
      
      return 0;
    }
    // Get all IP artifacts for this scan
    const ipArtifacts = await getIPArtifacts(scanId);
    
    if (ipArtifacts.length === 0) {
      log('No IP artifacts found for this scan');
      return 0;
    }
    
    // Deduplicate IPs
    const uniqueIPs = deduplicateIPs(ipArtifacts);
    log(`Processing ${uniqueIPs.length} unique IPs (${ipArtifacts.length - uniqueIPs.length} duplicates removed)`);
    
    const metrics: ScanMetrics = {
      totalIPs: uniqueIPs.length,
      suspicious: 0,
      malicious: 0,
      errors: 0,
      scanTimeMs: 0
    };
    
    let findingsCount = 0;
    
    // Process each IP sequentially with rate limiting
    for (let i = 0; i < uniqueIPs.length; i++) {
      const artifact = uniqueIPs[i];
      const ip = artifact.val_text.trim();
      
      try {
        // Check IP against AbuseIPDB
        const risk = await checkAbuseIPDB(ip);
        
        if (risk) {
          // Create finding linked to the original artifact
          await insertFinding(
            artifact.id,
            risk.findingType,
            risk.recommendation,
            risk.description
          );
          
          // Update metrics
          if (risk.findingType === 'MALICIOUS_IP') {
            metrics.malicious++;
          } else {
            metrics.suspicious++;
          }
          
          findingsCount++;
          
          log(`Created ${risk.findingType} finding for ${ip} (confidence: ${risk.confidence}%)`);
        }
        
      } catch (error) {
        metrics.errors++;
        log(`Error processing IP ${ip}: ${(error as Error).message}`);
        
        // Continue with remaining IPs
        continue;
      }
      
      // Rate limiting - don't delay after the last IP
      if (i < uniqueIPs.length - 1) {
        await jitteredDelay();
      }
    }
    
    // Calculate final metrics (duration will be handled by executeModule wrapper)
    
    // Create summary artifact
    await insertArtifact({
      type: 'abuse_intel_summary',
      val_text: `AbuseIPDB scan completed: ${metrics.malicious} malicious, ${metrics.suspicious} suspicious IPs found`,
      severity: metrics.malicious > 0 ? 'HIGH' : metrics.suspicious > 0 ? 'MEDIUM' : 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'abuseIntelScan',
        metrics: metrics,
        api_quota_used: metrics.totalIPs - metrics.errors
      }
    });
    
    log(`AbuseIPDB scan completed: ${findingsCount} findings from ${metrics.totalIPs} IPs in ${metrics.scanTimeMs}ms`);
    log(`Summary: ${metrics.malicious} malicious, ${metrics.suspicious} suspicious, ${metrics.errors} errors`);
    
    return findingsCount;
    
  }, { scanId });
}
</file>

<file path="accessibilityScan.ts">
/**
 * Accessibility Scan Module
 * 
 * Performs real WCAG 2.1 AA compliance testing to identify accessibility violations
 * that create genuine ADA lawsuit risk for companies.
 */

import axios from 'axios';
import { createHash } from 'node:crypto';
import { insertArtifact, insertFinding, pool } from '../core/artifactStore.js';
import { log as rootLog } from '../core/logger.js';
import { withPage } from '../util/dynamicBrowser.js';

// Configuration constants
const PAGE_TIMEOUT_MS = 30_000;
const AXE_TIMEOUT_MS = 15_000;
const MAX_PAGES_TO_TEST = 15;
const BROWSER_VIEWPORT = { width: 1200, height: 800 };
const AXE_CORE_CDN = 'https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.8.2/axe.min.js';

// Enhanced logging
const log = (...args: unknown[]) => rootLog('[accessibilityScan]', ...args);

interface AccessibilityViolation {
  ruleId: string;
  impact: 'critical' | 'serious' | 'moderate' | 'minor';
  description: string;
  help: string;
  helpUrl: string;
  elements: {
    selector: string;
    html: string;
    target: string[];
  }[];
  pageUrl: string;
}

interface AccessibilityPageResult {
  url: string;
  tested: boolean;
  violations: AccessibilityViolation[];
  passes: number;
  incomplete: number;
  error?: string;
}

interface AccessibilityScanSummary {
  totalPages: number;
  pagesSuccessful: number;
  totalViolations: number;
  criticalViolations: number;
  seriousViolations: number;
  worstPage: string;
  commonIssues: string[];
}

interface PageHashData {
  url: string;
  titleHash: string;
  headingsHash: string;
  linksHash: string;
  formsHash: string;
  contentHash: string;
}

/**
 * Smart page discovery - finds testable pages across common patterns and sitemap
 */
async function discoverTestablePages(domain: string): Promise<string[]> {
  const discoveredPages = new Set<string>();
  
  // 1. Essential pages (always test)
  const essentialPages = [
    `https://${domain}`,
    `https://${domain}/`,
    `https://www.${domain}`,
    `https://www.${domain}/`
  ];
  
  // 2. Common page patterns
  const commonPaths = [
    '/contact', '/about', '/services', '/products', '/pricing',
    '/signup', '/login', '/register', '/join',
    '/search', '/help', '/support', '/faq',
    '/privacy', '/terms', '/accessibility-statement'
  ];
  
  // 3. Sitemap discovery
  try {
    const sitemaps = [`https://${domain}/sitemap.xml`, `https://www.${domain}/sitemap.xml`];
    for (const sitemapUrl of sitemaps) {
      try {
        const { data } = await axios.get(sitemapUrl, { timeout: 10000 });
        const urlMatches = data.match(/<loc>(.*?)<\/loc>/g);
        if (urlMatches) {
          urlMatches.forEach((match: string) => {
            const url = match.replace(/<\/?loc>/g, '');
            if (isTestableUrl(url)) {
              discoveredPages.add(url);
            }
          });
        }
      } catch {
        // Continue if sitemap fails
      }
    }
  } catch {
    // Sitemap not available, continue with common paths
  }
  
  // Add essential and common paths
  const baseUrls = [`https://${domain}`, `https://www.${domain}`];
  baseUrls.forEach(base => {
    essentialPages.forEach(page => discoveredPages.add(page));
    commonPaths.forEach(path => discoveredPages.add(base + path));
  });
  
  // Limit to prevent excessive testing
  return Array.from(discoveredPages).slice(0, MAX_PAGES_TO_TEST);
}

/**
 * Check if URL is testable (filter out non-HTML resources)
 */
function isTestableUrl(url: string): boolean {
  const skipPatterns = [
    /\.(pdf|doc|docx|zip|exe|dmg)$/i,
    /\.(jpg|jpeg|png|gif|svg|ico)$/i,
    /\.(css|js|xml|json)$/i,
    /mailto:|tel:|javascript:/i
  ];
  
  return !skipPatterns.some(pattern => pattern.test(url));
}

/**
 * Compute page hash for change detection - captures key accessibility-relevant elements
 */
async function computePageHash(url: string): Promise<PageHashData | null> {
  try {
    return await withPage(async (page) => {
      await page.goto(url, { 
        waitUntil: 'domcontentloaded', 
        timeout: PAGE_TIMEOUT_MS 
      });
      
      // Extract key accessibility-relevant content for hashing
      const hashData = await page.evaluate(() => {
        const title = document.title || '';
        
        // Get all headings text
        const headings = Array.from(document.querySelectorAll('h1, h2, h3, h4, h5, h6'))
          .map(h => h.textContent?.trim() || '')
          .join('|');
        
        // Get all link text and href attributes
        const links = Array.from(document.querySelectorAll('a[href]'))
          .map(a => `${a.textContent?.trim() || ''}:${a.getAttribute('href') || ''}`)
          .join('|');
        
        // Get form structure (labels, inputs, buttons)
        const forms = Array.from(document.querySelectorAll('form, input, label, button'))
          .map(el => {
            if (el.tagName === 'INPUT') {
              return `input[${el.getAttribute('type') || 'text'}]:${el.getAttribute('name') || ''}`;
            }
            return `${el.tagName.toLowerCase()}:${el.textContent?.trim() || ''}`;
          })
          .join('|');
        
        // Get sample of main content (first 1000 chars)
        const content = (document.body?.textContent || '').slice(0, 1000);
        
        return { title, headings, links, forms, content };
      });
      
      // Create hashes of each component
      return {
        url,
        titleHash: createHash('md5').update(hashData.title).digest('hex'),
        headingsHash: createHash('md5').update(hashData.headings).digest('hex'),
        linksHash: createHash('md5').update(hashData.links).digest('hex'),
        formsHash: createHash('md5').update(hashData.forms).digest('hex'),
        contentHash: createHash('md5').update(hashData.content).digest('hex')
      };
    });
  } catch (error) {
    log(`Failed to compute hash for ${url}: ${(error as Error).message}`);
    return null;
  }
}

/**
 * Check if site has changed since last accessibility scan
 */
async function hasAccessibilityChanged(domain: string, currentHashes: PageHashData[]): Promise<boolean> {
  try {
    // Get the most recent accessibility scan hash
    const { rows } = await pool.query(`
      SELECT meta->'page_hashes' as page_hashes
      FROM artifacts 
      WHERE type IN ('accessibility_scan_summary', 'accessibility_scan_skipped')
        AND meta->>'domain' = $1
        AND meta->>'scan_module' = 'accessibilityScan'
      ORDER BY created_at DESC 
      LIMIT 1
    `, [domain]);
    
    if (!rows.length || !rows[0].page_hashes) {
      log(`accessibility=change_detection domain="${domain}" status="no_previous_scan"`);
      return true; // No previous scan, so run it
    }
    
    const previousHashes: PageHashData[] = rows[0].page_hashes;
    
    // Compare current vs previous hashes
    const currentHashMap = new Map(currentHashes.map(h => [h.url, h]));
    const previousHashMap = new Map(previousHashes.map(h => [h.url, h]));
    
    // Check if any pages changed
    for (const [url, currentHash] of currentHashMap) {
      const previousHash = previousHashMap.get(url);
      
      if (!previousHash) {
        log(`accessibility=change_detected domain="${domain}" url="${url}" reason="new_page"`);
        return true; // New page found
      }
      
      // Check if any component hash changed
      if (currentHash.titleHash !== previousHash.titleHash ||
          currentHash.headingsHash !== previousHash.headingsHash ||
          currentHash.linksHash !== previousHash.linksHash ||
          currentHash.formsHash !== previousHash.formsHash ||
          currentHash.contentHash !== previousHash.contentHash) {
        log(`accessibility=change_detected domain="${domain}" url="${url}" reason="content_changed"`);
        return true;
      }
    }
    
    // Check if pages were removed
    for (const url of previousHashMap.keys()) {
      if (!currentHashMap.has(url)) {
        log(`accessibility=change_detected domain="${domain}" url="${url}" reason="page_removed"`);
        return true;
      }
    }
    
    log(`accessibility=no_change_detected domain="${domain}" pages=${currentHashes.length}`);
    return false;
    
  } catch (error) {
    log(`accessibility=change_detection_error domain="${domain}" error="${(error as Error).message}"`);
    return true; // On error, run the scan to be safe
  }
}

/**
 * Test accessibility for a single page using axe-core
 */
async function testPageAccessibility(url: string): Promise<AccessibilityPageResult> {
  // Check if Puppeteer is enabled
  if (process.env.ENABLE_PUPPETEER === '0') {
    log(`Accessibility test skipped for ${url}: Puppeteer disabled`);
    return { 
      url, 
      tested: false, 
      violations: [], 
      passes: 0, 
      incomplete: 0, 
      error: 'Puppeteer disabled' 
    };
  }

  try {
    return await withPage(async (page) => {
      log(`Testing accessibility for: ${url}`);
      
      // Navigate to page
      const response = await page.goto(url, { 
        waitUntil: 'networkidle2', 
        timeout: PAGE_TIMEOUT_MS 
      });
      
      if (!response || response.status() >= 400) {
        return { 
          url, 
          tested: false, 
          violations: [], 
          passes: 0, 
          incomplete: 0, 
          error: `HTTP ${response?.status()}` 
        };
      }
      
      // Wait for page to stabilize
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Inject axe-core
      await page.addScriptTag({ url: AXE_CORE_CDN });
      
      // Run accessibility scan
      const results = await page.evaluate(async () => {
        // Configure axe for WCAG 2.1 AA
        const config = {
          runOnly: {
            type: 'tag',
            values: ['wcag2a', 'wcag2aa', 'wcag21aa']
          },
          rules: {
            'color-contrast': { enabled: true },
            'image-alt': { enabled: true },
            'button-name': { enabled: true },
            'link-name': { enabled: true },
            'form-field-multiple-labels': { enabled: true },
            'landmark-one-main': { enabled: true },
            'page-has-heading-one': { enabled: true }
          }
        };
        
        return await (window as any).axe.run(document, config);
      });
      
      // Transform results
      const violations: AccessibilityViolation[] = results.violations.map((violation: any) => ({
        ruleId: violation.id,
        impact: violation.impact || 'minor',
        description: violation.description,
        help: violation.help,
        helpUrl: violation.helpUrl,
        elements: violation.nodes.map((node: any) => ({
          selector: node.target.join(' '),
          html: node.html,
          target: node.target
        })),
        pageUrl: url
      }));
      
      log(`Accessibility test complete for ${url}: ${violations.length} violations, ${results.passes.length} passes`);
      
      return {
        url,
        tested: true,
        violations,
        passes: results.passes.length,
        incomplete: results.incomplete.length
      };
    });
    
  } catch (error) {
    log(`Accessibility test error for ${url}: ${(error as Error).message}`);
    return { 
      url, 
      tested: false, 
      violations: [], 
      passes: 0, 
      incomplete: 0, 
      error: (error as Error).message 
    };
  }
}

/**
 * Analyze scan results to generate summary
 */
function analyzeScanResults(pageResults: AccessibilityPageResult[]): AccessibilityScanSummary {
  const successful = pageResults.filter(p => p.tested);
  const allViolations = successful.flatMap(p => p.violations);
  
  const criticalViolations = allViolations.filter(v => v.impact === 'critical');
  const seriousViolations = allViolations.filter(v => v.impact === 'serious');
  
  // Find worst page
  const worstPage = successful.reduce((worst, current) => 
    current.violations.length > worst.violations.length ? current : worst
  , successful[0] || { url: 'none', violations: [] });
  
  // Find most common issues
  const issueFrequency = new Map<string, number>();
  allViolations.forEach(v => {
    issueFrequency.set(v.ruleId, (issueFrequency.get(v.ruleId) || 0) + 1);
  });
  
  const commonIssues = Array.from(issueFrequency.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([rule]) => rule);
  
  return {
    totalPages: pageResults.length,
    pagesSuccessful: successful.length,
    totalViolations: allViolations.length,
    criticalViolations: criticalViolations.length,
    seriousViolations: seriousViolations.length,
    worstPage: worstPage.url,
    commonIssues
  };
}

/**
 * Create accessibility artifact with scan summary
 */
async function createAccessibilityArtifact(
  scanId: string, 
  domain: string, 
  summary: AccessibilityScanSummary, 
  pageResults: AccessibilityPageResult[],
  pageHashes?: PageHashData[]
): Promise<number> {
  
  let severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' = 'INFO';
  if (summary.criticalViolations > 0) severity = 'HIGH';
  else if (summary.seriousViolations > 5) severity = 'HIGH';
  else if (summary.seriousViolations > 0 || summary.totalViolations > 10) severity = 'MEDIUM';
  else if (summary.totalViolations > 0) severity = 'LOW';
  
  return await insertArtifact({
    type: 'accessibility_scan_summary',
    val_text: `Accessibility scan: ${summary.totalViolations} violations across ${summary.pagesSuccessful} pages (${summary.criticalViolations} critical, ${summary.seriousViolations} serious)`,
    severity,
    meta: {
      scan_id: scanId,
      scan_module: 'accessibilityScan',
      domain,
      summary,
      page_results: pageResults,
      page_hashes: pageHashes || [], // Store hashes for future change detection
      legal_risk_assessment: {
        ada_lawsuit_risk: severity === 'HIGH' ? 'HIGH' : severity === 'MEDIUM' ? 'MEDIUM' : 'LOW',
        wcag_compliance: summary.totalViolations === 0 ? 'COMPLIANT' : 'NON_COMPLIANT',
        recommended_action: severity === 'HIGH' 
          ? 'Immediate remediation required to reduce legal risk'
          : severity === 'MEDIUM'
          ? 'Schedule accessibility improvements within 60 days'
          : 'Consider accessibility improvements in next development cycle'
      }
    }
  });
}

/**
 * Generate findings for accessibility violations
 */
async function createAccessibilityFindings(artifactId: number, pageResults: AccessibilityPageResult[], scanId?: string): Promise<number> {
  let findingsCount = 0;
  
  // Group violations by rule for cleaner reporting
  const violationsByRule = new Map<string, AccessibilityViolation[]>();
  
  pageResults.forEach(page => {
    page.violations.forEach(violation => {
      if (!violationsByRule.has(violation.ruleId)) {
        violationsByRule.set(violation.ruleId, []);
      }
      violationsByRule.get(violation.ruleId)!.push(violation);
    });
  });
  
  // Aggregate violations by severity for legal contingent liability assessment
  const violationsBySeverity = {
    critical: 0,
    serious: 0,
    moderate: 0,
    minor: 0
  };
  
  let totalViolationCount = 0;
  let worstImpact = 'minor';
  const violationDetails: string[] = [];
  
  for (const [ruleId, violations] of violationsByRule) {
    const impact = violations[0].impact;
    const affectedPages = [...new Set(violations.map(v => v.pageUrl))];
    const totalElements = violations.reduce((sum, v) => sum + v.elements.length, 0);
    
    // Count violations by severity
    violationsBySeverity[impact] += totalElements;
    totalViolationCount += totalElements;
    
    // Track worst impact for overall severity determination
    if (impact === 'critical' || (impact === 'serious' && worstImpact !== 'critical') || 
        (impact === 'moderate' && worstImpact !== 'critical' && worstImpact !== 'serious')) {
      worstImpact = impact;
    }
    
    // Collect violation details for description
    violationDetails.push(`${violations[0].description} (${totalElements} elements, ${affectedPages.length} pages)`);
  }
  
  // Only create ADA finding if violations exist
  if (totalViolationCount > 0) {
    // Determine overall legal risk severity based on worst violations
    let legalRiskSeverity: string;
    if (violationsBySeverity.critical > 0 || violationsBySeverity.serious > 0) {
      legalRiskSeverity = 'HIGH';  // $40k - Critical barriers create high lawsuit risk
    } else if (violationsBySeverity.moderate > 0) {
      legalRiskSeverity = 'MEDIUM';  // $30k - Moderate violations create moderate lawsuit risk
    } else {
      legalRiskSeverity = 'LOW';  // $20k - Minor violations only create lower lawsuit risk
    }
    
    // Create comprehensive description
    const severitySummary = [
      violationsBySeverity.critical > 0 ? `${violationsBySeverity.critical} critical` : '',
      violationsBySeverity.serious > 0 ? `${violationsBySeverity.serious} serious` : '',
      violationsBySeverity.moderate > 0 ? `${violationsBySeverity.moderate} moderate` : '',
      violationsBySeverity.minor > 0 ? `${violationsBySeverity.minor} minor` : ''
    ].filter(Boolean).join(', ');
    
    const description = `ADA compliance violations create legal contingent liability: ${severitySummary} violations (${totalViolationCount} total elements affected)`;
    
    // Include top violation details (limit for readability)
    const topViolations = violationDetails.slice(0, 3).join(' | ');
    const evidence = totalViolationCount > 0 ? 
      `Legal exposure: Defense costs + settlement + remediation + attorney fees. Top violations: ${topViolations}${violationDetails.length > 3 ? ` and ${violationDetails.length - 3} more` : ''}` :
      'No accessibility violations detected';
    
    // Create artifact for ADA legal contingent liability
    const adaArtifactId = await insertArtifact({
      type: 'ada_legal_contingent_liability',
      val_text: `ADA compliance violations create ${legalRiskSeverity.toLowerCase()} legal contingent liability risk`,
      severity: legalRiskSeverity as 'LOW' | 'MEDIUM' | 'HIGH',
      meta: {
        scan_id: scanId, // Use actual scan ID
        scan_module: 'accessibilityScan',
        violation_summary: violationsBySeverity,
        total_violations: totalViolationCount,
        worst_impact: worstImpact,
        legal_risk_tier: legalRiskSeverity,
        estimated_legal_exposure: legalRiskSeverity === 'HIGH' ? '$40,000' : legalRiskSeverity === 'MEDIUM' ? '$30,000' : '$20,000'
      }
    });

    await insertFinding(
      adaArtifactId,
      'ADA_LEGAL_CONTINGENT_LIABILITY',
      `Strengthen WCAG 2.1 AA compliance to reduce lawsuit risk - prioritize ${worstImpact} violations`,
      description
    );
    
    findingsCount = 1; // Single aggregated finding
  }
  
  return findingsCount;
}

/**
 * Main accessibility scan function
 */
export async function runAccessibilityScan(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;
  const startTime = Date.now();
  
  log(`Starting accessibility scan for domain="${domain}"`);
  
  // Handle Puppeteer disabled case
  if (process.env.ENABLE_PUPPETEER === '0') {
    log('Accessibility scan unavailable: Puppeteer disabled');
    
    await insertArtifact({
      type: 'accessibility_scan_unavailable',
      val_text: 'Accessibility scan unavailable: Puppeteer disabled',
      severity: 'INFO',
      meta: { 
        scan_id: scanId, 
        scan_module: 'accessibilityScan',
        reason: 'puppeteer_disabled',
        scan_duration_ms: Date.now() - startTime
      }
    });
    
    return 0;
  }
  
  const pageResults: AccessibilityPageResult[] = [];
  
  try {
    // Discover pages to test
    const pagesToTest = await discoverTestablePages(domain);
    log(`Discovered ${pagesToTest.length} pages to test for accessibility`);
    
    // STEP 1: Compute current page hashes for change detection
    log(`accessibility=hash_computation domain="${domain}" pages=${pagesToTest.length}`);
    const currentHashes: PageHashData[] = [];
    
    for (const url of pagesToTest.slice(0, 5)) { // Only hash first 5 pages for performance
      const hashData = await computePageHash(url);
      if (hashData) {
        currentHashes.push(hashData);
      }
    }
    
    // STEP 2: Check if site has changed since last scan
    const hasChanged = await hasAccessibilityChanged(domain, currentHashes);
    
    if (!hasChanged) {
      // Site hasn't changed, skip full accessibility scan
      log(`accessibility=skipped domain="${domain}" reason="no_changes_detected"`);
      
      await insertArtifact({
        type: 'accessibility_scan_skipped',
        val_text: `Accessibility scan skipped: No changes detected since last scan`,
        severity: 'INFO',
        meta: {
          scan_id: scanId,
          scan_module: 'accessibilityScan',
          domain,
          reason: 'no_changes_detected',
          pages_checked: currentHashes.length,
          page_hashes: currentHashes,
          scan_duration_ms: Date.now() - startTime
        }
      });
      
      return 0;
    }
    
    // STEP 3: Site has changed, run full accessibility scan
    log(`accessibility=running_full_scan domain="${domain}" reason="changes_detected"`);
    
    // Test each page using shared browser
    for (const url of pagesToTest) {
      const result = await testPageAccessibility(url);
      pageResults.push(result);
      
      // Rate limiting between pages
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    // Analyze results
    const summary = analyzeScanResults(pageResults);
    log(`Accessibility analysis complete: ${summary.totalViolations} violations (${summary.criticalViolations} critical, ${summary.seriousViolations} serious)`);
    
    // Create artifacts and findings
    const artifactId = await createAccessibilityArtifact(scanId, domain, summary, pageResults, currentHashes);
    const findingsCount = await createAccessibilityFindings(artifactId, pageResults, scanId);
    
    const duration = Date.now() - startTime;
    log(`Accessibility scan completed: ${findingsCount} findings from ${summary.pagesSuccessful}/${summary.totalPages} pages in ${duration}ms`);
    
    return findingsCount;
    
  } catch (error) {
    const errorMsg = (error as Error).message;
    log(`Accessibility scan failed: ${errorMsg}`);
    
    await insertArtifact({
      type: 'scan_error',
      val_text: `Accessibility scan failed: ${errorMsg}`,
      severity: 'MEDIUM',
      meta: { 
        scan_id: scanId, 
        scan_module: 'accessibilityScan',
        scan_duration_ms: Date.now() - startTime
      }
    });
    
    return 0;
  }
}
</file>

<file path="adversarialMediaScan.ts">
/**
 * Adversarial Media Scan Module
 * 
 * Performs reputational risk detection by searching for adverse media coverage
 * about target companies using Serper.dev's search API.
 */

import axios from 'axios';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { log as rootLog } from '../core/logger.js';

// Configuration constants
const SERPER_ENDPOINT = 'https://google.serper.dev/search';
const WINDOW_DAYS = 730; // 24 months lookback
const API_TIMEOUT_MS = 15_000;
const MAX_RESULTS_PER_QUERY = 20;
const MAX_FINDINGS_PER_CATEGORY = 5;
const QUERY_DELAY_MS = 1000; // Between queries

// Enhanced logging
const log = (...args: unknown[]) => rootLog('[adversarialMediaScan]', ...args);

interface SerperSearchResult {
  title: string;
  link: string;
  snippet: string;
  date?: string;
  source?: string;
}

interface CategorizedArticle extends SerperSearchResult {
  category: string;
  relevanceScore: number;
}

interface AdversarialMediaSummary {
  totalArticles: number;
  categoryCount: number;
  categorizedResults: Record<string, CategorizedArticle[]>;
  scanDurationMs: number;
  queriesSuccessful: number;
  queriesTotal: number;
}

/**
 * Generate targeted search queries for comprehensive adverse media coverage
 */
function generateSearchQueries(company: string, domain: string): string[] {
  return [
    `"${company}" (lawsuit OR "legal action" OR fine OR settlement OR sued)`,
    `"${domain}" (breach OR hack OR "data breach" OR "security incident" OR ransomware)`,
    `"${company}" (bankruptcy OR layoffs OR "financial distress" OR recall OR scandal)`,
    `"${company}" CEO OR founder (fraud OR misconduct OR harassment OR arrested)`
  ];
}

/**
 * Check if article is within the configured time window
 */
function isRecentArticle(dateStr: string | undefined, windowDays: number): boolean {
  if (!dateStr) return true; // Include if no date info
  
  try {
    const articleDate = new Date(dateStr).getTime();
    const cutoffDate = Date.now() - (windowDays * 24 * 60 * 60 * 1000);
    
    return articleDate > cutoffDate;
  } catch {
    return true; // Include if date parsing fails
  }
}

/**
 * Classify article into risk categories based on content analysis
 */
function classifyArticle(title: string, snippet: string): string {
  const text = (title + ' ' + snippet).toLowerCase();
  
  // Clear conditional logic for each category
  if (/lawsuit|litigation|regulator|fine|settlement|sued|court|judgment|penalty/.test(text)) {
    return 'Litigation / Regulatory';
  }
  
  if (/breach|hack|data breach|security incident|ransomware|cyber|leaked|exposed/.test(text)) {
    return 'Data Breach / Cyber Incident';
  }
  
  if (/fraud|misconduct|harassment|arrested|criminal|embezzlement|bribery/.test(text)) {
    return 'Executive Misconduct';
  }
  
  if (/bankruptcy|layoffs|financial distress|default|debt|insolvency|closure/.test(text)) {
    return 'Financial Distress';
  }
  
  if (/recall|injury|death|defect|safety|harm|poison|contamination/.test(text)) {
    return 'Product Safety / Customer Harm';
  }
  
  if (/discrimination|environment|pollution|esg|controversy|protest|boycott/.test(text)) {
    return 'Social / Environmental Controversy';
  }
  
  return 'Other'; // Will be filtered out
}

/**
 * Calculate relevance score for article based on title/snippet content
 */
function calculateRelevanceScore(article: SerperSearchResult, company: string): number {
  const text = (article.title + ' ' + article.snippet).toLowerCase();
  const companyLower = company.toLowerCase();
  
  let score = 0;
  
  // Company name mentions
  const companyMentions = (text.match(new RegExp(companyLower, 'g')) || []).length;
  score += companyMentions * 2;
  
  // Recency boost
  if (article.date) {
    const articleDate = new Date(article.date).getTime();
    const daysSince = (Date.now() - articleDate) / (24 * 60 * 60 * 1000);
    if (daysSince < 30) score += 3;
    else if (daysSince < 90) score += 2;
    else if (daysSince < 365) score += 1;
  }
  
  // Source credibility boost (simplified)
  if (article.source) {
    const credibleSources = ['reuters', 'bloomberg', 'wsj', 'ft.com', 'ap.org', 'bbc'];
    if (credibleSources.some(source => article.source!.toLowerCase().includes(source))) {
      score += 2;
    }
  }
  
  return score;
}

/**
 * Remove duplicate articles by URL across all queries
 */
function deduplicateArticles(articles: SerperSearchResult[]): SerperSearchResult[] {
  const seen = new Set<string>();
  return articles.filter(article => {
    if (seen.has(article.link)) return false;
    seen.add(article.link);
    return true;
  });
}

/**
 * Execute search query against Serper API
 */
async function executeSearchQuery(query: string, apiKey: string): Promise<SerperSearchResult[]> {
  try {
    log(`Executing search query: "${query.substring(0, 50)}..."`);
    
    const response = await axios.post(SERPER_ENDPOINT, {
      q: query,
      num: MAX_RESULTS_PER_QUERY,
      tbm: 'nws', // News search
      tbs: `qdr:y2` // Last 2 years to match our window
    }, {
      headers: {
        'X-API-KEY': apiKey,
        'Content-Type': 'application/json'
      },
      timeout: API_TIMEOUT_MS
    });
    
    const results: SerperSearchResult[] = (response.data.organic || []).map((item: any) => ({
      title: item.title || '',
      link: item.link || '',
      snippet: item.snippet || '',
      date: item.date,
      source: item.source
    }));
    
    log(`Query returned ${results.length} results`);
    return results;
    
  } catch (error) {
    const errorMsg = (error as Error).message;
    log(`Search query failed: ${errorMsg}`);
    
    // Return empty array to continue with other queries
    return [];
  }
}

/**
 * Process and categorize search results
 */
function processSearchResults(
  results: SerperSearchResult[], 
  company: string
): Record<string, CategorizedArticle[]> {
  
  // Filter by time window
  const recentArticles = results.filter(article => 
    isRecentArticle(article.date, WINDOW_DAYS)
  );
  
  log(`Filtered to ${recentArticles.length} recent articles (within ${WINDOW_DAYS} days)`);
  
  // Categorize and score articles
  const categorized: Record<string, CategorizedArticle[]> = {};
  
  recentArticles.forEach(article => {
    const category = classifyArticle(article.title, article.snippet);
    
    // Skip 'Other' category
    if (category === 'Other') return;
    
    const relevanceScore = calculateRelevanceScore(article, company);
    
    if (!categorized[category]) {
      categorized[category] = [];
    }
    
    categorized[category].push({
      ...article,
      category,
      relevanceScore
    });
  });
  
  // Sort each category by relevance score
  Object.keys(categorized).forEach(category => {
    categorized[category].sort((a, b) => b.relevanceScore - a.relevanceScore);
  });
  
  return categorized;
}

/**
 * Main scan function
 */
export async function runAdversarialMediaScan(job: { 
  company: string; 
  domain: string; 
  scanId: string 
}): Promise<number> {
  const { company, domain, scanId } = job;
  const startTime = Date.now();
  
  log(`Starting adversarial media scan for company="${company}" domain="${domain}"`);
  
  // Validate inputs
  if (!company || !domain) {
    log('Missing required parameters: company and domain');
    return 0;
  }
  
  // Check API key
  const apiKey = process.env.SERPER_KEY;
  if (!apiKey) {
    log('SERPER_KEY not configured, emitting error and exiting');
    
    await insertArtifact({
      type: 'scan_error',
      val_text: 'Adversarial media scan failed: SERPER_KEY not configured',
      severity: 'MEDIUM',
      meta: {
        scan_id: scanId,
        scan_module: 'adversarialMediaScan',
        reason: 'missing_api_key'
      }
    });
    
    return 0;
  }
  
  try {
    // Generate search queries
    const searchQueries = generateSearchQueries(company, domain);
    log(`Generated ${searchQueries.length} search queries`);
    
    let allResults: SerperSearchResult[] = [];
    let successfulQueries = 0;
    
    // Execute each query with delay
    for (let i = 0; i < searchQueries.length; i++) {
      const query = searchQueries[i];
      
      const results = await executeSearchQuery(query, apiKey);
      if (results.length > 0) {
        allResults = allResults.concat(results);
        successfulQueries++;
      }
      
      // Add delay between queries (except for the last one)
      if (i < searchQueries.length - 1) {
        await new Promise(resolve => setTimeout(resolve, QUERY_DELAY_MS));
      }
    }
    
    // Deduplicate results
    const uniqueResults = deduplicateArticles(allResults);
    log(`Collected ${uniqueResults.length} unique articles (${allResults.length - uniqueResults.length} duplicates removed)`);
    
    // Process and categorize results
    const categorizedResults = processSearchResults(uniqueResults, company);
    const totalArticles = Object.values(categorizedResults).reduce((sum, articles) => sum + articles.length, 0);
    const categoryCount = Object.keys(categorizedResults).length;
    
    log(`Categorized ${totalArticles} articles into ${categoryCount} risk categories`);
    
    // Create summary artifact
    const summary: AdversarialMediaSummary = {
      totalArticles,
      categoryCount,
      categorizedResults,
      scanDurationMs: Date.now() - startTime,
      queriesSuccessful: successfulQueries,
      queriesTotal: searchQueries.length
    };
    
    const artifactId = await insertArtifact({
      type: 'adverse_media_summary',
      val_text: `Found ${totalArticles} adverse media articles across ${categoryCount} risk categories`,
      severity: totalArticles > 10 ? 'HIGH' : totalArticles > 0 ? 'MEDIUM' : 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'adversarialMediaScan',
        total_articles: totalArticles,
        categories: categorizedResults,
        scan_duration_ms: summary.scanDurationMs,
        queries_successful: successfulQueries,
        queries_total: searchQueries.length
      }
    });
    
    // Generate findings for top articles in each category
    let findingsCount = 0;
    for (const [category, articles] of Object.entries(categorizedResults)) {
      const topArticles = articles
        .sort((a, b) => new Date(b.date || '1970-01-01').getTime() - new Date(a.date || '1970-01-01').getTime())
        .slice(0, MAX_FINDINGS_PER_CATEGORY);

      for (const article of topArticles) {
        await insertFinding(
          artifactId,
          'ADVERSE_MEDIA',
          `${category}: ${article.title}`,
          `Source: ${article.source || 'Unknown'} | Link: ${article.link}`
        );
        findingsCount++;
      }
    }
    
    const duration = Date.now() - startTime;
    log(`Adversarial media scan complete: ${findingsCount} findings generated in ${duration}ms`);
    
    return findingsCount;
    
  } catch (error) {
    const errorMsg = (error as Error).message;
    log(`Adversarial media scan failed: ${errorMsg}`);
    
    await insertArtifact({
      type: 'scan_error',
      val_text: `Adversarial media scan failed: ${errorMsg}`,
      severity: 'MEDIUM',
      meta: {
        scan_id: scanId,
        scan_module: 'adversarialMediaScan',
        error: true,
        scan_duration_ms: Date.now() - startTime
      }
    });
    
    return 0;
  }
}
</file>

<file path="aiPathFinder.ts">
/*
 * =============================================================================
 * MODULE: aiPathFinder.ts
 * =============================================================================
 * AI-powered intelligent path generation for discovering sensitive files and endpoints.
 * Uses OpenAI to generate context-aware paths based on detected technology stack.
 * =============================================================================
 */

import { OpenAI } from 'openai';
import axios from 'axios';
import * as https from 'node:https';
import { insertArtifact, pool } from '../core/artifactStore.js';
import { log } from '../core/logger.js';

// Configuration
const AI_MODEL = 'gpt-4.1-mini-2025-04-14'; // Using specified model
const MAX_PATHS_TO_GENERATE = 50;
const MAX_CONCURRENT_PROBES = 8;
const PROBE_TIMEOUT = 8000;

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15'
];

interface TechStack {
  frameworks: string[];
  languages: string[];
  servers: string[];
  databases: string[];
  cms: string[];
  cloud_services: string[];
}

interface GeneratedPath {
  path: string;
  confidence: 'high' | 'medium' | 'low';
  reasoning: string;
  category: string;
}

interface ProbeResult {
  url: string;
  statusCode: number;
  size: number;
  contentType: string;
  accessible: boolean;
}

/**
 * Get technology stack from previous scan results
 */
async function getTechStack(scanId: string, domain: string): Promise<TechStack> {
    const defaultStack: TechStack = {
        frameworks: [],
        languages: [],
        servers: [],
        databases: [],
        cms: [],
        cloud_services: []
    };

    try {
        // Query for tech stack artifacts from previous scans
        const techResult = await pool.query(`
            SELECT meta FROM artifacts 
            WHERE meta->>'scan_id' = $1 
            AND type IN ('tech_stack', 'discovered_technology')
            ORDER BY created_at DESC 
            LIMIT 5
        `, [scanId]);

        for (const row of techResult.rows) {
            const meta = row.meta;
            
            // Extract technology information from various formats
            if (meta.technologies) {
                defaultStack.frameworks.push(...(meta.technologies.frameworks || []));
                defaultStack.languages.push(...(meta.technologies.languages || []));
                defaultStack.servers.push(...(meta.technologies.servers || []));
                defaultStack.databases.push(...(meta.technologies.databases || []));
                defaultStack.cms.push(...(meta.technologies.cms || []));
                defaultStack.cloud_services.push(...(meta.technologies.cloud || []));
            }
            
            // Handle flat technology lists
            if (meta.technology) {
                const tech = meta.technology.toLowerCase();
                if (tech.includes('react') || tech.includes('vue') || tech.includes('angular')) {
                    defaultStack.frameworks.push(tech);
                } else if (tech.includes('node') || tech.includes('python') || tech.includes('php')) {
                    defaultStack.languages.push(tech);
                } else if (tech.includes('nginx') || tech.includes('apache') || tech.includes('cloudflare')) {
                    defaultStack.servers.push(tech);
                }
            }
        }

        // Deduplicate arrays
        Object.keys(defaultStack).forEach(key => {
            defaultStack[key as keyof TechStack] = [...new Set(defaultStack[key as keyof TechStack])];
        });

        log(`[aiPathFinder] Detected tech stack: ${JSON.stringify(defaultStack)}`);
        
    } catch (error) {
        log('[aiPathFinder] Error querying tech stack:', (error as Error).message);
    }

    return defaultStack;
}

/**
 * Generate intelligent paths using OpenAI
 */
async function generateIntelligentPaths(domain: string, techStack: TechStack): Promise<GeneratedPath[]> {
    if (!process.env.OPENAI_API_KEY) {
        log('[aiPathFinder] No OpenAI API key - using fallback path generation');
        return generateFallbackPaths(techStack);
    }

    try {
        const openai = new OpenAI({ timeout: 30000 });
        
        // Sanitize domain input to prevent AI prompt injection
        const safeDomain = domain.replace(/[^a-zA-Z0-9.-]/g, '').slice(0, 253);
        const safeTechStack = JSON.stringify(techStack).slice(0, 2000); // Limit tech stack size
        
        const prompt = `You are a cybersecurity expert specializing in web application reconnaissance. Your task is to generate a list of potential file paths that might expose sensitive information or provide insight into the application's structure.

TARGET INFORMATION:
- Domain: ${safeDomain}
- Detected Technologies: ${safeTechStack}

REQUIREMENTS:
1. Generate ${MAX_PATHS_TO_GENERATE} potential paths that are likely to exist on this specific technology stack
2. Focus on paths that might contain:
   - Configuration files (.env, config.json, settings.yaml)
   - Build artifacts (webpack configs, source maps, package files)
   - Development/staging endpoints
   - API documentation (swagger.json, openapi.yaml)
   - Admin interfaces
   - Debug endpoints
   - Backup files
   - Log files
   - Framework-specific paths

3. Tailor paths to the detected technologies. For example:
   - React: /_next/static/, /build/, /static/js/
   - Vue: /dist/, /.nuxt/
   - Node.js: /package.json, /node_modules/
   - WordPress: /wp-config.php, /wp-admin/
   - Laravel: /.env, /storage/logs/
   - Django: /settings.py, /debug/

4. Return ONLY a JSON array with this exact format:
[
  {
    "path": "/example/path",
    "confidence": "high|medium|low",
    "reasoning": "Brief explanation why this path might exist",
    "category": "config|build|api|admin|debug|backup|logs|other"
  }
]

IMPORTANT: Return ONLY the JSON array, no additional text or explanation.`;

        const response = await openai.chat.completions.create({
            model: AI_MODEL,
            messages: [
                {
                    role: 'system',
                    content: 'You are a cybersecurity expert. Return only valid JSON arrays as requested.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            temperature: 0.7,
            max_tokens: 2000
        });

        const content = response.choices[0]?.message?.content?.trim();
        if (!content) {
            throw new Error('Empty response from OpenAI');
        }

        // Parse the JSON response
        const generatedPaths: GeneratedPath[] = JSON.parse(content);
        
        // Validate the response format
        if (!Array.isArray(generatedPaths)) {
            throw new Error('Response is not an array');
        }

        // Filter and validate paths
        const validPaths = generatedPaths.filter(path => 
            path.path && 
            path.confidence && 
            path.reasoning && 
            path.category &&
            path.path.startsWith('/')
        );

        log(`[aiPathFinder] Generated ${validPaths.length} AI-powered paths`);
        return validPaths.slice(0, MAX_PATHS_TO_GENERATE);

    } catch (error) {
        log('[aiPathFinder] Error generating AI paths:', (error as Error).message);
        log('[aiPathFinder] Falling back to rule-based path generation');
        return generateFallbackPaths(techStack);
    }
}

/**
 * Fallback path generation when AI is unavailable
 */
function generateFallbackPaths(techStack: TechStack): GeneratedPath[] {
    const paths: GeneratedPath[] = [];
    
    // Universal high-value paths
    const universalPaths = [
        { path: '/.env', confidence: 'high' as const, reasoning: 'Common environment file', category: 'config' },
        { path: '/config.json', confidence: 'high' as const, reasoning: 'Common config file', category: 'config' },
        { path: '/package.json', confidence: 'medium' as const, reasoning: 'Node.js package info', category: 'build' },
        { path: '/swagger.json', confidence: 'medium' as const, reasoning: 'API documentation', category: 'api' },
        { path: '/api/config', confidence: 'medium' as const, reasoning: 'API configuration endpoint', category: 'api' }
    ];
    
    paths.push(...universalPaths);
    
    // Framework-specific paths
    if (techStack.frameworks.some(f => f.toLowerCase().includes('react'))) {
        paths.push(
            { path: '/_next/static/chunks/webpack.js', confidence: 'high', reasoning: 'Next.js webpack config', category: 'build' },
            { path: '/build/static/js/main.js', confidence: 'medium', reasoning: 'React build artifact', category: 'build' }
        );
    }
    
    if (techStack.frameworks.some(f => f.toLowerCase().includes('vue'))) {
        paths.push(
            { path: '/.nuxt/dist/', confidence: 'medium', reasoning: 'Nuxt.js build directory', category: 'build' },
            { path: '/dist/js/app.js', confidence: 'medium', reasoning: 'Vue build artifact', category: 'build' }
        );
    }
    
    if (techStack.cms.some(c => c.toLowerCase().includes('wordpress'))) {
        paths.push(
            { path: '/wp-config.php', confidence: 'high', reasoning: 'WordPress configuration', category: 'config' },
            { path: '/wp-admin/admin.php', confidence: 'medium', reasoning: 'WordPress admin interface', category: 'admin' }
        );
    }
    
    log(`[aiPathFinder] Generated ${paths.length} fallback paths`);
    return paths;
}

/**
 * Probe generated paths to see which ones are accessible
 */
async function probeGeneratedPaths(baseUrl: string, paths: GeneratedPath[]): Promise<ProbeResult[]> {
    const results: ProbeResult[] = [];
    const httpsAgent = new https.Agent({ rejectUnauthorized: false });
    
    // Process paths in chunks to control concurrency
    for (let i = 0; i < paths.length; i += MAX_CONCURRENT_PROBES) {
        const chunk = paths.slice(i, i + MAX_CONCURRENT_PROBES);
        
        const chunkResults = await Promise.allSettled(
            chunk.map(async (pathInfo) => {
                const url = `${baseUrl}${pathInfo.path}`;
                
                try {
                    const response = await axios.head(url, {
                        timeout: PROBE_TIMEOUT,
                        httpsAgent,
                        headers: {
                            'User-Agent': USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)]
                        },
                        validateStatus: () => true, // Don't throw on 4xx/5xx
                        maxRedirects: 3
                    });
                    
                    const accessible = response.status < 400;
                    if (accessible) {
                        log(`[aiPathFinder] Found accessible path: ${url} (${response.status})`);
                    }
                    
                    return {
                        url,
                        statusCode: response.status,
                        size: parseInt(response.headers['content-length'] || '0'),
                        contentType: response.headers['content-type'] || 'unknown',
                        accessible,
                        pathInfo
                    };
                    
                } catch (error) {
                    return {
                        url,
                        statusCode: 0,
                        size: 0,
                        contentType: 'error',
                        accessible: false,
                        pathInfo,
                        error: (error as Error).message
                    };
                }
            })
        );
        
        // Process chunk results
        for (const result of chunkResults) {
            if (result.status === 'fulfilled' && result.value.accessible) {
                results.push(result.value);
            }
        }
        
        // Rate limiting delay
        if (i + MAX_CONCURRENT_PROBES < paths.length) {
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    }
    
    return results;
}

/**
 * Main AI Path Finder function
 */
export async function runAiPathFinder(job: { domain: string; scanId?: string }): Promise<number> {
    log(`[aiPathFinder] Starting AI-powered path discovery for ${job.domain}`);
    
    if (!job.scanId) {
        log('[aiPathFinder] No scanId provided - skipping AI path finding');
        return 0;
    }
    
    const baseUrl = `https://${job.domain}`;
    
    try {
        // 1. Get technology stack from previous scans
        const techStack = await getTechStack(job.scanId, job.domain);
        
        // 2. Generate intelligent paths using AI
        const generatedPaths = await generateIntelligentPaths(job.domain, techStack);
        
        // 3. Probe the generated paths
        const accessiblePaths = await probeGeneratedPaths(baseUrl, generatedPaths);
        
        // 4. Save results as artifacts for other modules to use
        if (accessiblePaths.length > 0) {
            await insertArtifact({
                type: 'ai_discovered_paths',
                val_text: `AI discovered ${accessiblePaths.length} accessible paths on ${job.domain}`,
                severity: 'INFO',
                meta: {
                    scan_id: job.scanId,
                    scan_module: 'aiPathFinder',
                    accessible_paths: accessiblePaths,
                    generated_paths_count: generatedPaths.length,
                    tech_stack: techStack,
                    ai_model_used: AI_MODEL,
                    success_rate: `${((accessiblePaths.length / generatedPaths.length) * 100).toFixed(1)}%`
                }
            });
            
            // Save high-confidence paths as web assets for secret scanning
            for (const pathResult of accessiblePaths.filter(p => p.contentType.includes('text') || p.contentType.includes('json'))) {
                await insertArtifact({
                    type: 'discovered_web_assets',
                    val_text: `AI-discovered web asset: ${pathResult.url}`,
                    severity: 'INFO',
                    meta: {
                        scan_id: job.scanId,
                        scan_module: 'aiPathFinder',
                        assets: [{
                            url: pathResult.url,
                            type: pathResult.contentType.includes('json') ? 'json' : 'other',
                            confidence: 'high',
                            source: 'ai_generated',
                            mimeType: pathResult.contentType,
                            size: pathResult.size
                        }]
                    }
                });
            }
        }
        
        log(`[aiPathFinder] Completed AI path discovery: ${accessiblePaths.length}/${generatedPaths.length} paths accessible`);
        return accessiblePaths.length;
        
    } catch (error) {
        log('[aiPathFinder] Error in AI path discovery:', (error as Error).message);
        return 0;
    }
}
</file>

<file path="assetCorrelator.ts">
/*
 * =============================================================================
 * MODULE: assetCorrelator.ts
 * =============================================================================
 * Correlates disparate security findings into asset-centric intelligence.
 * Transforms flat artifact lists into actionable, prioritized asset groups.
 * 
 * Key optimizations:
 * - Batch DNS resolution with caching
 * - Streaming for large datasets
 * - Service-level correlation (IP:port tuples)
 * - Hostname affinity validation
 * - Finding deduplication
 * =============================================================================
 */

import { pool, insertArtifact } from '../core/artifactStore.js';
import { log } from '../core/logger.js';
import dns from 'node:dns/promises';
import pLimit from 'p-limit';

// Types
interface CorrelatedAsset {
  ip: string;
  port?: number;
  hostnames: string[];
  service?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  findings: Finding[];
  asn?: string;
  org?: string;
  asset_criticality: number;
}

interface Finding {
  artifact_id: number;
  type: string;
  id?: string; // CVE-ID, finding ID
  cvss?: number;
  epss?: number;
  description: string;
}

interface RawArtifact {
  id: number;
  type: string;
  val_text: string;
  severity: string;
  ip?: string;
  host?: string;
  port?: number | string;
  meta: any;
  hostnames_json?: string;
  product?: string;
  version?: string;
  org?: string;
  asn?: string;
  cve?: string;
  cvss?: string;
  epss?: string;
}

// DNS cache for the scan session
class DNSCache {
  private cache = new Map<string, string[]>();
  private limit = pLimit(10); // Max 10 concurrent DNS lookups

  async resolve(hostname: string): Promise<string[]> {
    if (this.cache.has(hostname)) {
      return this.cache.get(hostname)!;
    }

    try {
      const result = await this.limit(() => 
        Promise.race([
          dns.lookup(hostname, { all: true }),
          new Promise<never>((_, reject) => 
            setTimeout(() => reject(new Error('DNS timeout')), 3000)
          )
        ])
      );
      
      const ips = Array.isArray(result) 
        ? result.map((r: any) => r.address) 
        : [(result as any).address];
      
      this.cache.set(hostname, ips);
      return ips;
    } catch (error) {
      log(`[assetCorrelator] DNS resolution failed for ${hostname}: ${error}`);
      this.cache.set(hostname, []); // Cache failures too
      return [];
    }
  }

  async resolveBatch(hostnames: Set<string>): Promise<Map<string, string[]>> {
    const results = new Map<string, string[]>();
    const promises = Array.from(hostnames).map(async hostname => {
      const ips = await this.resolve(hostname);
      results.set(hostname, ips);
    });
    
    await Promise.allSettled(promises);
    return results;
  }
}

// Main correlation function
export async function runAssetCorrelator(job: { 
  scanId: string; 
  domain: string; 
  tier?: 'tier1' | 'tier2' 
}): Promise<void> {
  const { scanId, domain, tier = 'tier1' } = job;
  const startTime = Date.now();
  const TIMEOUT_MS = 30000; // 30 second overall timeout
  
  log(`[assetCorrelator] Starting correlation for scanId: ${scanId}, tier: ${tier}`);

  try {
    // Set up timeout
    const timeoutPromise = new Promise<never>((_, reject) => 
      setTimeout(() => reject(new Error('Correlation timeout')), TIMEOUT_MS)
    );

    await Promise.race([
      correlateAssets(scanId, domain),
      timeoutPromise
    ]);

  } catch (error) {
    const elapsed = Date.now() - startTime;
    log(`[assetCorrelator] Failed after ${elapsed}ms:`, (error as Error).message);
    
    await insertArtifact({
      type: 'scan_error',
      val_text: `Asset correlation failed: ${(error as Error).message}`,
      severity: 'MEDIUM',
      meta: { 
        scan_id: scanId, 
        scan_module: 'assetCorrelator',
        elapsed_ms: elapsed,
        truncated: (error as Error).message === 'Correlation timeout'
      }
    });
  }
}

async function correlateAssets(scanId: string, domain: string): Promise<void> {
  const dnsCache = new DNSCache();
  const assets = new Map<string, CorrelatedAsset>();
  const correlatedArtifactIds = new Set<number>();
  
  // Query to get all artifacts for this scan
  const query = `SELECT 
      id, 
      type, 
      val_text, 
      severity,
      meta->>'ip' AS ip,
      meta->>'host' AS host, 
      meta->>'port' AS port,
      meta->>'hostnames' AS hostnames_json,
      meta->>'product' AS product,
      meta->>'version' AS version,
      meta->>'org' AS org,
      meta->>'asn' AS asn,
      meta->>'cve' AS cve,
      meta->>'cvss' AS cvss,
      meta->>'epss_score' AS epss,
      meta
    FROM artifacts 
    WHERE meta->>'scan_id' = $1
    ORDER BY created_at`;

  let artifactCount = 0;
  let correlatedCount = 0;

  // Phase 1: Fetch all artifacts and collect hostnames for batch DNS resolution
  const allHostnames = new Set<string>();
  let artifactBuffer: RawArtifact[] = [];
  
  try {
    const result = await pool.query(query, [scanId]);
    artifactBuffer = result.rows || [];
    artifactCount = artifactBuffer.length;
    
    // Collect hostnames from artifacts
    for (const row of artifactBuffer) {
      if (row.host) allHostnames.add(row.host);
      if (row.type === 'hostname' || row.type === 'subdomain') {
        allHostnames.add(row.val_text);
      }
      if (row.hostnames_json) {
        try {
          const hostnames = JSON.parse(row.hostnames_json);
          if (Array.isArray(hostnames)) {
            hostnames.forEach((h: string) => allHostnames.add(h));
          }
        } catch (e) {}
      }
    }
  } catch (error) {
    log(`[assetCorrelator] Query error:`, error);
    throw error;
  }

  log(`[assetCorrelator] Found ${artifactCount} artifacts, resolving ${allHostnames.size} hostnames`);

  // Phase 2: Batch DNS resolution
  const hostnameToIps = await dnsCache.resolveBatch(allHostnames);

  // Phase 3: Process artifacts and build asset map
  for (const artifact of artifactBuffer) {
    const ips = extractIPs(artifact, hostnameToIps);
    
    if (ips.length === 0) {
      // Non-correlatable artifact
      continue;
    }

    correlatedCount++;
    correlatedArtifactIds.add(artifact.id);

    for (const ip of ips) {
      // Create asset key (IP:port for services, IP for host-level)
      const port = artifact.port ? parseInt(String(artifact.port)) : undefined;
      const assetKey = port ? `${ip}:${port}` : ip;
      
      // Get or create asset
      if (!assets.has(assetKey)) {
        assets.set(assetKey, {
          ip,
          port,
          hostnames: [],
          service: artifact.product || undefined,
          severity: 'INFO',
          findings: [],
          asn: artifact.asn || undefined,
          org: artifact.org || undefined,
          asset_criticality: 1
        });
      }

      const asset = assets.get(assetKey)!;

      // Add hostnames with affinity validation
      const validHostnames = validateHostnameAffinity(artifact, ip, hostnameToIps);
      validHostnames.forEach(h => {
        if (!asset.hostnames.includes(h)) {
          asset.hostnames.push(h);
        }
      });

      // Add finding (with deduplication)
      const finding: Finding = {
        artifact_id: artifact.id,
        type: artifact.type,
        id: artifact.cve || undefined,
        cvss: artifact.cvss ? parseFloat(artifact.cvss) : undefined,
        epss: artifact.epss ? parseFloat(artifact.epss) : undefined,
        description: artifact.val_text
      };

      // Deduplicate by type and description
      const findingKey = `${finding.type}:${finding.description}`;
      const existingFinding = asset.findings.find(f => 
        `${f.type}:${f.description}` === findingKey
      );

      if (!existingFinding) {
        asset.findings.push(finding);
        
        // Update asset severity (max of all findings)
        asset.severity = maxSeverity(asset.severity, artifact.severity as any);
        
        // Update criticality score
        if (artifact.severity === 'CRITICAL') {
          asset.asset_criticality = Math.min(10, asset.asset_criticality + 3);
        } else if (artifact.severity === 'HIGH') {
          asset.asset_criticality = Math.min(10, asset.asset_criticality + 2);
        }
      }
    }
  }

  // Phase 4: Generate correlation summary
  const assetArray = Array.from(assets.values());
  const criticalAssets = assetArray.filter(a => 
    a.severity === 'CRITICAL' || a.asset_criticality >= 8
  );

  if (assetArray.length > 0) {
    const summary = {
      total_artifacts: artifactCount,
      correlated_artifacts: correlatedCount,
      uncorrelated_artifacts: artifactCount - correlatedCount,
      total_assets: assetArray.length,
      critical_assets: criticalAssets.length,
      severity_breakdown: {
        critical: assetArray.filter(a => a.severity === 'CRITICAL').length,
        high: assetArray.filter(a => a.severity === 'HIGH').length,
        medium: assetArray.filter(a => a.severity === 'MEDIUM').length,
        low: assetArray.filter(a => a.severity === 'LOW').length,
        info: assetArray.filter(a => a.severity === 'INFO').length
      },
      assets: assetArray.sort((a, b) => b.asset_criticality - a.asset_criticality)
    };

    await insertArtifact({
      type: 'correlated_asset_summary',
      val_text: `Correlated ${correlatedCount}/${artifactCount} artifacts into ${assetArray.length} assets (${criticalAssets.length} critical)`,
      severity: criticalAssets.length > 0 ? 'HIGH' : 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'assetCorrelator',
        correlation_summary: summary
      }
    });

    log(`[assetCorrelator] Successfully correlated ${correlatedCount} artifacts into ${assetArray.length} assets`);
  } else {
    log(`[assetCorrelator] No correlatable assets found in ${artifactCount} artifacts`);
  }
}

// Helper functions
function extractIPs(artifact: RawArtifact, hostnameToIps: Map<string, string[]>): string[] {
  const ips = new Set<string>();
  
  // Direct IP
  if (artifact.ip) ips.add(artifact.ip);
  
  // IPs from meta
  if (artifact.meta?.ips) {
    artifact.meta.ips.forEach((ip: string) => ips.add(ip));
  }
  
  // IP artifacts
  if (artifact.type === 'ip') {
    ips.add(artifact.val_text);
  }
  
  // Resolved IPs from hostnames
  if (artifact.host) {
    const resolved = hostnameToIps.get(artifact.host) || [];
    resolved.forEach(ip => ips.add(ip));
  }
  
  if (artifact.type === 'hostname' || artifact.type === 'subdomain') {
    const resolved = hostnameToIps.get(artifact.val_text) || [];
    resolved.forEach(ip => ips.add(ip));
  }
  
  return Array.from(ips);
}

function validateHostnameAffinity(
  artifact: RawArtifact, 
  ip: string, 
  hostnameToIps: Map<string, string[]>
): string[] {
  const validHostnames: string[] = [];
  
  // Check all possible hostnames
  const candidateHostnames = new Set<string>();
  if (artifact.host) candidateHostnames.add(artifact.host);
  if (artifact.type === 'hostname' || artifact.type === 'subdomain') {
    candidateHostnames.add(artifact.val_text);
  }
  if (artifact.hostnames_json) {
    try {
      const hostnames = JSON.parse(artifact.hostnames_json);
      hostnames.forEach((h: string) => candidateHostnames.add(h));
    } catch (e) {}
  }
  
  // Validate each hostname resolves to this IP
  for (const hostname of candidateHostnames) {
    const resolvedIps = hostnameToIps.get(hostname) || [];
    if (resolvedIps.includes(ip)) {
      validHostnames.push(hostname);
    }
  }
  
  // If from TLS cert, trust it even without DNS match
  if (artifact.type === 'tls_scan' && artifact.meta?.cert_hostnames) {
    artifact.meta.cert_hostnames.forEach((h: string) => {
      if (!validHostnames.includes(h)) {
        validHostnames.push(h);
      }
    });
  }
  
  return validHostnames;
}

function maxSeverity(a: string, b: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  const severityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
  const aVal = severityOrder[a as keyof typeof severityOrder] || 0;
  const bVal = severityOrder[b as keyof typeof severityOrder] || 0;
  const maxVal = Math.max(aVal, bVal);
  
  return (Object.keys(severityOrder).find(
    k => severityOrder[k as keyof typeof severityOrder] === maxVal
  ) || 'INFO') as any;
}
</file>

<file path="breachDirectoryProbe.ts">
/**
 * Breach Directory Probe Module
 * 
 * Queries BreachDirectory and LeakCheck APIs for comprehensive domain breach intelligence
 * to identify compromised accounts and breach exposure statistics.
 */

import axios from 'axios';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { log as rootLog } from '../core/logger.js';
import { executeModule, apiCall } from '../util/errorHandler.js';

// Configuration constants
const BREACH_DIRECTORY_API_BASE = 'https://BreachDirectory.com/api_usage';
const LEAKCHECK_API_BASE = 'https://leakcheck.io/api/v2';
const API_TIMEOUT_MS = 30_000;
const MAX_SAMPLE_USERNAMES = 100;
const LEAKCHECK_RATE_LIMIT_MS = 350; // 3 requests per second = ~333ms + buffer

// Enhanced logging
const log = (...args: unknown[]) => rootLog('[breachDirectoryProbe]', ...args);

interface BreachDirectoryResponse {
  breached_total?: number;
  sample_usernames?: string[];
  error?: string;
  message?: string;
}

interface LeakCheckResponse {
  success: boolean;
  found: number;
  quota: number;
  result: Array<{
    email: string;
    source: {
      name: string;
      breach_date: string;
      unverified: number;
      passwordless: number;
      compilation: number;
    };
    first_name?: string;
    last_name?: string;
    username?: string;
    fields: string[];
  }>;
  error?: string;
}

interface BreachProbeSummary {
  domain: string;
  breached_total: number;
  sample_usernames: string[];
  high_risk_assessment: boolean;
  breach_directory_success: boolean;
  leakcheck_total: number;
  leakcheck_sources: string[];
  leakcheck_success: boolean;
  combined_total: number;
  leakcheck_results: Array<{
    email: string | null;
    username: string | null;
    source: {
      name: string;
      breach_date: string | null;
      unverified: number;
      passwordless: number;
      compilation: number;
    };
    has_password: boolean;
    has_cookies: boolean;
    has_autofill: boolean;
    has_browser_data: boolean;
    field_count: number;
    first_name: string | null;
    last_name: string | null;
  }>;
}

interface UserBreachRecord {
  userId: string;
  breaches: Array<{
    email: string | null;
    username: string | null;
    source: {
      name: string;
      breach_date: string | null;
      unverified: number;
      passwordless: number;
      compilation: number;
    };
    has_password: boolean;
    has_cookies: boolean;
    has_autofill: boolean;
    has_browser_data: boolean;
    field_count: number;
    first_name: string | null;
    last_name: string | null;
  }>;
  highestSeverity: 'CRITICAL' | 'MEDIUM' | 'INFO';
  exposureTypes: string[];
  allSources: string[];
  earliestBreach: string | null;
  latestBreach: string | null;
}

/**
 * Query Breach Directory API for domain breach data
 */
async function queryBreachDirectory(domain: string, apiKey: string): Promise<BreachDirectoryResponse> {
  const operation = async () => {
    log(`Querying Breach Directory for domain: ${domain}`);
    
    const response = await axios.get(BREACH_DIRECTORY_API_BASE, {
      params: {
        method: 'domain',
        key: apiKey,
        query: domain
      },
      timeout: API_TIMEOUT_MS,
      validateStatus: (status) => status < 500 // Accept 4xx as valid responses
    });
    
    if (response.status === 200) {
      const data = response.data as BreachDirectoryResponse;
      log(`Breach Directory response for ${domain}: ${data.breached_total || 0} breached accounts`);
      return data;
    } else if (response.status === 404) {
      log(`No breach data found for domain: ${domain}`);
      return { breached_total: 0, sample_usernames: [] };
    } else if (response.status === 403) {
      // Enhanced logging for 403 Forbidden responses
      const responseData = response.data || {};
      const errorMessage = responseData.error || responseData.message || 'Access forbidden';
      log(`Breach Directory API returned 403 Forbidden for ${domain}: ${errorMessage}`);
      throw new Error(`API access forbidden (403): ${errorMessage}`);
    } else {
      // Enhanced generic error handling with response data
      const responseData = response.data || {};
      const errorMessage = responseData.error || responseData.message || `HTTP ${response.status}`;
      log(`Breach Directory API returned status ${response.status} for ${domain}: ${errorMessage}`);
      throw new Error(`API returned status ${response.status}: ${errorMessage}`);
    }
  };

  const result = await apiCall(operation, {
    moduleName: 'breachDirectoryProbe',
    operation: 'queryBreachDirectory',
    target: domain
  });

  if (!result.success) {
    throw new Error(result.error);
  }

  return result.data;
}

/**
 * Query LeakCheck API for domain breach data
 */
async function queryLeakCheck(domain: string, apiKey: string): Promise<LeakCheckResponse> {
  const operation = async () => {
    log(`Querying LeakCheck for domain: ${domain}`);
    
    const response = await axios.get(`${LEAKCHECK_API_BASE}/query/${domain}`, {
      headers: {
        'Accept': 'application/json',
        'X-API-Key': apiKey
      },
      params: {
        type: 'domain',
        limit: 1000 // Max allowed
      },
      timeout: API_TIMEOUT_MS,
      validateStatus: (status) => status < 500 // Accept 4xx as valid responses
    });
    
    if (response.status === 200) {
      const data = response.data as LeakCheckResponse;
      log(`LeakCheck response for ${domain}: ${data.found || 0} accounts found`);
      return data;
    } else if (response.status === 404) {
      log(`No leak data found for domain: ${domain}`);
      return { success: false, found: 0, quota: 0, result: [] };
    } else {
      const responseData = response.data || {};
      const errorMessage = responseData.error || `HTTP ${response.status}`;
      throw new Error(`LeakCheck API error: ${errorMessage}`);
    }
  };

  const result = await apiCall(operation, {
    moduleName: 'breachDirectoryProbe', 
    operation: 'queryLeakCheck',
    target: domain
  });

  if (!result.success) {
    throw new Error(result.error);
  }

  return result.data;
}

/**
 * Analyze combined breach data from both sources
 */
function analyzeCombinedBreach(
  breachDirectoryData: BreachDirectoryResponse,
  leakCheckData: LeakCheckResponse
): BreachProbeSummary {
  const breached_total = breachDirectoryData.breached_total || 0;
  const sample_usernames = (breachDirectoryData.sample_usernames || []).slice(0, MAX_SAMPLE_USERNAMES);
  
  // LeakCheck data processing
  const leakcheck_total = leakCheckData.found || 0;
  const leakcheck_sources = leakCheckData.result
    .map(entry => entry.source.name)
    .filter((name, index, array) => array.indexOf(name) === index) // Remove duplicates
    .slice(0, 20); // Limit to first 20 unique sources
  
  // Process LeakCheck results for enhanced analysis (NO sensitive data stored)
  const leakCheckResults = leakCheckData.result
    .map(entry => ({
      email: entry.email || null,
      username: entry.username || (entry.email ? entry.email.split('@')[0] : null),
      source: {
        name: entry.source?.name || 'Unknown',
        breach_date: entry.source?.breach_date || null,
        unverified: entry.source?.unverified || 0,
        passwordless: entry.source?.passwordless || 0,
        compilation: entry.source?.compilation || 0
      },
      // Only store field existence flags, NOT actual values
      has_password: entry.fields?.includes('password') || false,
      has_cookies: entry.fields?.includes('cookies') || entry.fields?.includes('cookie') || false,
      has_autofill: entry.fields?.includes('autofill') || entry.fields?.includes('autofill_data') || false,
      has_browser_data: entry.fields?.includes('browser_data') || entry.fields?.includes('browser') || false,
      field_count: entry.fields?.length || 0,
      first_name: entry.first_name || null,
      last_name: entry.last_name || null
    }))
    .slice(0, 100); // Limit to 100 for performance

  // Add usernames from LeakCheck to sample usernames for backward compatibility
  const leakCheckUsernames = leakCheckResults
    .map(entry => entry.username)
    .filter(username => username !== null)
    .slice(0, 50);
  
  const combinedUsernames = [...sample_usernames, ...leakCheckUsernames]
    .filter((name, index, array) => array.indexOf(name) === index) // Remove duplicates
    .slice(0, MAX_SAMPLE_USERNAMES);
  
  const combined_total = breached_total + leakcheck_total;
  
  // High risk assessment based on breach count and username patterns
  let high_risk_assessment = false;
  
  // Risk factors
  if (combined_total >= 100) {
    high_risk_assessment = true;
  }
  
  // Check for administrative/privileged account patterns
  const privilegedPatterns = [
    'admin', 'administrator', 'root', 'sa', 'sysadmin',
    'ceo', 'cto', 'cfo', 'founder', 'owner',
    'security', 'infosec', 'it', 'tech'
  ];
  
  const hasPrivilegedAccounts = combinedUsernames.some(username => 
    privilegedPatterns.some(pattern => 
      username.toLowerCase().includes(pattern)
    )
  );
  
  if (hasPrivilegedAccounts && combined_total >= 10) {
    high_risk_assessment = true;
  }
  
  // Check for recent breaches in LeakCheck data
  const recentBreaches = leakCheckData.result.filter(entry => {
    if (!entry.source?.breach_date) return false;
    const breachYear = parseInt(entry.source.breach_date.split('-')[0]);
    return !isNaN(breachYear) && breachYear >= 2020; // Breaches from 2020 onwards
  });
  
  if (recentBreaches.length >= 10) {
    high_risk_assessment = true;
  }
  
  return {
    domain: '', // Will be set by caller
    breached_total,
    sample_usernames: combinedUsernames,
    high_risk_assessment,
    breach_directory_success: !breachDirectoryData.error,
    leakcheck_total,
    leakcheck_sources,
    leakcheck_success: leakCheckData.success,
    combined_total,
    leakcheck_results: leakCheckResults // Add full results with security flags
  };
}

/**
 * Check if breach source is infostealer malware
 */
function isInfostealerSource(credential: any): boolean {
  if (!credential.source?.name) return false;
  const sourceName = credential.source.name.toLowerCase();
  return sourceName.includes('stealer') ||
         sourceName.includes('redline') ||
         sourceName.includes('raccoon') ||
         sourceName.includes('vidar') ||
         sourceName.includes('azorult') ||
         sourceName.includes('formbook') ||
         sourceName.includes('lokibot');
}

/**
 * Check if user has username + password + session data (CRITICAL)
 */
function hasUsernamePasswordCookies(credential: any): boolean {
  return credential.has_password && 
         (credential.has_cookies || credential.has_autofill || credential.has_browser_data) &&
         (credential.username || credential.email);
}

/**
 * Check if user has username + password only (MEDIUM)
 */
function hasUsernamePassword(credential: any): boolean {
  return credential.has_password && 
         !credential.has_cookies && 
         !credential.has_autofill && 
         !credential.has_browser_data &&
         (credential.username || credential.email);
}

/**
 * Check if user has username/email only, no password (INFO)
 */
function hasUsernameOnly(credential: any): boolean {
  return !credential.has_password && 
         !credential.has_cookies && 
         !credential.has_autofill && 
         !credential.has_browser_data &&
         (credential.username || credential.email);
}

/**
 * Calculate the highest severity for a user across all their breaches
 */
function calculateUserSeverity(userBreaches: any[]): 'CRITICAL' | 'MEDIUM' | 'INFO' {
  // Check for CRITICAL conditions first (highest priority)
  const hasInfostealer = userBreaches.some(isInfostealerSource);
  const hasPasswordAndSession = userBreaches.some(hasUsernamePasswordCookies);
  
  if (hasInfostealer || hasPasswordAndSession) {
    return 'CRITICAL';
  }
  
  // Check for MEDIUM condition
  const hasPasswordOnly = userBreaches.some(hasUsernamePassword);
  if (hasPasswordOnly) {
    return 'MEDIUM';
  }
  
  // Default to INFO (username/email only)
  return 'INFO';
}

/**
 * Deduplicate and consolidate breach data by user
 */
function consolidateBreachesByUser(leakCheckResults: any[]): UserBreachRecord[] {
  const userBreachMap = new Map<string, UserBreachRecord>();
  
  leakCheckResults.forEach(credential => {
    // Use email as primary identifier, fallback to username
    const userId = credential.email || credential.username;
    if (!userId) return;
    
    // Normalize userId (lowercase for consistent grouping)
    const normalizedUserId = userId.toLowerCase();
    
    if (!userBreachMap.has(normalizedUserId)) {
      userBreachMap.set(normalizedUserId, {
        userId: userId, // Keep original case for display
        breaches: [],
        highestSeverity: 'INFO',
        exposureTypes: [],
        allSources: [],
        earliestBreach: null,
        latestBreach: null
      });
    }
    
    const userRecord = userBreachMap.get(normalizedUserId)!;
    userRecord.breaches.push(credential);
    
    // Track unique sources
    if (credential.source?.name && !userRecord.allSources.includes(credential.source.name)) {
      userRecord.allSources.push(credential.source.name);
    }
    
    // Track breach dates for timeline
    if (credential.source?.breach_date) {
      const breachDate = credential.source.breach_date;
      if (!userRecord.earliestBreach || breachDate < userRecord.earliestBreach) {
        userRecord.earliestBreach = breachDate;
      }
      if (!userRecord.latestBreach || breachDate > userRecord.latestBreach) {
        userRecord.latestBreach = breachDate;
      }
    }
  });
  
  // Calculate severity and exposure types for each user
  for (const userRecord of userBreachMap.values()) {
    userRecord.highestSeverity = calculateUserSeverity(userRecord.breaches);
    
    // Determine exposure types
    const exposureTypes = new Set<string>();
    userRecord.breaches.forEach(breach => {
      if (isInfostealerSource(breach)) {
        exposureTypes.add('Infostealer malware');
      }
      if (breach.has_password && (breach.has_cookies || breach.has_autofill || breach.has_browser_data)) {
        exposureTypes.add('Password + session data');
      } else if (breach.has_password) {
        exposureTypes.add('Password');
      }
      if (breach.has_cookies) exposureTypes.add('Cookies');
      if (breach.has_autofill) exposureTypes.add('Autofill data');
      if (breach.has_browser_data) exposureTypes.add('Browser data');
    });
    
    userRecord.exposureTypes = Array.from(exposureTypes);
  }
  
  return Array.from(userBreachMap.values());
}

/**
 * Get recommendation text based on severity
 */
function getRecommendationText(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return 'Immediately force password reset and revoke all sessions for affected accounts';
    case 'MEDIUM':
      return 'Force password reset and enable 2FA for affected accounts';
    case 'INFO':
      return 'Monitor for phishing attempts and consider security awareness training';
    default:
      return 'Review and monitor affected accounts';
  }
}

/**
 * Map severity to finding type
 */
function mapSeverityToFindingType(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return 'CRITICAL_BREACH_EXPOSURE';
    case 'MEDIUM':
      return 'PASSWORD_BREACH_EXPOSURE';
    case 'INFO':
      return 'EMAIL_BREACH_EXPOSURE';
    default:
      return 'BREACH_EXPOSURE';
  }
}

/**
 * Generate breach intelligence summary
 */
function generateBreachSummary(results: BreachProbeSummary[]): {
  total_breached_accounts: number;
  leakcheck_total_accounts: number;
  combined_total_accounts: number;
  domains_with_breaches: number;
  high_risk_domains: number;
  privileged_accounts_found: boolean;
  unique_breach_sources: string[];
} {
  const summary = {
    total_breached_accounts: 0,
    leakcheck_total_accounts: 0,
    combined_total_accounts: 0,
    domains_with_breaches: 0,
    high_risk_domains: 0,
    privileged_accounts_found: false,
    unique_breach_sources: [] as string[]
  };
  
  const allSources = new Set<string>();
  
  results.forEach(result => {
    if ((result.breach_directory_success && result.breached_total > 0) || 
        (result.leakcheck_success && result.leakcheck_total > 0)) {
      
      summary.total_breached_accounts += result.breached_total;
      summary.leakcheck_total_accounts += result.leakcheck_total;
      summary.combined_total_accounts += result.combined_total;
      summary.domains_with_breaches += 1;
      
      if (result.high_risk_assessment) {
        summary.high_risk_domains += 1;
      }
      
      // Add unique breach sources from LeakCheck
      result.leakcheck_sources.forEach(source => allSources.add(source));
      
      // Check for privileged account indicators
      const privilegedPatterns = ['admin', 'ceo', 'root', 'sysadmin'];
      if (result.sample_usernames.some(username => 
        privilegedPatterns.some(pattern => username.toLowerCase().includes(pattern))
      )) {
        summary.privileged_accounts_found = true;
      }
    }
  });
  
  summary.unique_breach_sources = Array.from(allSources);
  
  return summary;
}

/**
 * Main breach directory probe function
 */
export async function runBreachDirectoryProbe(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;
  
  return executeModule('breachDirectoryProbe', async () => {
    const startTime = Date.now();
    
    log(`Starting comprehensive breach probe for domain="${domain}" (BreachDirectory + LeakCheck)`);
    
    // Check for API keys
    const breachDirectoryApiKey = process.env.BREACH_DIRECTORY_API_KEY;
    const leakCheckApiKey = process.env.LEAKCHECK_API_KEY;
    
    if (!breachDirectoryApiKey && !leakCheckApiKey) {
      log('No breach API keys found - need BREACH_DIRECTORY_API_KEY or LEAKCHECK_API_KEY environment variable');
      return 0;
    }
    
    let breachData: BreachDirectoryResponse = { breached_total: 0, sample_usernames: [] };
    let leakCheckData: LeakCheckResponse = { success: false, found: 0, quota: 0, result: [] };
    
    // Query BreachDirectory if API key available
    if (breachDirectoryApiKey) {
      try {
        breachData = await queryBreachDirectory(domain, breachDirectoryApiKey);
      } catch (error) {
        log(`BreachDirectory query failed: ${(error as Error).message}`);
        breachData = { breached_total: 0, sample_usernames: [], error: (error as Error).message };
      }
    } else {
      log('BreachDirectory API key not found, skipping BreachDirectory query');
    }
    
    // Query LeakCheck if API key available  
    if (leakCheckApiKey) {
      try {
        // Add rate limiting delay if we queried BreachDirectory first
        if (breachDirectoryApiKey) {
          await new Promise(resolve => setTimeout(resolve, LEAKCHECK_RATE_LIMIT_MS));
        }
        
        leakCheckData = await queryLeakCheck(domain, leakCheckApiKey);
      } catch (error) {
        log(`LeakCheck query failed: ${(error as Error).message}`);
        leakCheckData = { success: false, found: 0, quota: 0, result: [], error: (error as Error).message };
      }
    } else {
      log('LeakCheck API key not found, skipping LeakCheck query');
    }
    
    // Analyze combined results
    const analysis = analyzeCombinedBreach(breachData, leakCheckData);
    analysis.domain = domain;
    
    // Generate summary for reporting
    const summary = generateBreachSummary([analysis]);
    
    log(`Combined breach analysis complete: BD=${analysis.breached_total}, LC=${analysis.leakcheck_total}, Total=${analysis.combined_total}`);
    
    let findingsCount = 0;
    
    // Process breach findings with proper deduplication and severity logic
    if (analysis.leakcheck_results && analysis.leakcheck_results.length > 0) {
      // Step 1: Consolidate breaches by unique user
      const consolidatedUsers = consolidateBreachesByUser(analysis.leakcheck_results);
      
      log(`Consolidated ${analysis.leakcheck_results.length} breach records into ${consolidatedUsers.length} unique users`);
      
      // Step 2: Group users by severity level
      const usersBySeverity = new Map<string, UserBreachRecord[]>();
      consolidatedUsers.forEach(user => {
        const severity = user.highestSeverity;
        if (!usersBySeverity.has(severity)) {
          usersBySeverity.set(severity, []);
        }
        usersBySeverity.get(severity)!.push(user);
      });
      
      // Step 3: Create separate artifact for each severity level (fixes severity inheritance bug)
      for (const [severityLevel, users] of usersBySeverity) {
        if (users.length === 0) continue;
        
        // Create artifact with correct severity for this specific level
        const artifactId = await insertArtifact({
          type: 'breach_directory_summary',
          val_text: `Breach probe: ${users.length} ${severityLevel.toLowerCase()} breach exposures for ${domain}`,
          severity: severityLevel as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
          meta: {
            scan_id: scanId,
            scan_module: 'breachDirectoryProbe',
            domain,
            breach_analysis: analysis,
            summary,
            breach_sources: analysis.leakcheck_sources,
            scan_duration_ms: Date.now() - startTime,
            severity_level: severityLevel,
            user_count: users.length
          }
        });
        
        // Create consolidated finding with all users of this severity
        const userList = users.map(u => u.userId).join(', ');
        const allSources = [...new Set(users.flatMap(u => u.allSources))].join(', ');
        const allExposureTypes = [...new Set(users.flatMap(u => u.exposureTypes))].join(', ');
        
        // Build timeline info
        const timelineInfo = users
          .filter(u => u.earliestBreach || u.latestBreach)
          .map(u => {
            if (u.earliestBreach === u.latestBreach) {
              return u.earliestBreach;
            } else {
              return `${u.earliestBreach || 'unknown'} to ${u.latestBreach || 'unknown'}`;
            }
          })
          .filter((timeline, index, array) => array.indexOf(timeline) === index) // dedupe
          .join(', ');
        
        // Create detailed description with user information
        const userDetails = users.length <= 5 
          ? users.map(u => u.userId).join(', ')
          : `${users.map(u => u.userId).slice(0, 5).join(', ')} and ${users.length - 5} more`;
        
        const detailedDescription = `${users.length} ${severityLevel.toLowerCase()} breach exposures found: ${userDetails}` +
          (allExposureTypes ? ` | Exposure types: ${allExposureTypes}` : '') +
          (allSources ? ` | Sources: ${allSources.slice(0, 100)}${allSources.length > 100 ? '...' : ''}` : '') +
          (timelineInfo ? ` | Timeline: ${timelineInfo}` : '');
        
        await insertFinding(
          artifactId,
          mapSeverityToFindingType(severityLevel),
          getRecommendationText(severityLevel),
          detailedDescription
        );
        
        findingsCount++;
        
        log(`Created ${severityLevel} finding for ${users.length} users: ${users.map(u => u.userId).slice(0, 5).join(', ')}${users.length > 5 ? '...' : ''}`);
      }
    }
    
    // Create summary artifact with overall stats
    const overallSeverity = analysis.combined_total >= 100 ? 'HIGH' : analysis.combined_total > 0 ? 'MEDIUM' : 'INFO';
    await insertArtifact({
      type: 'breach_directory_summary',
      val_text: `Breach probe complete: ${analysis.combined_total} total breached accounts (BD: ${analysis.breached_total}, LC: ${analysis.leakcheck_total}) for ${domain}`,
      severity: overallSeverity,
      meta: {
        scan_id: scanId,
        scan_module: 'breachDirectoryProbe',
        domain,
        breach_analysis: analysis,
        summary,
        breach_sources: analysis.leakcheck_sources,
        scan_duration_ms: Date.now() - startTime,
        is_summary: true
      }
    });
    
    const duration = Date.now() - startTime;
    log(`Breach probe completed: ${findingsCount} findings in ${duration}ms`);
    
    return findingsCount;
    
  }, { scanId, target: domain });
}
</file>

<file path="censysPlatformScan.ts">
/*
 * MODULE: censysPlatformScan.ts  (Platform API v3, memory-optimised)
 * v2.3 – resolves TS-2769, 2345, 2352, 2322
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';

/* ─────────── Configuration ─────────── */

// Don't throw error on import - handle gracefully in scan function

const CENSYS_PAT     = process.env.CENSYS_PAT as string;
const CENSYS_ORG_ID  = process.env.CENSYS_ORG_ID as string;
const DATA_DIR       = process.env.DATA_DIR ?? './data';
const MAX_HOSTS      = Number.parseInt(process.env.CENSYS_MAX_HOSTS ?? '10000', 10);
const BATCH_SIZE     = Number.parseInt(process.env.CENSYS_BATCH_SIZE ?? '25', 10);

const BASE   = 'https://api.platform.censys.io/v3/global';
const SEARCH = `${BASE}/search/query`;
const HOST   = `${BASE}/asset/host`;

const MAX_QPS = 3;
const TIMEOUT = 30_000;
const RETRIES = 4;

/* ─────────── Types ─────────── */

export interface Finding {
  source: 'censys';
  ip: string;
  hostnames: string[];
  service: string;
  evidence: unknown;
  risk: 'low' | 'medium' | 'high';
  timestamp: string;
  status: 'new' | 'existing' | 'resolved';
}

interface ScanParams {
  domain: string;
  scanId: string;
  logger?: (m: string) => void;
}

/* ─────────── Helpers ─────────── */

const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
const nowIso = () => new Date().toISOString();

const riskFrom = (svc: string, cvss?: number): 'low' | 'medium' | 'high' =>
  ['RDP', 'SSH'].includes(svc) || (cvss ?? 0) >= 9
    ? 'high'
    : (cvss ?? 0) >= 7
    ? 'medium'
    : 'low';

const logWrap = (l?: (m: string) => void) =>
  // eslint-disable-next-line no-console
  (msg: string) => (l ? l(msg) : console.log(msg));

/* ─────────── Fetch with throttle + retry ─────────── */

const tick: number[] = [];
let censysApiCallsCount = 0;

async function censysFetch<T>(
  url: string,
  init: RequestInit & { jsonBody?: unknown } = {},
  attempt = 0,
): Promise<T> {
  /* throttle */
  const now = Date.now();
  while (tick.length && now - tick[0] > 1_000) tick.shift();
  if (tick.length >= MAX_QPS) await delay(1_000 - (now - tick[0]));
  tick.push(Date.now());

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT);

  const body =
    init.jsonBody === undefined
      ? init.body
      : JSON.stringify(init.jsonBody);

  try {
    const res = await fetch(url, {
      ...init,
      method: init.method ?? 'GET',
      headers: {
        Authorization: `Bearer ${CENSYS_PAT}`,
        'X-Organization-ID': CENSYS_ORG_ID,
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(init.headers ?? {}),
      },
      body,
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    censysApiCallsCount++;
    return (await res.json()) as T;
  } catch (e) {
    if (attempt >= RETRIES) throw e;
    await delay(500 * 2 ** attempt);
    return censysFetch<T>(url, init, attempt + 1);
  }
}

/* ─────────── State persistence ─────────── */

async function stateFile(domain: string): Promise<string> {
  await fs.mkdir(DATA_DIR, { recursive: true });
  return path.join(DATA_DIR, `${sha256(domain)}.json`);
}

async function loadPrev(domain: string): Promise<Set<string>> {
  try {
    return new Set(JSON.parse(await fs.readFile(await stateFile(domain), 'utf8')));
  } catch {
    return new Set<string>();
  }
}

async function saveNow(domain: string, hashes: Set<string>): Promise<void> {
  await fs.writeFile(await stateFile(domain), JSON.stringify([...hashes]), 'utf8');
}

/* ─────────── Main scan ─────────── */

export async function runCensysPlatformScan({
  domain,
  scanId,
  logger,
}: ScanParams): Promise<Finding[]> {
  const log = logWrap(logger);
  log(`[${scanId}] Censys v3 START for ${domain}`);

  const findings: Finding[] = [];
  const hashes = new Set<string>();

  /* ---- helper: process batch of IPs ---- */
  async function processBatch(ips: string[]): Promise<void> {
    if (!ips.length) return;

    interface HostResp {
      result: {
        ip: string;
        dns?: { names: string[] };
        services: {
          port: number;
          service_name: string;
          extended_service_name: string;
          observed_at: string;
          vulnerabilities?: { cve: string; cvss?: { score: number } }[];
          tls?: { certificate: { leaf_data: { not_after: string; issuer: { common_name: string } } } };
        }[];
      };
    }

    const detail = await Promise.allSettled(
      ips.map((ip) => censysFetch<HostResp>(`${HOST}/${ip}`)),
    );

    for (const res of detail) {
      if (res.status !== 'fulfilled') {
        log(`[${scanId}] host-detail error: ${res.reason as string}`);
        continue;
      }
      const host = res.value.result;
      for (const svc of host.services) {
        const cvss = svc.vulnerabilities?.[0]?.cvss?.score;
        const risk = riskFrom(svc.service_name, cvss);

        const base: Finding = {
          source: 'censys',
          ip: host.ip,
          hostnames: host.dns?.names ?? [],
          service: svc.extended_service_name,
          evidence: {
            port: svc.port,
            observedAt: svc.observed_at,
            vulns: svc.vulnerabilities,
          },
          risk,
          timestamp: nowIso(),
          status: 'existing',
        };
        const list: Finding[] = [base];

        if (svc.service_name === 'HTTPS' && svc.tls) {
          const dLeft =
            (Date.parse(svc.tls.certificate.leaf_data.not_after) - Date.now()) /
            86_400_000;
          if (dLeft < 30) {
            list.push({
              ...base,
              service: 'TLS',
              evidence: {
                issuer: svc.tls.certificate.leaf_data.issuer.common_name,
                notAfter: svc.tls.certificate.leaf_data.not_after,
                daysLeft: dLeft,
              },
              risk: dLeft <= 7 ? 'high' : 'medium',
            });
          }
        }

        for (const f of list) {
          const h = sha256(JSON.stringify([f.ip, f.service, f.risk, f.evidence]));
          (f as unknown as any)._h = h;               // helper tag
          hashes.add(h);
          findings.push(f);
        }
      }
    }
  }

  /* ---- 1. enumerate assets ---- */
  interface SearchResp {
    result: { assets: { asset_id: string }[]; links?: { next?: string } };
  }

  let cursor: string | undefined;
  const batch: string[] = [];

  do {
    const body = {
      q: `services.tls.certificates.leaf_data.names: ${domain}`,
      per_page: 100,
      cursor,
    };
    // eslint-disable-next-line no-await-in-loop
    const data = await censysFetch<SearchResp>(SEARCH, { method: 'POST', jsonBody: body });

    for (const a of data.result.assets) {
      const ip = a.asset_id.replace(/^ip:/, '');
      if (hashes.size >= MAX_HOSTS) { cursor = undefined; break; }
      batch.push(ip);
      if (batch.length >= BATCH_SIZE) {
        // eslint-disable-next-line no-await-in-loop
        await processBatch(batch.splice(0));
      }
    }
    cursor = data.result.links?.next;
  } while (cursor);

  await processBatch(batch);

  /* ---- 2. delta status ---- */
  const prev = await loadPrev(domain);

  findings.forEach((f) => {
    const h = (f as unknown as any)._h as string;
    delete (f as unknown as any)._h;
    // eslint-disable-next-line no-param-reassign
    f.status = prev.has(h) ? 'existing' : 'new';
  });

  [...prev].filter((h) => !hashes.has(h)).forEach((h) =>
    findings.push({
      source: 'censys',
      ip: '',
      hostnames: [],
      service: '',
      evidence: { hash: h },
      risk: 'low',
      timestamp: nowIso(),
      status: 'resolved',
    }),
  );

  await saveNow(domain, hashes);

  log(
    `[${scanId}] Censys v3 DONE – ` +
      `${findings.filter((f) => f.status === 'new').length} new, ` +
      `${findings.filter((f) => f.status === 'resolved').length} resolved, ` +
      `${findings.length} total`,
  );
  return findings;
}

// Wrapper function for DealBrief worker integration
export async function runCensysScan(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;
  
  // Check if Censys credentials are available
  if (!process.env.CENSYS_PAT || !process.env.CENSYS_ORG_ID) {
    const log = logWrap();
    log(`[${scanId}] Censys scan skipped - CENSYS_PAT and CENSYS_ORG_ID not configured (saves ~$2-10 per scan)`);
    return 0;
  }
  
  const log = logWrap();
  log(`[${scanId}] Censys scan starting - estimated cost: $2-10 for typical domain (at $0.20/credit)`);
  
  try {
    const findings = await runCensysPlatformScan({ domain, scanId });
    
    // Convert Censys findings to DealBrief artifacts
    let persistedFindings = 0;
    
    for (const finding of findings) {
      if (finding.status === 'resolved') continue; // Skip resolved findings
      
      const severity = finding.risk === 'high' ? 'HIGH' : finding.risk === 'medium' ? 'MEDIUM' : 'LOW';
      
      const artifactId = await insertArtifact({
        type: 'censys_service',
        val_text: `${finding.ip} - ${finding.service}`,
        severity,
        src_url: `https://search.censys.io/hosts/${finding.ip}`,
        meta: {
          scan_id: scanId,
          scan_module: 'censysPlatformScan',
          ip: finding.ip,
          hostnames: finding.hostnames,
          service: finding.service,
          evidence: finding.evidence,
          risk: finding.risk,
          status: finding.status,
          timestamp: finding.timestamp
        }
      });
      
      await insertFinding(
        artifactId,
        'EXPOSED_SERVICE',
        `Review and secure ${finding.service} service on ${finding.ip}`,
        `Service: ${finding.service}, Risk: ${finding.risk}, Status: ${finding.status}`
      );
      
      persistedFindings++;
    }
    
    // Create summary artifact
    await insertArtifact({
      type: 'scan_summary',
      val_text: `Censys scan: ${persistedFindings} services discovered`,
      severity: 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'censysPlatformScan',
        total_findings: persistedFindings,
        new_findings: findings.filter(f => f.status === 'new').length,
        resolved_findings: findings.filter(f => f.status === 'resolved').length,
        api_calls_used: censysApiCallsCount,
        timestamp: new Date().toISOString()
      }
    });
    
    const log = logWrap();
    const estimatedCost = (censysApiCallsCount * 0.20).toFixed(2);
    log(`[${scanId}] Censys scan complete: ${persistedFindings} services, ${censysApiCallsCount} API calls used (~$${estimatedCost})`);
    
    return persistedFindings;
    
  } catch (error) {
    const log = logWrap();
    log(`[${scanId}] Censys scan failed: ${(error as Error).message}`);
    return 0;
  }
}

export default runCensysPlatformScan;
</file>

<file path="clientSecretScanner.ts">
// apps/workers/modules/clientSecretScanner.ts
// Lightweight client-side secret detector with plug-in regex support
// ------------------------------------------------------------------
import { insertArtifact, insertFinding, pool } from '../core/artifactStore.js';
import { log } from '../core/logger.js';

import fs from 'node:fs';
import yaml from 'yaml';                       // ← NEW – tiny dependency

// ------------------------------------------------------------------
// Types
// ------------------------------------------------------------------
interface ClientSecretScannerJob { scanId: string; }
interface WebAsset { url: string; content: string; }

interface SecretPattern {
  name:      string;
  regex:     RegExp;
  severity:  'CRITICAL' | 'HIGH' | 'MEDIUM';
  verify?:  (key: string) => Promise<boolean>;   // optional future hook
}
type SecretHit = { pattern: SecretPattern; match: string };

// ------------------------------------------------------------------
// 1. Curated high-precision built-in patterns
// ------------------------------------------------------------------
const BUILTIN_PATTERNS: SecretPattern[] = [
  /* Core cloud / generic */
  { name: 'Supabase Service Key', regex: /(eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}).*?service_role/gi, severity: 'CRITICAL' },
  { name: 'AWS Access Key ID',    regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,            severity: 'CRITICAL' },
  { name: 'AWS Secret Access Key',regex: /aws_secret_access_key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/g,           severity: 'CRITICAL' },
  { name: 'Google API Key',       regex: /AIza[0-9A-Za-z-_]{35}/g,                                                         severity: 'HIGH'     },
  { name: 'Stripe Live Secret',   regex: /sk_live_[0-9a-zA-Z]{24}/g,                                                       severity: 'CRITICAL' },
  { name: 'Generic API Key',      regex: /(api_key|apikey|api-key|secret|token|auth_token)["']?\s*[:=]\s*["']?([A-Za-z0-9\-_.]{20,})["']?/gi,
                                                                                                                            severity: 'HIGH'     },
  { name: 'JSON Web Token (JWT)', regex: /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}/g,               severity: 'MEDIUM'   },

  /* Popular vendor-specific */
  { name: 'Mapbox Token',         regex: /pk\.[A-Za-z0-9]{60,}/g,                                                          severity: 'HIGH'     },
  { name: 'Sentry DSN',           regex: /https:\/\/[0-9a-f]{32}@o\d+\.ingest\.sentry\.io\/\d+/gi,                        severity: 'HIGH'     },
  { name: 'Datadog API Key',      regex: /dd[0-9a-f]{32}/gi,                                                               severity: 'HIGH'     },
  { name: 'Cloudinary URL',       regex: /cloudinary:\/\/[0-9]+:[A-Za-z0-9]+@[A-Za-z0-9_-]+/gi,                           severity: 'HIGH'     },
  { name: 'Algolia Admin Key',    regex: /[a-f0-9]{32}(?:-dsn)?\.algolia\.net/gi,                                         severity: 'HIGH'     },
  { name: 'Auth0 Client Secret',  regex: /AUTH0_CLIENT_SECRET["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{30,})["']?/gi,             severity: 'CRITICAL' },
  { name: 'Bugsnag API Key',      regex: /bugsnag\.apiKey\s*=\s*['"]([A-Za-z0-9]{32})['"]/gi,                             severity: 'HIGH'     },
  { name: 'New Relic License',    regex: /NRAA-[0-9a-f]{27}/i,                                                             severity: 'HIGH'     },
  { name: 'PagerDuty API Key',    regex: /pdt[A-Z0-9]{30,32}/g,                                                            severity: 'HIGH'     },
  { name: 'Segment Write Key',    regex: /SEGMENT_WRITE_KEY["']?\s*[:=]\s*["']?([A-Za-z0-9]{32})["']?/gi,                  severity: 'HIGH'     }
];

// ------------------------------------------------------------------
// 2. Optional YAML plug-in patterns (lazy loaded with caching)
// ------------------------------------------------------------------
let cachedPluginPatterns: SecretPattern[] | null = null;

function loadPluginPatterns(): SecretPattern[] {
  // Return cached patterns if already loaded
  if (cachedPluginPatterns !== null) {
    return cachedPluginPatterns;
  }

  try {
    const p = process.env.CLIENT_SECRET_REGEX_YAML ?? '/app/config/extra-client-regex.yml';
    if (!fs.existsSync(p)) {
      cachedPluginPatterns = [];
      return cachedPluginPatterns;
    }
    
    const doc = yaml.parse(fs.readFileSync(p, 'utf8')) as Array<{name:string; regex:string; severity:string}>;
    if (!Array.isArray(doc)) {
      cachedPluginPatterns = [];
      return cachedPluginPatterns;
    }
    
    cachedPluginPatterns = doc.flatMap(e => {
      try {
        return [{
          name: e.name,
          regex: new RegExp(e.regex, 'gi'),
          severity: (e.severity ?? 'HIGH').toUpperCase() as 'CRITICAL'|'HIGH'|'MEDIUM'
        } satisfies SecretPattern];
      } catch { 
        log(`[clientSecretScanner] ⚠️  invalid regex in YAML: ${e.name}`); 
        return []; 
      }
    });
    
    log(`[clientSecretScanner] loaded ${cachedPluginPatterns.length} plugin patterns from YAML`);
    return cachedPluginPatterns;
    
  } catch (err) {
    log('[clientSecretScanner] Failed to load plug-in regexes:', (err as Error).message);
    cachedPluginPatterns = [];
    return cachedPluginPatterns;
  }
}

// Lazy initialization function
let secretPatterns: SecretPattern[] | null = null;
function getSecretPatterns(): SecretPattern[] {
  if (secretPatterns === null) {
    secretPatterns = [...BUILTIN_PATTERNS, ...loadPluginPatterns()];
    log(`[clientSecretScanner] initialized ${secretPatterns.length} total patterns (${BUILTIN_PATTERNS.length} builtin + ${cachedPluginPatterns?.length || 0} plugin)`);
  }
  return secretPatterns;
}

// ------------------------------------------------------------------
// 3. Helpers
// ------------------------------------------------------------------
function findSecrets(content: string): SecretHit[] {
  const hits: SecretHit[] = [];
  for (const pattern of getSecretPatterns()) {
    for (const m of content.matchAll(pattern.regex)) {
      hits.push({ pattern, match: m[1] || m[0] });
    }
  }
  return hits;
}

// Optional entropy fallback
function looksRandom(s: string): boolean {
  if (s.length < 24) return false;
  const freq: Record<string, number> = {};
  for (const ch of Buffer.from(s)) freq[ch] = (freq[ch] ?? 0) + 1;
  const H = Object.values(freq).reduce((h,c) => h - (c/s.length)*Math.log2(c/s.length), 0);
  return H / 8 > 0.35;
}

// ------------------------------------------------------------------
// 4. Main module
// ------------------------------------------------------------------
export async function runClientSecretScanner(job: ClientSecretScannerJob): Promise<number> {
  const { scanId } = job;
  log(`[clientSecretScanner] ▶ start – scanId=${scanId}`);

  let total = 0;

  try {
    const { rows } = await pool.query(
      `SELECT meta FROM artifacts
       WHERE type='discovered_web_assets' AND meta->>'scan_id'=$1
       ORDER BY created_at DESC LIMIT 1`, [scanId]);

    if (!rows.length || !rows[0].meta?.assets) {
      log('[clientSecretScanner] no assets to scan'); return 0;
    }

    const assets = (rows[0].meta.assets as WebAsset[])
      .filter(a => a.content && a.content !== '[binary content]');

    log(`[clientSecretScanner] scanning ${assets.length}/${rows[0].meta.assets.length} assets`);

    for (const asset of assets) {
      let hits = findSecrets(asset.content);

      // entropy heuristic – optional low-severity catch-all
      for (const m of asset.content.matchAll(/[A-Za-z0-9\/+=_-]{24,}/g)) {
        const t = m[0];
        if (looksRandom(t)) hits.push({
          pattern: { name:'High-entropy token', regex:/./, severity:'MEDIUM' },
          match: t
        });
      }

      if (!hits.length) continue;
      log(`[clientSecretScanner] ${hits.length} hit(s) → ${asset.url}`);
      let assetHits = 0;

      for (const { pattern, match } of hits) {
        if (++assetHits > 25) { log('  ↪ noisy asset, truncated'); break; }
        total++;

        const artifactId = await insertArtifact({
          type: 'secret',
          val_text: `[Client] ${pattern.name}`,
          severity: pattern.severity,
          src_url: asset.url,
          meta: { scan_id: scanId, detector:'ClientSecretScanner', pattern:pattern.name, preview:match.slice(0,50) }
        });

        await insertFinding(
          artifactId,
          'CLIENT_SIDE_SECRET_EXPOSURE',
          'Revoke / rotate this credential immediately; it is publicly downloadable.',
          `Exposed ${pattern.name} in client asset. Sample: ${match.slice(0,80)}…`
        );
      }
    }
  } catch (err) {
    log('[clientSecretScanner] error:', (err as Error).message);
  }

  await insertArtifact({
    type: 'scan_summary',
    val_text: `Client-side secret scan finished – ${total} secret(s) found`,
    severity: total ? 'HIGH' : 'INFO',
    meta: { scan_id: scanId, module:'clientSecretScanner', total }
  });

  log(`[clientSecretScanner] ▶ done – ${total} finding(s)`);
  return total;
}
</file>

<file path="cveVerifier.ts">
/* ============================================================================
 * MODULE: cveVerifier.ts (v1.1 – fixes & batching)
 * ============================================================================= */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import axios from 'axios';
import { glob } from 'glob';
import semver from 'semver';
import { log as rootLog } from '../core/logger.js';

const exec = promisify(execFile);
const log = (...args: unknown[]) => rootLog('[cveVerifier]', ...args);

export interface CVECheckInput {
  host: string;          // https://74.208.42.246:443
  serverBanner: string;  // "Apache/2.4.62 (Ubuntu)"
  cves: string[];        // [ 'CVE-2020-11023', 'CVE-2021-40438' ]
}

export interface CVECheckResult {
  id: string;
  fixedIn?: string;      // e.g. "2.4.64-1ubuntu2.4"
  verified: boolean;     // exploit actually worked
  suppressed: boolean;   // ruled out by version mapping
  error?: string;        // execution / template error
}

// Cache for vendor fix data
const ubuntuFixCache = new Map<string, string | undefined>();
const nucleiTemplateCache = new Map<string, string | undefined>();

/* ------------------------------------------------------------------------ */
/* 1.  Distribution-level version mapping                                   */
/* ------------------------------------------------------------------------ */

async function getUbuntuFixedVersion(cve: string): Promise<string | undefined> {
  // Check cache first
  if (ubuntuFixCache.has(cve)) {
    return ubuntuFixCache.get(cve);
  }

  try {
    log(`Checking Ubuntu fix data for ${cve}`);
    const { data } = await axios.get(
      `https://ubuntu.com/security/${cve}.json`,
      { timeout: 8000 }
    );
    // API returns { packages:[{fixed_version:'2.4.52-1ubuntu4.4', ...}] }
    const httpd = data.packages?.find((p: any) => p.name === 'apache2');
    const fixedVersion = httpd?.fixed_version;
    
    // Cache the result
    ubuntuFixCache.set(cve, fixedVersion);
    
    if (fixedVersion) {
      log(`Ubuntu fix found for ${cve}: ${fixedVersion}`);
    } else {
      log(`No Ubuntu fix data found for ${cve}`);
    }
    
    return fixedVersion;
  } catch (error) {
    log(`Error fetching Ubuntu fix data for ${cve}: ${(error as Error).message}`);
    ubuntuFixCache.set(cve, undefined);
    return undefined;
  }
}

async function getRHELFixedVersion(cve: string): Promise<string | undefined> {
  try {
    // RHEL/CentOS security data - simplified approach
    const { data } = await axios.get(
      `https://access.redhat.com/hydra/rest/securitydata/cve/${cve}.json`,
      { timeout: 8000 }
    );
    
    // Look for httpd package fixes
    const httpdFix = data.affected_packages?.find((pkg: any) => 
      pkg.package_name?.includes('httpd')
    );
    
    return httpdFix?.fixed_in_version;
  } catch {
    return undefined;
  }
}

async function isVersionPatched(
  bannerVersion: string | undefined,
  fixed: string | undefined
): Promise<boolean> {
  if (!bannerVersion || !fixed) return false;
  
  // Very light semver comparison – works for x.y.z-ubuntuN
  const norm = (v: string) => {
    const cleaned = v.split('-')[0].split('~')[0]; // strip "-ubuntu..." and "~" 
    const parts = cleaned.split('.').map(Number);
    return { major: parts[0] || 0, minor: parts[1] || 0, patch: parts[2] || 0 };
  };
  
  const current = norm(bannerVersion);
  const fixedVer = norm(fixed);
  
  // Compare versions
  if (current.major > fixedVer.major) return true;
  if (current.major < fixedVer.major) return false;
  
  if (current.minor > fixedVer.minor) return true;
  if (current.minor < fixedVer.minor) return false;
  
  return current.patch >= fixedVer.patch;
}

/* ------------------------------------------------------------------------ */
/* 2.  Active exploit probe via Nuclei                                      */
/* ------------------------------------------------------------------------ */

async function nucleiSupports(cve: string): Promise<string | undefined> {
  // Check cache first
  if (nucleiTemplateCache.has(cve)) {
    return nucleiTemplateCache.get(cve);
  }

  try {
    // Look for nuclei templates in common locations
    const patterns = await glob(`**/${cve}.yaml`, {
      cwd: process.env.HOME || '.',
      ignore: ['node_modules/**', '.git/**']
    });
    
    // Prefer nuclei-templates directory structure
    const preferred = patterns.find((p: string) => 
      p.includes('nuclei-templates') && (
        p.includes('/cves/') || 
        p.includes('/http/') ||
        p.includes('/vulnerabilities/')
      )
    );
    
    const templatePath = preferred || patterns[0];
    
    // Cache the result
    nucleiTemplateCache.set(cve, templatePath);
    
    if (templatePath) {
      log(`Found Nuclei template for ${cve}: ${templatePath}`);
    } else {
      log(`No Nuclei template found for ${cve}`);
    }
    
    return templatePath;
  } catch (error) {
    log(`Error searching for Nuclei template ${cve}: ${(error as Error).message}`);
    nucleiTemplateCache.set(cve, undefined);
    return undefined;
  }
}

async function runNuclei(
  host: string,
  template: string
): Promise<boolean> {
  try {
    log(`Running Nuclei template ${template} against ${host}`);
    
    const { stdout } = await exec(
      'nuclei',
      ['-t', template, '-target', host, '-json', '-silent', '-rate-limit', '5'],
      { timeout: 15_000 }
    );
    
    const hasMatch = stdout.trim().length > 0;
    
    if (hasMatch) {
      log(`Nuclei confirmed vulnerability: ${template} matched ${host}`);
    } else {
      log(`Nuclei found no vulnerability: ${template} did not match ${host}`);
    }
    
    return hasMatch;
  } catch (error) {
    log(`Nuclei execution failed for ${template}: ${(error as Error).message}`);
    return false;
  }
}

/* ------------------------------------------------------------------------ */
/* 3.  Enhanced version parsing and service detection                       */
/* ------------------------------------------------------------------------ */

function extractServiceInfo(banner: string): { service: string; version: string } | null {
  // Apache patterns
  const apacheMatch = banner.match(/Apache\/(\d+\.\d+\.\d+)/i);
  if (apacheMatch) {
    return { service: 'apache', version: apacheMatch[1] };
  }
  
  // Nginx patterns
  const nginxMatch = banner.match(/nginx\/(\d+\.\d+\.\d+)/i);
  if (nginxMatch) {
    return { service: 'nginx', version: nginxMatch[1] };
  }
  
  // IIS patterns
  const iisMatch = banner.match(/IIS\/(\d+\.\d+)/i);
  if (iisMatch) {
    return { service: 'iis', version: iisMatch[1] };
  }
  
  return null;
}

/* ------------------------------------------------------------------------ */
/* 4.  Public API                                                           */
/* ------------------------------------------------------------------------ */

async function batchEPSS(ids: string[]): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  if (!ids.length) return out;
  try {
    const { data } = await axios.get(`https://api.first.org/data/v1/epss?cve=${ids.join(',')}`, { timeout: 10_000 });
    (data.data as any[]).forEach((d: any) => { out[d.cve] = Number(d.epss) || 0; });
  } catch { ids.forEach(id => (out[id] = 0)); }
  return out;
}

export async function verifyCVEs(opts: CVECheckInput): Promise<CVECheckResult[]> {
  const results: CVECheckResult[] = [];
  const srvInfo = extractServiceInfo(opts.serverBanner);
  const bannerVersion = srvInfo?.version;
  const epssScores = await batchEPSS(opts.cves);
  for (const id of opts.cves) {
    const res: CVECheckResult = { id, verified: false, suppressed: false };
    try {
      const [ubuntuFix, rhelFix] = await Promise.all([getUbuntuFixedVersion(id), getRHELFixedVersion(id)]);
      const fixed = ubuntuFix || rhelFix;
      res.fixedIn = fixed;
      if (fixed && bannerVersion && (await isVersionPatched(bannerVersion, fixed))) {
        res.suppressed = true;
        results.push(res);
        continue;
      }
      const template = await nucleiSupports(id);
      if (template) res.verified = await runNuclei(opts.host, template);
      res.suppressed ||= epssScores[id] < 0.005 && !template; // informational only
    } catch (e) { res.error = (e as Error).message; }
    results.push(res);
  }
  return results;
}

// CVE database with version ranges and publication dates
interface CVEInfo {
  id: string;
  description: string;
  affectedVersions: string; // semver range
  publishedYear: number;
}

const serviceCVEDatabase: Record<string, CVEInfo[]> = {
  apache: [
    {
      id: 'CVE-2021-40438',
      description: 'Apache HTTP Server 2.4.48 and earlier SSRF',
      affectedVersions: '>=2.4.7 <=2.4.48',
      publishedYear: 2021
    },
    {
      id: 'CVE-2021-41773',
      description: 'Apache HTTP Server 2.4.49 Path Traversal',
      affectedVersions: '=2.4.49',
      publishedYear: 2021
    },
    {
      id: 'CVE-2021-42013',
      description: 'Apache HTTP Server 2.4.50 Path Traversal',
      affectedVersions: '<=2.4.50',
      publishedYear: 2021
    },
    {
      id: 'CVE-2020-11993',
      description: 'Apache HTTP Server 2.4.43 and earlier',
      affectedVersions: '<=2.4.43',
      publishedYear: 2020
    },
    {
      id: 'CVE-2019-0190',
      description: 'Apache HTTP Server 2.4.17 to 2.4.38',
      affectedVersions: '>=2.4.17 <=2.4.38',
      publishedYear: 2019
    },
    {
      id: 'CVE-2020-11023',
      description: 'jQuery (if mod_proxy_html enabled)',
      affectedVersions: '*', // Version-independent
      publishedYear: 2020
    }
  ],
  nginx: [
    {
      id: 'CVE-2021-23017',
      description: 'Nginx resolver off-by-one',
      affectedVersions: '>=0.6.18 <1.20.1',
      publishedYear: 2021
    },
    {
      id: 'CVE-2019-20372',
      description: 'Nginx HTTP/2 implementation',
      affectedVersions: '>=1.9.5 <=1.17.7',
      publishedYear: 2019
    },
    {
      id: 'CVE-2017-7529',
      description: 'Nginx range filter integer overflow',
      affectedVersions: '>=0.5.6 <=1.13.2',
      publishedYear: 2017
    }
  ],
  iis: [
    {
      id: 'CVE-2021-31207',
      description: 'Microsoft IIS Server Elevation of Privilege',
      affectedVersions: '*', // Version-independent for IIS
      publishedYear: 2021
    },
    {
      id: 'CVE-2020-0618',
      description: 'Microsoft IIS Server Remote Code Execution',
      affectedVersions: '*',
      publishedYear: 2020
    },
    {
      id: 'CVE-2017-7269',
      description: 'Microsoft IIS 6.0 WebDAV ScStoragePathFromUrl',
      affectedVersions: '=6.0',
      publishedYear: 2017
    }
  ]
};

// Helper function to estimate software release year
function estimateSoftwareReleaseYear(service: string, version: string): number | null {
  const versionMatch = version.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!versionMatch) return null;
  
  const [, major, minor, patch] = versionMatch.map(Number);
  
  // Service-specific release year estimates
  if (service === 'apache' && major === 2 && minor === 4) {
    if (patch >= 60) return 2024;
    if (patch >= 50) return 2021;
    if (patch >= 40) return 2019;
    if (patch >= 30) return 2017;
    if (patch >= 20) return 2015;
    if (patch >= 10) return 2013;
    return 2012;
  }
  
  if (service === 'nginx') {
    if (major >= 2) return 2023;
    if (major === 1 && minor >= 20) return 2021;
    if (major === 1 && minor >= 15) return 2019;
    if (major === 1 && minor >= 10) return 2016;
    return 2012;
  }
  
  return null; // Can't estimate
}

/**
 * Enhanced function to get CVEs for services with proper version and timeline filtering
 */
export function getCommonCVEsForService(service: string, version: string): string[] {
  const serviceLower = service.toLowerCase();
  const cveList = serviceCVEDatabase[serviceLower];
  
  if (!cveList) {
    log(`No CVE database found for service: ${service}`);
    return [];
  }

  // Clean and normalize version
  const cleanVersion = semver.coerce(version);
  if (!cleanVersion) {
    log(`Could not parse version: ${version}, returning all CVEs for ${service}`);
    return cveList.map(cve => cve.id);
  }

  // Estimate release year of this software version
  const releaseYear = estimateSoftwareReleaseYear(serviceLower, version);
  
  const applicableCVEs: string[] = [];
  
  for (const cve of cveList) {
    // Timeline validation: CVE can't affect software released after CVE publication
    if (releaseYear && releaseYear > cve.publishedYear + 1) { // +1 year buffer
      log(`CVE ${cve.id} excluded: software version ${version} (${releaseYear}) released after CVE (${cve.publishedYear})`);
      continue;
    }
    
    // Version range validation
    try {
      if (cve.affectedVersions === '*') {
        // Version-independent vulnerability
        applicableCVEs.push(cve.id);
        continue;
      }
      
      if (semver.satisfies(cleanVersion, cve.affectedVersions)) {
        applicableCVEs.push(cve.id);
        log(`CVE ${cve.id} applicable to ${service} ${version}`);
      } else {
        log(`CVE ${cve.id} not applicable: version ${version} outside range ${cve.affectedVersions}`);
      }
    } catch (error) {
      log(`Error checking version range for ${cve.id}: ${(error as Error).message}`);
      // Include on error for safety, but log the issue
      applicableCVEs.push(cve.id);
    }
  }
  
  log(`Service ${service} v${version}: ${applicableCVEs.length}/${cveList.length} CVEs applicable`);
  return applicableCVEs;
}

/**
 * Extract CVE IDs from Nuclei JSON output  
 */
export function extractCVEsFromNucleiOutput(nucleiJson: string): string[] {
  const cves = new Set<string>();
  
  try {
    const lines = nucleiJson.split('\n').filter(line => line.trim());
    
    for (const line of lines) {
      const result = JSON.parse(line);
      
      // Extract CVE from template-id or info.reference
      const templateId = result['template-id'] || result.templateID;
      const references = result.info?.reference || [];
      
      // Check template ID for CVE pattern
      const cveMatch = templateId?.match(/CVE-\d{4}-\d{4,}/);
      if (cveMatch) {
        cves.add(cveMatch[0]);
      }
      
      // Check references array
      if (Array.isArray(references)) {
        references.forEach((ref: string) => {
          const refCveMatch = ref.match(/CVE-\d{4}-\d{4,}/);
          if (refCveMatch) {
            cves.add(refCveMatch[0]);
          }
        });
      }
    }
  } catch (error) {
    log(`Error parsing Nuclei output for CVE extraction: ${(error as Error).message}`);
  }
  
  return Array.from(cves);
}

export default { verifyCVEs, getCommonCVEsForService, extractCVEsFromNucleiOutput };
</file>

<file path="dbPortScan.ts">
/*
 * =============================================================================
 * MODULE: dbPortScan.ts (Refactored v2)
 * =============================================================================
 * This module scans for exposed database services, identifies their versions,
 * and checks for known vulnerabilities and common misconfigurations.
 *
 * Key Improvements from previous version:
 * 1.  **Dependency Validation:** Checks for `nmap` and `nuclei` before running.
 * 2.  **Concurrency Control:** Scans multiple targets in parallel for performance.
 * 3.  **Dynamic Vulnerability Scanning:** Leverages `nuclei` for up-to-date
 * vulnerability and misconfiguration scanning.
 * 4.  **Enhanced Service Detection:** Uses `nmap -sV` for accurate results.
 * 5.  **Expanded Configuration Checks:** The list of nmap scripts has been expanded.
 * 6.  **Progress Tracking:** Logs scan progress for long-running jobs.
 * =============================================================================
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { XMLParser } from 'fast-xml-parser';
import { insertArtifact, insertFinding, pool } from '../core/artifactStore.js';
import { log } from '../core/logger.js';
import { runNuclei } from '../util/nucleiWrapper.js';

const exec = promisify(execFile);
const xmlParser = new XMLParser({ ignoreAttributes: false });

// REFACTOR: Concurrency control for scanning multiple targets.
const MAX_CONCURRENT_SCANS = 4;

interface Target {
  host: string;
  port: string;
}

interface JobData {
  domain: string;
  scanId?: string;
  targets?: Target[];
}

const PORT_TO_TECH_MAP: Record<string, string> = {
    '5432': 'PostgreSQL',
    '3306': 'MySQL',
    '1433': 'MSSQL',
    '27017': 'MongoDB',
    '6379': 'Redis',
    '8086': 'InfluxDB',
    '9200': 'Elasticsearch',
    '11211': 'Memcached'
};

/**
 * REFACTOR: Validates that required external tools (nmap, nuclei) are installed.
 */
async function validateDependencies(): Promise<{ nmap: boolean; nuclei: boolean }> {
    log('[dbPortScan] Validating dependencies...');
    
    // Check nmap
    const nmapCheck = await exec('nmap', ['--version']).then(() => true).catch(() => false);
    
    // Check nuclei using the wrapper
    const nucleiCheck = await runNuclei({ version: true }).then(result => result.success).catch(() => false);

    if (!nmapCheck) log('[dbPortScan] [CRITICAL] nmap binary not found. Scans will be severely limited.');
    if (!nucleiCheck) log('[dbPortScan] [CRITICAL] nuclei binary not found. Dynamic vulnerability scanning is disabled.');

    return { nmap: nmapCheck, nuclei: nucleiCheck };
}

function getCloudProvider(host: string): string | null {
  if (host.endsWith('.rds.amazonaws.com')) return 'AWS RDS';
  if (host.endsWith('.postgres.database.azure.com')) return 'Azure SQL';
  if (host.endsWith('.sql.azuresynapse.net')) return 'Azure Synapse';
  if (host.endsWith('.db.ondigitalocean.com')) return 'DigitalOcean Managed DB';
  if (host.endsWith('.cloud.timescale.com')) return 'Timescale Cloud';
  if (host.includes('.gcp.datagrid.g.aivencloud.com')) return 'Aiven (GCP)';
  if (host.endsWith('.neon.tech')) return 'Neon';
  return null;
}

async function runNmapScripts(host: string, port: string, type: string, scanId?: string): Promise<void> {
    const scripts: Record<string, string[]> = {
        'MySQL': ['mysql-info', 'mysql-enum', 'mysql-empty-password', 'mysql-vuln-cve2012-2122'],
        'PostgreSQL': ['pgsql-info', 'pgsql-empty-password'],
        'MongoDB': ['mongodb-info', 'mongodb-databases'],
        'Redis': ['redis-info'],
        'MSSQL': ['ms-sql-info', 'ms-sql-empty-password', 'ms-sql-config'],
        'InfluxDB': ['http-enum', 'http-methods'],
        'Elasticsearch': ['http-enum', 'http-methods'],
        'Memcached': ['memcached-info']
    };
    const relevantScripts = scripts[type] || ['banner', 'version']; // Default handler for unknown types

    log(`[dbPortScan] Running Nmap scripts (${relevantScripts.join(',')}) on ${host}:${port}`);
    try {
        const { stdout } = await exec('nmap', ['-Pn', '-p', port, '--script', relevantScripts.join(','), '-oX', '-', host], { timeout: 120000 });
        const result = xmlParser.parse(stdout);
        const scriptOutputs = result?.nmaprun?.host?.ports?.port?.script;
        
        if (!scriptOutputs) return;
        
        for (const script of Array.isArray(scriptOutputs) ? scriptOutputs : [scriptOutputs]) {
            if (script['@_id'] === 'mysql-empty-password' && script['@_output'].includes("root account has empty password")) {
                const artifactId = await insertArtifact({ type: 'db_auth_weakness', val_text: `MySQL root has empty password on ${host}:${port}`, severity: 'CRITICAL', meta: { scan_id: scanId, scan_module: 'dbPortScan', host, port, script: script['@_id'] } });
                await insertFinding(artifactId, 'WEAK_CREDENTIALS', 'Set a strong password for the MySQL root user immediately.', 'Empty root password on an exposed database instance.');
            }
            if (script['@_id'] === 'mongodb-databases') {
                // Handle both elem array and direct output cases
                const hasDatabaseInfo = script.elem?.some((e: any) => e.key === 'databases') || 
                                       script['@_output']?.includes('databases');
                if (hasDatabaseInfo) {
                    const artifactId = await insertArtifact({ type: 'db_misconfiguration', val_text: `MongoDB databases are listable without authentication on ${host}:${port}`, severity: 'HIGH', meta: { scan_id: scanId, scan_module: 'dbPortScan', host, port, script: script['@_id'], output: script['@_output'] } });
                    await insertFinding(artifactId, 'DATABASE_EXPOSURE', 'Configure MongoDB to require authentication to list databases and perform other operations.', 'Database enumeration possible due to missing authentication.');
                }
            }
            if (script['@_id'] === 'memcached-info' && script['@_output']?.includes('version')) {
                const artifactId = await insertArtifact({ type: 'db_service', val_text: `Memcached service exposed on ${host}:${port}`, severity: 'MEDIUM', meta: { scan_id: scanId, scan_module: 'dbPortScan', host, port, script: script['@_id'], output: script['@_output'] } });
                await insertFinding(artifactId, 'DATABASE_EXPOSURE', 'Secure Memcached by binding to localhost only and configuring SASL authentication.', 'Memcached service exposed without authentication.');
            }
        }
    } catch (error) {
        log(`[dbPortScan] Nmap script scan failed for ${host}:${port}:`, (error as Error).message);
    }
}

async function runNucleiForDb(host: string, port: string, type: string, scanId?: string): Promise<void> {
    const techTag = type.toLowerCase();
    log(`[dbPortScan] Running Nuclei scan on ${host}:${port} for technology: ${techTag}`);

    try {
        // Use the standardized nuclei wrapper with consistent configuration
        const result = await runNuclei({
            url: `${host}:${port}`,
            tags: ['cve', 'misconfiguration', 'default-credentials', techTag],
            timeout: 5,
            retries: 1,
            scanId: scanId
        });

        if (!result.success) {
            log(`[dbPortScan] Nuclei scan failed for ${host}:${port}: exit code ${result.exitCode}`);
            return;
        }

        log(`[dbPortScan] Nuclei scan completed for ${host}:${port}: ${result.results.length} findings, ${result.persistedCount || 0} persisted`);

        // Additional processing for database-specific findings if needed
        for (const vuln of result.results) {
            const cve = vuln.info.classification?.['cve-id'];
            if (cve) {
                log(`[dbPortScan] Database vulnerability found: ${vuln.info.name} (${cve}) on ${host}:${port}`);
            }
        }
    } catch (error) {
        log(`[dbPortScan] Nuclei scan failed for ${host}:${port}:`, (error as Error).message);
    }
}

/**
 * REFACTOR: Logic for scanning a single target, designed to be run concurrently.
 */
async function scanTarget(target: Target, totalTargets: number, scanId?: string, findingsCount?: { count: number }): Promise<void> {
    const { host, port } = target;
    if (!findingsCount) {
        log(`[dbPortScan] Warning: findingsCount not provided for ${host}:${port}`);
        return;
    }
    
    log(`[dbPortScan] [${findingsCount.count + 1}/${totalTargets}] Scanning ${host}:${port}...`);

    try {
        const { stdout } = await exec('nmap', ['-sV', '-Pn', '-p', port, host, '-oX', '-'], { timeout: 60000 });
        const result = xmlParser.parse(stdout);
        
        const portInfo = result?.nmaprun?.host?.ports?.port;
        if (portInfo?.state?.['@_state'] !== 'open') {
            return; // Port is closed, no finding.
        }

        const service = portInfo.service;
        const serviceProduct = service?.['@_product'] || PORT_TO_TECH_MAP[port] || 'Unknown';
        const serviceVersion = service?.['@_version'] || 'unknown';
        
        log(`[dbPortScan] [OPEN] ${host}:${port} is running ${serviceProduct} ${serviceVersion}`);
        findingsCount.count++; // Increment directly without alias
        
        const cloudProvider = getCloudProvider(host);
        const artifactId = await insertArtifact({
            type: 'db_service',
            val_text: `${serviceProduct} service exposed on ${host}:${port}`,
            severity: 'HIGH',
            meta: { host, port, service_type: serviceProduct, version: serviceVersion, cloud_provider: cloudProvider, scan_id: scanId, scan_module: 'dbPortScan' }
        });
        
        let recommendation = `Secure ${serviceProduct} by restricting network access. Use a firewall, VPN, or IP allow-listing.`;
        if (cloudProvider) {
            recommendation = `Secure ${serviceProduct} on ${cloudProvider} by reviewing security group/firewall rules and checking IAM policies.`;
        }
        await insertFinding(artifactId, 'DATABASE_EXPOSURE', recommendation, `${serviceProduct} service exposed to the internet.`);
        
        await runNmapScripts(host, port, serviceProduct, scanId);
        await runNucleiForDb(host, port, serviceProduct, scanId);

    } catch (error) {
       log(`[dbPortScan] Error scanning ${host}:${port}:`, (error as Error).message);
    }
}


/**
 * Query for dynamically discovered database targets from secret analysis
 */
async function getDiscoveredDatabaseTargets(scanId: string): Promise<Target[]> {
    const discoveredTargets: Target[] = [];
    
    try {
        log('[dbPortScan] Querying for dynamically discovered database targets...');
        
        // Query for database service targets discovered from secrets
        const dbTargetsResult = await pool.query(`
            SELECT meta FROM artifacts 
            WHERE meta->>'scan_id' = $1 
            AND type = 'db_service_target'
            ORDER BY created_at DESC
        `, [scanId]);
        
        for (const row of dbTargetsResult.rows) {
            const meta = row.meta;
            if (meta.host && meta.port) {
                discoveredTargets.push({
                    host: meta.host,
                    port: meta.port
                });
                log(`[dbPortScan] Added discovered target: ${meta.host}:${meta.port} (${meta.service_type})`);
            }
        }
        
        // Query for API endpoint targets that might be databases
        const apiTargetsResult = await pool.query(`
            SELECT meta FROM artifacts 
            WHERE meta->>'scan_id' = $1 
            AND type = 'api_endpoint_target'
            AND (meta->>'service_hint' = 'supabase' OR meta->>'service_hint' = 'aws_rds')
            ORDER BY created_at DESC
        `, [scanId]);
        
        for (const row of apiTargetsResult.rows) {
            const meta = row.meta;
            if (meta.endpoint) {
                try {
                    const url = new URL(meta.endpoint);
                    const host = url.hostname;
                    const port = url.port || (meta.service_hint === 'supabase' ? '443' : '5432');
                    
                    discoveredTargets.push({ host, port });
                    log(`[dbPortScan] Added API endpoint target: ${host}:${port} (${meta.service_hint})`);
                } catch (error) {
                    log(`[dbPortScan] Invalid endpoint URL: ${meta.endpoint}`);
                }
            }
        }
        
        log(`[dbPortScan] Found ${discoveredTargets.length} dynamically discovered database targets`);
        
    } catch (error) {
        log('[dbPortScan] Error querying for discovered targets:', (error as Error).message);
    }
    
    return discoveredTargets;
}

/**
 * Get credentials for discovered database targets
 */
async function getCredentialsForTarget(scanId: string, host: string, port: string): Promise<{username?: string, password?: string} | null> {
    try {
        const credResult = await pool.query(`
            SELECT meta FROM artifacts 
            WHERE meta->>'scan_id' = $1 
            AND type = 'credential_target'
            AND meta->>'host' = $2
            AND meta->>'port' = $3
            ORDER BY created_at DESC 
            LIMIT 1
        `, [scanId, host, port]);
        
        if (credResult.rows.length > 0) {
            const meta = credResult.rows[0].meta;
            return {
                username: meta.username,
                password: meta.password
            };
        }
    } catch (error) {
        log(`[dbPortScan] Error querying credentials for ${host}:${port}:`, (error as Error).message);
    }
    
    return null;
}

export async function runDbPortScan(job: JobData): Promise<number> {
  log('[dbPortScan] Starting enhanced database security scan for', job.domain);
  
  const { nmap } = await validateDependencies();
  if (!nmap) {
      log('[dbPortScan] CRITICAL: nmap is not available. Aborting scan.');
      return 0;
  }

  const defaultPorts = Object.keys(PORT_TO_TECH_MAP);
  let targets: Target[] = job.targets?.length ? job.targets : defaultPorts.map(port => ({ host: job.domain, port }));
  
  // NEW: Add dynamically discovered database targets from secret analysis
  if (job.scanId) {
      const discoveredTargets = await getDiscoveredDatabaseTargets(job.scanId);
      targets = [...targets, ...discoveredTargets];
      
      // Remove duplicates
      const seen = new Set<string>();
      targets = targets.filter(target => {
          const key = `${target.host}:${target.port}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
      });
      
      log(`[dbPortScan] Total targets to scan: ${targets.length} (${discoveredTargets.length} discovered from secrets)`);
  }
  
  const findingsCounter = { count: 0 };

  // REFACTOR: Process targets in concurrent chunks for performance.
  for (let i = 0; i < targets.length; i += MAX_CONCURRENT_SCANS) {
      const chunk = targets.slice(i, i + MAX_CONCURRENT_SCANS);
      await Promise.all(
          chunk.map(target => scanTarget(target, targets.length, job.scanId, findingsCounter))
      );
  }

  log('[dbPortScan] Completed database scan, found', findingsCounter.count, 'exposed services');
  await insertArtifact({
    type: 'scan_summary',
    val_text: `Database port scan completed: ${findingsCounter.count} exposed services found`,
    severity: 'INFO',
    meta: {
      scan_id: job.scanId,
      scan_module: 'dbPortScan',
      total_findings: findingsCounter.count,
      targets_scanned: targets.length,
      timestamp: new Date().toISOString()
    }
  });
  
  return findingsCounter.count;
}
</file>

<file path="denialWalletScan.ts">
/**
 * Denial-of-Wallet (DoW) Scan Module
 * 
 * Production-grade scanner that identifies endpoints that can drive unbounded cloud 
 * spending when abused, focusing on real economic impact over theoretical vulnerabilities.
 */

import axios from 'axios';
import { insertArtifact, insertFinding, pool } from '../core/artifactStore.js';
import { log as rootLog } from '../core/logger.js';
import { executeModule, apiCall } from '../util/errorHandler.js';

// Configuration constants
const TESTING_CONFIG = {
  INITIAL_RPS: 5,           // Start conservative
  MAX_RPS: 100,             // Lower ceiling for safety
  TEST_DURATION_SECONDS: 10, // Shorter bursts
  BACKOFF_MULTIPLIER: 1.5,  // Gentler scaling
  CIRCUIT_BREAKER_THRESHOLD: 0.15, // Stop at 15% failure rate
  COOLDOWN_SECONDS: 30,     // Wait between test phases
  RESPECT_ROBOTS_TXT: true  // Check robots.txt first
};

const SAFETY_CONTROLS = {
  MAX_CONCURRENT_TESTS: 3,      // Limit parallel testing
  TOTAL_REQUEST_LIMIT: 1000,    // Hard cap per scan
  TIMEOUT_SECONDS: 30,          // Request timeout
  RETRY_ATTEMPTS: 2,            // Limited retries
  BLACKLIST_STATUS: [429, 503], // Stop immediately on these
  RESPECT_HEADERS: [            // Honor protective headers
    'retry-after',
    'x-ratelimit-remaining', 
    'x-ratelimit-reset'
  ]
};

// Enhanced logging
const log = (...args: unknown[]) => rootLog('[denialWalletScan]', ...args);

interface EndpointReport {
  url: string;
  method: string;
  statusCode: number;
  responseTime: number;
  contentLength: number;
  headers: Record<string, string>;
}

interface BackendIndicators {
  responseTimeMs: number;        // >500ms suggests complex processing
  serverHeaders: string[];       // AWS/GCP/Azure headers
  errorPatterns: string[];       // Service-specific error messages
  costIndicators: string[];      // Pricing-related headers
  authPatterns: string[];        // API key patterns in responses
}

enum AuthGuardType {
  NONE = 'none',                    // No protection
  WEAK_API_KEY = 'weak_api_key',   // API key in URL/header
  SHARED_SECRET = 'shared_secret',  // Same key for all users
  CORS_BYPASS = 'cors_bypass',     // CORS misconfig allows bypass
  JWT_NONE_ALG = 'jwt_none_alg',   // JWT with none algorithm
  RATE_LIMIT_ONLY = 'rate_limit_only', // Only rate limiting
  USER_SCOPED = 'user_scoped',     // Proper per-user auth
  OAUTH_PROTECTED = 'oauth_protected' // OAuth2/OIDC
}

interface AuthBypassAnalysis {
  authType: AuthGuardType;
  bypassProbability: number;  // 0.0 - 1.0
  bypassMethods: string[];    // Specific bypass techniques
}

interface CostEstimate {
  service_detected: string;
  confidence: 'high' | 'medium' | 'low';
  base_unit_cost: number;   // $ per billing unit
  multiplier: string;       // requests | tokens | memory_mb | …
  risk_factors: string[];
}

interface DoWRiskAssessment {
  service_detected: string;
  estimated_daily_cost: number;
  auth_bypass_probability: number;
  sustained_rps: number;
  attack_complexity: 'trivial' | 'low' | 'medium' | 'high';
}

interface DoWEvidence {
  endpoint_analysis: {
    url: string;
    methods_tested: string[];
    response_patterns: string[];
    auth_attempts: string[];
  };
  
  cost_calculation: {
    service_detected: string;
    detection_method: string;
    cost_basis: string;
    confidence_level: string;
  };
  
  rate_limit_testing: {
    max_rps_achieved: number;
    test_duration_seconds: number;
    failure_threshold_hit: boolean;
    protective_responses: string[];
  };
  
  remediation_guidance: {
    immediate_actions: string[];
    long_term_fixes: string[];
    cost_cap_recommendations: string[];
  };
}

// Comprehensive service cost modeling
const SERVICE_COSTS = {
  // AI/ML Services (High Cost)
  'openai': { pattern: /openai\.com\/v1\/(chat|completions|embeddings)/, cost: 0.015, multiplier: 'tokens' },
  'anthropic': { pattern: /anthropic\.com\/v1\/(complete|messages)/, cost: 0.030, multiplier: 'tokens' },
  'cohere': { pattern: /api\.cohere\.ai\/v1/, cost: 0.020, multiplier: 'tokens' },
  'huggingface': { pattern: /api-inference\.huggingface\.co/, cost: 0.010, multiplier: 'requests' },
  
  // Cloud Functions (Variable Cost)  
  'aws_lambda': { pattern: /lambda.*invoke|x-amz-function/, cost: 0.0000208, multiplier: 'memory_mb' },
  'gcp_functions': { pattern: /cloudfunctions\.googleapis\.com/, cost: 0.0000240, multiplier: 'memory_mb' },
  'azure_functions': { pattern: /azurewebsites\.net.*api/, cost: 0.0000200, multiplier: 'memory_mb' },
  
  // Database Operations
  'dynamodb': { pattern: /dynamodb.*PutItem|UpdateItem/, cost: 0.000001, multiplier: 'requests' },
  'firestore': { pattern: /firestore\.googleapis\.com/, cost: 0.000002, multiplier: 'requests' },
  'cosmosdb': { pattern: /documents\.azure\.com/, cost: 0.000003, multiplier: 'requests' },
  
  // Storage Operations
  's3_put': { pattern: /s3.*PutObject|POST.*s3/, cost: 0.000005, multiplier: 'requests' },
  'gcs_upload': { pattern: /storage\.googleapis\.com.*upload/, cost: 0.000005, multiplier: 'requests' },
  
  // External APIs (Medium Cost)
  'stripe': { pattern: /api\.stripe\.com\/v1/, cost: 0.009, multiplier: 'requests' },
  'twilio': { pattern: /api\.twilio\.com/, cost: 0.075, multiplier: 'requests' },
  'sendgrid': { pattern: /api\.sendgrid\.com/, cost: 0.0001, multiplier: 'emails' },
  
  // Image/Video Processing
  'imagekit': { pattern: /ik\.imagekit\.io/, cost: 0.005, multiplier: 'transformations' },
  'cloudinary': { pattern: /res\.cloudinary\.com/, cost: 0.003, multiplier: 'transformations' },
  
  // Search Services
  'elasticsearch': { pattern: /elastic.*search|\.es\..*\.amazonaws\.com/, cost: 0.0001, multiplier: 'requests' },
  'algolia': { pattern: /.*-dsn\.algolia\.net/, cost: 0.001, multiplier: 'searches' },
  
  // Default for unknown state-changing endpoints
  'unknown_stateful': { pattern: /.*/, cost: 0.0005, multiplier: 'requests' }
};

/* ──────────────────────────────────────────────────────────────
 *  Dynamic volume estimation
 *  ────────────────────────────────────────────────────────────── */
const DEFAULT_TOKENS_PER_REQUEST = 750; // empirical median
const DEFAULT_MEMORY_MB         = 128; // AWS/Lambda billing quantum

function estimateDailyUnits(
  multiplier: string,
  sustainedRps: number,
  authBypassProb: number
): number {
  // Shorter exploitation window if bypass is harder
  const windowSeconds =
    authBypassProb >= 0.9 ? 86_400 :   // 24 h
    authBypassProb >= 0.5 ? 21_600 :   // 6 h
    authBypassProb >= 0.2 ?  7_200 :   // 2 h
                              1_800;   // 30 min

  switch (multiplier) {
    case 'requests':
    case 'searches':
    case 'emails':
    case 'transformations':
      return sustainedRps * windowSeconds;
    case 'tokens':
      // cost tables are per-1 000 tokens
      return (sustainedRps * windowSeconds * DEFAULT_TOKENS_PER_REQUEST) / 1_000;
    case 'memory_mb':
      // AWS bills per 128 MB-second; normalise to 128 MB baseline
      return sustainedRps * windowSeconds * (DEFAULT_MEMORY_MB / 128);
    default:
      return sustainedRps * windowSeconds;
  }
}

class DoWSafetyController {
  private requestCount = 0;
  private errorCount = 0;
  private startTime = Date.now();
  
  async checkSafetyLimits(): Promise<boolean> {
    if (this.requestCount >= SAFETY_CONTROLS.TOTAL_REQUEST_LIMIT) {
      log('Safety limit reached: maximum requests exceeded');
      return false;
    }
    
    const errorRate = this.errorCount / Math.max(this.requestCount, 1);
    if (errorRate > TESTING_CONFIG.CIRCUIT_BREAKER_THRESHOLD) {
      log(`Safety limit reached: error rate ${(errorRate * 100).toFixed(1)}% exceeds threshold`);
      return false;
    }
    
    return true;
  }
  
  recordRequest(success: boolean): void {
    this.requestCount++;
    if (!success) this.errorCount++;
  }
  
  async handleRateLimit(response: any): Promise<void> {
    const retryAfter = response.headers?.['retry-after'];
    if (retryAfter) {
      const delay = parseInt(retryAfter) * 1000;
      log(`Rate limited, waiting ${delay}ms as requested`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  async emergencyStop(reason: string): Promise<void> {
    log(`Emergency stop triggered: ${reason}`);
    // Could emit emergency artifact here
  }
}

/**
 * Get endpoint artifacts from previous scans
 */
async function getEndpointArtifacts(scanId: string): Promise<EndpointReport[]> {
  try {
    const { rows } = await pool.query(
      `SELECT meta FROM artifacts 
       WHERE type='discovered_endpoints' AND meta->>'scan_id'=$1`,
      [scanId]
    );
    
    const endpoints = rows[0]?.meta?.endpoints || [];
    log(`Found ${endpoints.length} endpoints from endpoint discovery`);
    return endpoints;
  } catch (error) {
    log(`Error querying endpoint artifacts: ${(error as Error).message}`);
    return [];
  }
}

/**
 * Analyze endpoint response for backend service indicators
 */
async function analyzeEndpointResponse(url: string): Promise<BackendIndicators> {
  const operation = async () => {
    const response = await axios.get(url, {
      timeout: SAFETY_CONTROLS.TIMEOUT_SECONDS * 1000,
      validateStatus: () => true, // Accept all status codes
      maxRedirects: 2
    });

    const indicators: BackendIndicators = {
      responseTimeMs: response.headers['x-response-time-ms'] ? 
        parseInt(response.headers['x-response-time-ms']) : 0,
      serverHeaders: [],
      errorPatterns: [],
      costIndicators: [],
      authPatterns: []
    };

    // Extract server headers that indicate cloud services
    Object.entries(response.headers).forEach(([key, value]) => {
      const lowerKey = key.toLowerCase();
      const stringValue = String(value).toLowerCase();
      
      if (lowerKey.includes('server') || lowerKey.includes('x-powered-by')) {
        indicators.serverHeaders.push(`${key}: ${value}`);
      }
      
      if (lowerKey.includes('x-amz') || lowerKey.includes('x-goog') || lowerKey.includes('x-azure')) {
        indicators.costIndicators.push(`${key}: ${value}`);
      }
      
      if (lowerKey.includes('auth') || lowerKey.includes('api-key') || lowerKey.includes('token')) {
        indicators.authPatterns.push(`${key}: ${value}`);
      }
    });

    // Analyze response body for service patterns
    if (typeof response.data === 'string') {
      const body = response.data.toLowerCase();
      
      // Error patterns that indicate specific services
      if (body.includes('lambda') || body.includes('aws')) {
        indicators.errorPatterns.push('aws_service_detected');
      }
      if (body.includes('cloudfunctions') || body.includes('gcp')) {
        indicators.errorPatterns.push('gcp_service_detected');
      }
      if (body.includes('azurewebsites') || body.includes('azure')) {
        indicators.errorPatterns.push('azure_service_detected');
      }
    }

    return indicators;
  };

  const result = await apiCall(operation, {
    moduleName: 'denialWalletScan',
    operation: 'analyzeEndpoint',
    target: url
  });

  if (!result.success) {
    // Return empty indicators if analysis fails
    return {
      responseTimeMs: 0,
      serverHeaders: [],
      errorPatterns: [],
      costIndicators: [],
      authPatterns: []
    };
  }

  return result.data;
}

/**
 * Detect service type and calculate cost estimates
 */
function detectServiceAndCalculateCost(endpoint: EndpointReport, indicators: BackendIndicators): CostEstimate {
  let detectedService = 'unknown_stateful';
  let confidence: 'high' | 'medium' | 'low' = 'low';
  
  // Try to match against known service patterns
  for (const [serviceName, serviceConfig] of Object.entries(SERVICE_COSTS)) {
    if (serviceConfig.pattern.test(endpoint.url)) {
      detectedService = serviceName;
      confidence = 'high';
      break;
    }
  }
  
  // If no direct match, use response analysis
  if (confidence === 'low' && indicators.serverHeaders.length > 0) {
    confidence = 'medium';
    if (indicators.responseTimeMs > 1000) {
      detectedService = 'complex_processing';
    }
  }
  
  const serviceConfig =
    SERVICE_COSTS[detectedService as keyof typeof SERVICE_COSTS] ??
    SERVICE_COSTS.unknown_stateful;
  const baseCost = serviceConfig.cost;
  
  const risk_factors = [];
  if (indicators.responseTimeMs > 500) risk_factors.push('High response time suggests complex processing');
  if (indicators.serverHeaders.length > 0) risk_factors.push('Cloud service headers detected');
  if (indicators.costIndicators.length > 0) risk_factors.push('Billing/quota headers present');
  
  return {
    service_detected: detectedService,
    confidence,
    base_unit_cost: baseCost,
    multiplier: serviceConfig.multiplier,
    risk_factors
  };
}

/**
 * Test authentication bypass possibilities
 */
async function classifyAuthBypass(endpoint: string): Promise<AuthBypassAnalysis> {
  const operation = async () => {
    // Test various bypass methods
    const bypassMethods: string[] = [];
    let bypassProbability = 0;
    let authType = AuthGuardType.NONE;

    // Test 1: Direct access without authentication
    try {
      const response = await axios.get(endpoint, {
        timeout: SAFETY_CONTROLS.TIMEOUT_SECONDS * 1000,
        validateStatus: () => true
      });

      if (response.status === 200) {
        bypassMethods.push('direct_access');
        bypassProbability += 0.9;
        authType = AuthGuardType.NONE;
      } else if (response.status === 401) {
        authType = AuthGuardType.USER_SCOPED;
      } else if (response.status === 403) {
        authType = AuthGuardType.RATE_LIMIT_ONLY;
        bypassProbability += 0.3;
      }
    } catch (error) {
      // Endpoint might be protected or unavailable
    }

    // Test 2: Common header bypasses
    try {
      const headerTests = [
        { 'X-Forwarded-For': '127.0.0.1' },
        { 'X-Originating-IP': '127.0.0.1' },
        { 'X-API-Key': 'test' },
        { 'Authorization': 'Bearer test' }
      ];

      for (const headers of headerTests) {
        const response = await axios.get(endpoint, {
          headers,
          timeout: SAFETY_CONTROLS.TIMEOUT_SECONDS * 1000,
          validateStatus: () => true
        });

        if (response.status === 200) {
          bypassMethods.push(`header_bypass_${Object.keys(headers)[0]}`);
          bypassProbability += 0.5;
          authType = AuthGuardType.WEAK_API_KEY;
          break;
        }
      }
    } catch (error) {
      // Header bypass tests failed
    }

    return {
      authType,
      bypassProbability: Math.min(bypassProbability, 1.0),
      bypassMethods
    };
  };

  const result = await apiCall(operation, {
    moduleName: 'denialWalletScan',
    operation: 'classifyAuthBypass',
    target: endpoint
  });

  if (!result.success) {
    // Return conservative assessment if testing fails
    return {
      authType: AuthGuardType.USER_SCOPED,
      bypassProbability: 0.1,
      bypassMethods: []
    };
  }

  return result.data;
}

/**
 * Measure sustained RPS with safety controls
 */
async function measureSustainedRPS(endpoint: string, safetyController: DoWSafetyController): Promise<number> {
  let currentRPS = TESTING_CONFIG.INITIAL_RPS;
  let sustainedRPS = 0;
  
  log(`Starting RPS testing for ${endpoint}`);
  
  while (currentRPS <= TESTING_CONFIG.MAX_RPS) {
    if (!(await safetyController.checkSafetyLimits())) {
      break;
    }
    
    log(`Testing ${currentRPS} RPS for ${TESTING_CONFIG.TEST_DURATION_SECONDS} seconds`);
    
    const requests = [];
    const interval = 1000 / currentRPS;
    let successCount = 0;
    
    // Send requests at target RPS
    for (let i = 0; i < currentRPS * TESTING_CONFIG.TEST_DURATION_SECONDS; i++) {
      const requestPromise = axios.get(endpoint, {
        timeout: SAFETY_CONTROLS.TIMEOUT_SECONDS * 1000,
        validateStatus: (status) => status < 500 // Treat 4xx as success for RPS testing
      }).then(() => {
        successCount++;
        safetyController.recordRequest(true);
        return true;
      }).catch(() => {
        safetyController.recordRequest(false);
        return false;
      });
      
      requests.push(requestPromise);
      
      // Wait for interval
      await new Promise(resolve => setTimeout(resolve, interval));
    }
    
    // Wait for all requests to complete
    await Promise.allSettled(requests);
    
    const successRate = successCount / requests.length;
    log(`RPS ${currentRPS}: ${(successRate * 100).toFixed(1)}% success rate`);
    
    // Check if we hit the circuit breaker threshold
    if (successRate < (1 - TESTING_CONFIG.CIRCUIT_BREAKER_THRESHOLD)) {
      log(`Circuit breaker triggered at ${currentRPS} RPS`);
      break;
    }
    
    sustainedRPS = currentRPS;
    currentRPS = Math.floor(currentRPS * TESTING_CONFIG.BACKOFF_MULTIPLIER);
    
    // Cooldown between test phases
    await new Promise(resolve => setTimeout(resolve, TESTING_CONFIG.COOLDOWN_SECONDS * 1000));
  }
  
  log(`Maximum sustained RPS: ${sustainedRPS}`);
  return sustainedRPS;
}

/**
 * Calculate simplified risk assessment
 */
function calculateRiskAssessment(
  costEstimate: CostEstimate,
  sustainedRPS: number,
  authBypass: AuthBypassAnalysis
): DoWRiskAssessment {

  const dailyUnits = estimateDailyUnits(
    costEstimate.multiplier,
    sustainedRPS,
    authBypass.bypassProbability
  );

  const estimated_daily_cost = dailyUnits * costEstimate.base_unit_cost;

  return {
    service_detected: costEstimate.service_detected,
    estimated_daily_cost,
    auth_bypass_probability: authBypass.bypassProbability,
    sustained_rps: sustainedRPS,
    attack_complexity: authBypass.bypassProbability > 0.8 ? 'trivial' :
                      authBypass.bypassProbability > 0.5 ? 'low' :
                      authBypass.bypassProbability > 0.2 ? 'medium' : 'high'
  };
}

/**
 * Main denial-of-wallet scan function
 */
export async function runDenialWalletScan(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;
  
  return executeModule('denialWalletScan', async () => {
    const startTime = Date.now();
    
    log(`Starting denial-of-wallet scan for domain="${domain}"`);
    
    const safetyController = new DoWSafetyController();
    let findingsCount = 0;
    
    // Get endpoints from previous discovery
    const endpoints = await getEndpointArtifacts(scanId);
    
    if (endpoints.length === 0) {
      log('No endpoints found for DoW testing');
      return 0;
    }
    
    // Filter to state-changing endpoints that could trigger costs
    const costEndpoints = endpoints.filter(ep => 
      ['POST', 'PUT', 'PATCH'].includes(ep.method) ||
      ep.url.includes('/api/') ||
      ep.url.includes('/upload') ||
      ep.url.includes('/process')
    );
    
    log(`Filtered to ${costEndpoints.length} potential cost-amplification endpoints`);
    
    // Test each endpoint for DoW vulnerability
    for (const endpoint of costEndpoints.slice(0, 10)) { // Limit for safety
      if (!(await safetyController.checkSafetyLimits())) {
        break;
      }
      
      log(`Analyzing endpoint: ${endpoint.url}`);
      
      try {
        // Analyze endpoint for backend indicators
        const indicators = await analyzeEndpointResponse(endpoint.url);
        
        // Detect service and obtain base-unit costs
        const costEstimate = detectServiceAndCalculateCost(endpoint, indicators);
        
        // Test authentication bypass
        const authBypass = await classifyAuthBypass(endpoint.url);
        
        // Measure sustained RPS (only if bypass possible)
        let sustainedRPS = 0;
        if (authBypass.bypassProbability > 0.1) {
          sustainedRPS = await measureSustainedRPS(endpoint.url, safetyController);
        }
        
        // Calculate overall risk (daily burn)
        const riskAssessment = calculateRiskAssessment(
          costEstimate,
          sustainedRPS,
          authBypass
        );
        
        // Only create findings for significant risks
        if (riskAssessment.estimated_daily_cost > 10) { // $10+ per day threshold
          // Create a simple artifact first for the finding to reference
          const artifactId = await insertArtifact({
            type: 'denial_wallet_endpoint',
            val_text: `${riskAssessment.service_detected} service detected at ${endpoint.url}`,
            severity: riskAssessment.estimated_daily_cost > 1000 ? 'CRITICAL' : 
                      riskAssessment.estimated_daily_cost > 100 ? 'HIGH' : 'MEDIUM',
            meta: {
              scan_id: scanId,
              scan_module: 'denialWalletScan',
              endpoint_url: endpoint.url,
              service_detected: riskAssessment.service_detected,
              estimated_daily_cost: riskAssessment.estimated_daily_cost,
              auth_bypass_probability: riskAssessment.auth_bypass_probability,
              sustained_rps: riskAssessment.sustained_rps,
              attack_complexity: riskAssessment.attack_complexity
            }
          });
          
          // Insert finding - let database calculate EAL values
          await insertFinding(
            artifactId,
            'DENIAL_OF_WALLET',
            `${endpoint.url} vulnerable to cost amplification attacks via ${riskAssessment.service_detected}`,
            `Implement rate limiting and authentication. Estimated daily cost: $${riskAssessment.estimated_daily_cost.toFixed(2)}`
          );
          
          findingsCount++;
        }
        
      } catch (error) {
        log(`Error analyzing endpoint ${endpoint.url}: ${(error as Error).message}`);
        continue;
      }
    }
    
    const duration = Date.now() - startTime;
    log(`Denial-of-wallet scan completed: ${findingsCount} findings in ${duration}ms`);
    
    return findingsCount;
    
  }, { scanId, target: domain });
}
</file>

<file path="dnsTwist.ts">
/*
 * =============================================================================
 * MODULE: dnsTwist.ts (Refactored v4 – full, lint‑clean)
 * =============================================================================
 * Features
 *   • Generates typosquatted domain permutations with `dnstwist`.
 *   • Excludes the submitted (legitimate) domain itself from results.
 *   • Detects wildcard DNS, MX, NS, and certificate transparency entries.
 *   • Fetches pages over HTTPS→HTTP fallback and heuristically scores phishing risk.
 *   • Detects whether the candidate domain performs an HTTP 3xx redirect back to
 *     the legitimate domain (ownership‑verification case).
 *   • Calculates a composite severity score and inserts SpiderFoot‑style
 *     Artifacts & Findings for downstream pipelines.
 *   • Concurrency limit + batch delay to stay under rate‑limits.
 * =============================================================================
 * Lint options: ESLint strict, noImplicitAny, noUnusedLocals, noUnusedParameters.
 * This file has zero lint errors under TypeScript 5.x strict mode.
 * =============================================================================
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as https from 'node:https';
import axios, { AxiosRequestConfig } from 'axios';
import { parse } from 'node-html-parser';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { log } from '../core/logger.js';
import { resolveWhoisBatch } from './whoisWrapper.js';

// -----------------------------------------------------------------------------
// Promisified helpers
// -----------------------------------------------------------------------------
const exec = promisify(execFile);

// -----------------------------------------------------------------------------
// Tuning constants
// -----------------------------------------------------------------------------
const MAX_CONCURRENT_CHECKS = 10; // Reduced from 15 to 10 for stability and OpenAI rate limiting
const DELAY_BETWEEN_BATCHES_MS = 300; // Reduced from 1000ms to 300ms  
const WHOIS_TIMEOUT_MS = 10_000; // Reduced from 30s to 10s
const MAX_DOMAINS_TO_ANALYZE = 25; // Limit total domains for speed
const ENABLE_WHOIS_ENRICHMENT = process.env.ENABLE_WHOIS_ENRICHMENT !== 'false'; // Enable by default for phishing assessment (critical for security)
const USE_WHOXY_RESOLVER = process.env.USE_WHOXY_RESOLVER !== 'false'; // Use Whoxy by default for 87% cost savings

// -----------------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------------
/** Normalises domain for equality comparison (strips www. and lowercase). */
function canonical(domain: string): string {
  return domain.toLowerCase().replace(/^www\./, '');
}

/**
 * Fast redirect detector: issues a single request with maxRedirects: 0 and
 * checks Location header for a canonical match to the origin domain.
 */
async function redirectsToOrigin(testDomain: string, originDomain: string): Promise<boolean> {
  const attempt = async (proto: 'https' | 'http'): Promise<boolean> => {
    const cfg: AxiosRequestConfig = {
      url: `${proto}://${testDomain}`,
      method: 'GET',
      maxRedirects: 0,
      validateStatus: (status) => status >= 300 && status < 400,
      timeout: 6_000,
      httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    };
    try {
      const resp = await axios(cfg);
      const location = resp.headers.location;
      if (!location) return false;
      const host = location.replace(/^https?:\/\//i, '').split('/')[0];
      return canonical(host) === canonical(originDomain);
    } catch {
      return false;
    }
  };

  return (await attempt('https')) || (await attempt('http'));
}

/** Retrieve MX and NS records using `dig` for portability across runtimes. */
async function getDnsRecords(domain: string): Promise<{ mx: string[]; ns: string[] }> {
  const records: { mx: string[]; ns: string[] } = { mx: [], ns: [] };

  try {
    const { stdout: mxOut } = await exec('dig', ['MX', '+short', domain]);
    if (mxOut.trim()) records.mx = mxOut.trim().split('\n').filter(Boolean);
  } catch {
    // ignore
  }

  try {
    const { stdout: nsOut } = await exec('dig', ['NS', '+short', domain]);
    if (nsOut.trim()) records.ns = nsOut.trim().split('\n').filter(Boolean);
  } catch {
    // ignore
  }

  return records;
}

/** Query crt.sh JSON endpoint – returns up to five unique certs. */
async function checkCTLogs(domain: string): Promise<Array<{ issuer_name: string; common_name: string }>> {
  try {
    const { data } = await axios.get(`https://crt.sh/?q=%25.${domain}&output=json`, { timeout: 10_000 });
    if (!Array.isArray(data)) return [];
    const uniq = new Map<string, { issuer_name: string; common_name: string }>();
    for (const cert of data) {
      uniq.set(cert.common_name, { issuer_name: cert.issuer_name, common_name: cert.common_name });
      if (uniq.size >= 5) break;
    }
    return [...uniq.values()];
  } catch (err) {
    log(`[dnstwist] CT‑log check failed for ${domain}:`, (err as Error).message);
    return [];
  }
}

/**
 * Wildcard DNS check: resolve a random subdomain and see if an A record exists.
 */
async function checkForWildcard(domain: string): Promise<boolean> {
  const randomSub = `${Math.random().toString(36).substring(2, 12)}.${domain}`;
  try {
    const { stdout } = await exec('dig', ['A', '+short', randomSub]);
    return stdout.trim().length > 0;
  } catch (err) {
    log(`[dnstwist] Wildcard check failed for ${domain}:`, (err as Error).message);
    return false;
  }
}

/**
 * Check if domain actually resolves (has A/AAAA records)
 */
async function checkDomainResolution(domain: string): Promise<boolean> {
  try {
    const { stdout: aRecords } = await exec('dig', ['A', '+short', domain]);
    const { stdout: aaaaRecords } = await exec('dig', ['AAAA', '+short', domain]);
    return aRecords.trim().length > 0 || aaaaRecords.trim().length > 0;
  } catch (err) {
    log(`[dnstwist] DNS resolution check failed for ${domain}:`, (err as Error).message);
    return false;
  }
}

/**
 * Check for MX records (email capability)
 */
async function checkMxRecords(domain: string): Promise<boolean> {
  try {
    const { stdout } = await exec('dig', ['MX', '+short', domain]);
    return stdout.trim().length > 0;
  } catch (err) {
    log(`[dnstwist] MX check failed for ${domain}:`, (err as Error).message);
    return false;
  }
}

/**
 * Check if domain has TLS certificate (active hosting indicator)
 */
async function checkTlsCertificate(domain: string): Promise<boolean> {
  try {
    const { data } = await axios.get(`https://crt.sh/?q=%25.${domain}&output=json`, { timeout: 10_000 });
    return Array.isArray(data) && data.length > 0;
  } catch (err) {
    log(`[dnstwist] TLS cert check failed for ${domain}:`, (err as Error).message);
    return false;
  }
}

/**
 * Detect algorithmic/unusual domain patterns AND calculate domain similarity
 */
function isAlgorithmicPattern(domain: string): { isAlgorithmic: boolean; pattern: string; confidence: number } {
  // Split-word subdomain patterns (lodgin.g-source.com)
  const splitWordPattern = /^[a-z]+\.[a-z]{1,3}-[a-z]+\.com$/i;
  if (splitWordPattern.test(domain)) {
    return { isAlgorithmic: true, pattern: 'split-word-subdomain', confidence: 0.9 };
  }

  // Hyphen insertion patterns (lodging-sou.rce.com)
  const hyphenInsertPattern = /^[a-z]+-[a-z]{1,4}\.[a-z]{3,6}\.com$/i;
  if (hyphenInsertPattern.test(domain)) {
    return { isAlgorithmic: true, pattern: 'hyphen-insertion-subdomain', confidence: 0.85 };
  }

  // Multiple dots indicating subdomain structure
  const dotCount = (domain.match(/\./g) || []).length;
  if (dotCount >= 3) {
    return { isAlgorithmic: true, pattern: 'multi-level-subdomain', confidence: 0.7 };
  }

  // Random character patterns (common in DGA)
  const randomPattern = /^[a-z]{12,20}\.com$/i;
  if (randomPattern.test(domain)) {
    return { isAlgorithmic: true, pattern: 'dga-style', confidence: 0.8 };
  }

  return { isAlgorithmic: false, pattern: 'standard', confidence: 0.1 };
}

/**
 * Calculate domain name similarity and email phishing potential
 */
function analyzeDomainSimilarity(typosquatDomain: string, originalDomain: string): {
  similarityScore: number;
  emailPhishingRisk: number;
  evidence: string[];
  domainType: 'impersonation' | 'variant' | 'related' | 'unrelated';
} {
  const evidence: string[] = [];
  let similarityScore = 0;
  let emailPhishingRisk = 0;
  
  const originalBase = originalDomain.split('.')[0].toLowerCase();
  const typosquatBase = typosquatDomain.split('.')[0].toLowerCase();
  const originalTLD = originalDomain.split('.').slice(1).join('.');
  const typosquatTLD = typosquatDomain.split('.').slice(1).join('.');
  
  // 1. Exact base match with different TLD (high impersonation risk)
  if (originalBase === typosquatBase && originalTLD !== typosquatTLD) {
    similarityScore += 90;
    emailPhishingRisk += 85;
    evidence.push(`Exact name match with different TLD: ${originalBase}.${originalTLD} vs ${typosquatBase}.${typosquatTLD}`);
  }
  
  // 2. Character-level similarity (Levenshtein-like)
  const editDistance = calculateEditDistance(originalBase, typosquatBase);
  const maxLength = Math.max(originalBase.length, typosquatBase.length);
  const charSimilarity = 1 - (editDistance / maxLength);
  
  if (charSimilarity > 0.8) {
    similarityScore += 70;
    emailPhishingRisk += 60;
    evidence.push(`High character similarity: ${Math.round(charSimilarity * 100)}% (${editDistance} character changes)`);
  } else if (charSimilarity > 0.6) {
    similarityScore += 40;
    emailPhishingRisk += 35;
    evidence.push(`Moderate character similarity: ${Math.round(charSimilarity * 100)}% (${editDistance} character changes)`);
  }
  
  // 3. Common typosquat patterns
  const typosquatPatterns = [
    // Character substitution/addition patterns
    { pattern: originalBase.replace(/o/g, '0'), type: 'character-substitution' },
    { pattern: originalBase.replace(/i/g, '1'), type: 'character-substitution' },
    { pattern: originalBase.replace(/e/g, '3'), type: 'character-substitution' },
    { pattern: originalBase + 's', type: 'pluralization' },
    { pattern: originalBase.slice(0, -1), type: 'character-omission' },
    { pattern: originalBase + originalBase.slice(-1), type: 'character-repetition' }
  ];
  
  for (const { pattern, type } of typosquatPatterns) {
    if (typosquatBase === pattern) {
      similarityScore += 60;
      emailPhishingRisk += 50;
      evidence.push(`Common typosquat pattern: ${type}`);
      break;
    }
  }
  
  // 4. Prefix/suffix additions (email phishing indicators)
  const emailPatterns = [
    'billing', 'invoice', 'payment', 'accounting', 'finance', 'admin',
    'support', 'help', 'service', 'portal', 'secure', 'verify',
    'update', 'confirm', 'notification', 'alert', 'urgent'
  ];
  
  const domainParts = typosquatBase.replace(/[-_]/g, ' ').toLowerCase();
  for (const pattern of emailPatterns) {
    if (domainParts.includes(pattern) && domainParts.includes(originalBase)) {
      emailPhishingRisk += 70;
      similarityScore += 30;
      evidence.push(`Email phishing keyword detected: "${pattern}" combined with brand name`);
      break;
    }
  }
  
  // 5. Subdomain impersonation (brand.attacker.com)
  if (typosquatDomain.toLowerCase().startsWith(originalBase + '.')) {
    similarityScore += 80;
    emailPhishingRisk += 75;
    evidence.push(`Subdomain impersonation: ${originalBase} used as subdomain`);
  }
  
  // 6. Homograph attacks (unicode lookalikes)
  const homographs = {
    'a': ['а', 'α'], 'e': ['е', 'ε'], 'o': ['о', 'ο'], 'p': ['р', 'ρ'],
    'c': ['с', 'ϲ'], 'x': ['х', 'χ'], 'y': ['у', 'γ']
  };
  
  for (const [latin, lookalikes] of Object.entries(homographs)) {
    if (originalBase.includes(latin)) {
      for (const lookalike of lookalikes) {
        if (typosquatBase.includes(lookalike)) {
          similarityScore += 85;
          emailPhishingRisk += 80;
          evidence.push(`Homograph attack detected: "${latin}" replaced with lookalike character`);
          break;
        }
      }
    }
  }
  
  // 7. Determine domain type
  let domainType: 'impersonation' | 'variant' | 'related' | 'unrelated';
  if (similarityScore >= 70) {
    domainType = 'impersonation';
  } else if (similarityScore >= 40) {
    domainType = 'variant';
  } else if (similarityScore >= 20) {
    domainType = 'related';
  } else {
    domainType = 'unrelated';
  }
  
  return { similarityScore, emailPhishingRisk, evidence, domainType };
}

/**
 * Calculate edit distance between two strings (simplified Levenshtein)
 */
function calculateEditDistance(str1: string, str2: string): number {
  const matrix: number[][] = [];
  
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  
  return matrix[str2.length][str1.length];
}

/**
 * Perform HTTP content analysis
 */
async function analyzeHttpContent(domain: string): Promise<{ 
  responds: boolean; 
  hasLoginForm: boolean; 
  redirectsToOriginal: boolean; 
  statusCode?: number;
  contentType?: string;
}> {
  const result = {
    responds: false,
    hasLoginForm: false,
    redirectsToOriginal: false,
    statusCode: undefined as number | undefined,
    contentType: undefined as string | undefined
  };

  for (const proto of ['https', 'http'] as const) {
    try {
      const response = await axios.get(`${proto}://${domain}`, {
        timeout: 10_000,
        maxRedirects: 5,
        httpsAgent: new https.Agent({ rejectUnauthorized: false }),
        validateStatus: () => true // Accept any status code
      });

      result.responds = true;
      result.statusCode = response.status;
      result.contentType = response.headers['content-type'] || '';

      // Check for login forms in HTML content
      if (typeof response.data === 'string') {
        const htmlContent = response.data.toLowerCase();
        result.hasLoginForm = htmlContent.includes('<input') && 
                             (htmlContent.includes('type="password"') || htmlContent.includes('login'));
      }

      // Check if final URL redirects to original domain
      if (response.request?.res?.responseUrl) {
        const finalUrl = response.request.res.responseUrl;
        result.redirectsToOriginal = finalUrl.includes(domain.replace(/^[^.]+\./, ''));
      }

      break; // Success, no need to try other protocol
    } catch (err) {
      // Try next protocol
      continue;
    }
  }

  return result;
}

/** Simple HTTPS→HTTP fetch with relaxed TLS for phishing sites. */
async function fetchWithFallback(domain: string): Promise<string | null> {
  for (const proto of ['https', 'http'] as const) {
    try {
      const { data } = await axios.get(`${proto}://${domain}`, {
        timeout: 7_000,
        httpsAgent: new https.Agent({ rejectUnauthorized: false }),
      });
      return data as string;
    } catch {
      /* try next protocol */
    }
  }
  return null;
}

/**
 * Get site description/snippet using Serper.dev search API
 */
async function getSiteSnippet(domain: string): Promise<{ snippet: string; title: string; error?: string }> {
  const serperApiKey = process.env.SERPER_KEY || process.env.SERPER_API_KEY;
  if (!serperApiKey) {
    log(`[dnstwist] Serper API key not configured for ${domain}`);
    return { snippet: '', title: '', error: 'SERPER_KEY not configured' };
  }

  try {
    log(`[dnstwist] 🔍 Calling Serper API for ${domain}`);
    const response = await axios.post('https://google.serper.dev/search', {
      q: `site:${domain}`,
      num: 1
    }, {
      headers: {
        'X-API-KEY': serperApiKey,
        'Content-Type': 'application/json'
      },
      timeout: 5000
    });

    const result = response.data?.organic?.[0];
    if (!result) {
      log(`[dnstwist] ❌ Serper API: No search results found for ${domain}`);
      return { snippet: '', title: '', error: 'No search results found' };
    }

    log(`[dnstwist] ✅ Serper API: Found result for ${domain} - "${result.title?.substring(0, 50)}..."`);
    return {
      snippet: result.snippet || '',
      title: result.title || '',
    };
  } catch (error) {
    log(`[dnstwist] ❌ Serper API error for ${domain}: ${(error as Error).message}`);
    return { snippet: '', title: '', error: `Serper API error: ${(error as Error).message}` };
  }
}

/**
 * Validate that input is a legitimate domain name (basic validation)
 */
function isValidDomainFormat(domain: string): boolean {
  if (!domain || typeof domain !== 'string') return false;
  
  // Basic domain validation - alphanumeric, dots, hyphens only
  const domainRegex = /^[a-zA-Z0-9.-]+$/;
  if (!domainRegex.test(domain)) return false;
  
  // Length checks
  if (domain.length > 253 || domain.length < 1) return false;
  
  // Must contain at least one dot
  if (!domain.includes('.')) return false;
  
  // No consecutive dots or hyphens
  if (domain.includes('..') || domain.includes('--')) return false;
  
  // Can't start or end with hyphen or dot
  if (domain.startsWith('-') || domain.endsWith('-') || 
      domain.startsWith('.') || domain.endsWith('.')) return false;
  
  return true;
}

/**
 * Enhanced sanitization for AI prompts to prevent injection attacks
 * Specifically designed for domain inputs and content strings
 */
function sanitizeForPrompt(input: string, isDomain: boolean = false): string {
  if (!input) return '';
  
  // For domain inputs, validate domain format first
  if (isDomain) {
    if (!isValidDomainFormat(input)) {
      // If not a valid domain, return a safe placeholder
      return '[INVALID_DOMAIN]';
    }
    // For valid domains, just do basic cleaning and length limiting
    return input.trim().slice(0, 253); // Max domain length
  }
  
  // For content strings (titles, snippets), apply comprehensive sanitization
  return input
    .replace(/["\`]/g, "'")           // Replace quotes and backticks with single quotes
    .replace(/\{|\}/g, '')            // Remove curly braces (JSON injection)
    .replace(/\[|\]/g, '')            // Remove square brackets (array injection) 
    .replace(/\n\s*\n/g, '\n')        // Collapse multiple newlines
    .replace(/^\s+|\s+$/g, '')        // Trim whitespace
    .replace(/\${.*?}/g, '')          // Remove template literals
    .replace(/<!--.*?-->/g, '')       // Remove HTML comments
    .replace(/<script.*?<\/script>/gi, '') // Remove any script tags
    .replace(/javascript:/gi, '')     // Remove javascript: URLs
    .replace(/on\w+\s*=\s*['"]/gi, '') // Remove inline event handlers
    .slice(0, 500);                   // Limit length to prevent prompt bloating
}

// OpenAI rate limiting
let openaiQueue: Promise<any> = Promise.resolve();
const OPENAI_RATE_LIMIT_DELAY = 1000; // 1 second between OpenAI calls

/**
 * Rate-limited OpenAI API call wrapper
 */
async function rateLimitedOpenAI<T>(operation: () => Promise<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    openaiQueue = openaiQueue
      .then(async () => {
        try {
          const result = await operation();
          // Add delay after each call
          await new Promise(resolve => setTimeout(resolve, OPENAI_RATE_LIMIT_DELAY));
          resolve(result);
        } catch (error) {
          reject(error);
        }
      })
      .catch(reject);
  });
}

/**
 * Use OpenAI to compare site content similarity for phishing detection
 */
async function compareContentWithAI(
  originalDomain: string, 
  typosquatDomain: string, 
  originalSnippet: string, 
  typosquatSnippet: string,
  originalTitle: string,
  typosquatTitle: string
): Promise<{ similarityScore: number; reasoning: string; confidence: number }> {
  const openaiApiKey = process.env.OPENAI_API_KEY;
  if (!openaiApiKey) {
    log(`[dnstwist] OpenAI API key not configured for ${originalDomain} vs ${typosquatDomain}`);
    return { similarityScore: 0, reasoning: 'OpenAI API key not configured', confidence: 0 };
  }

  // Sanitize all inputs to prevent prompt injection
  const safeDomain = sanitizeForPrompt(originalDomain, true);  // Mark as domain input
  const safeTyposquat = sanitizeForPrompt(typosquatDomain, true);  // Mark as domain input
  const safeOriginalTitle = sanitizeForPrompt(originalTitle, false);
  const safeTyposquatTitle = sanitizeForPrompt(typosquatTitle, false);
  const safeOriginalSnippet = sanitizeForPrompt(originalSnippet, false);
  const safeTyposquatSnippet = sanitizeForPrompt(typosquatSnippet, false);

  const prompt = `You are a cybersecurity expert analyzing typosquat domains for phishing threat potential. Compare these two domains:

ORIGINAL: ${safeDomain}
Title: ${safeOriginalTitle}
Description: ${safeOriginalSnippet}

TYPOSQUAT: ${safeTyposquat}
Title: ${safeTyposquatTitle}
Description: ${safeTyposquatSnippet}

Key threat assessment priorities:
1. ACTIVE IMPERSONATION: Is the typosquat copying/mimicking the original brand/content?
2. PARKED THREAT: Generic/minimal content on a similar domain = phishing risk potential
3. LEGITIMATE DIFFERENT BUSINESS: Established company with unique products/services

Rate the PHISHING THREAT RISK considering:
- Content impersonation (copying brand, services, design)
- Generic/parked content that could be weaponized later  
- Clear legitimate business operations that are genuinely different
- Domain sale/auction pages (registrar sale pages, marketplace listings)

SPECIAL CASE: If this is a domain registrar sale page (contains phrases like "domain for sale", "buy this domain", "domain auction", GoDaddy/Sedo listings), note this in reasoning as "domain sale page"

Respond with ONLY a JSON object:
{
  "similarityScore": 0-100,
  "reasoning": "brief threat assessment",
  "confidence": 0-100,
  "isImpersonation": true/false
}`;

  return rateLimitedOpenAI(async () => {
    try {
      log(`[dnstwist] 🤖 Calling OpenAI API to compare ${originalDomain} vs ${typosquatDomain}`);
      const response = await axios.post('https://api.openai.com/v1/chat/completions', {
        model: 'gpt-4o-mini-2024-07-18',
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 300,
        temperature: 0.1
      }, {
        headers: {
          'Authorization': `Bearer ${openaiApiKey}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000
      });

      const content = response.data.choices[0]?.message?.content;
      if (!content) {
        log(`[dnstwist] ❌ OpenAI API: No response content for ${originalDomain} vs ${typosquatDomain}`);
        return { similarityScore: 0, reasoning: 'No OpenAI response', confidence: 0 };
      }

      // Clean up markdown code blocks that OpenAI sometimes adds - handle all variations
      let cleanContent = content.trim();
      
      // More aggressive cleanup to handle all markdown variations
      // Remove markdown code block wrappers (```json ... ```)
      cleanContent = cleanContent.replace(/^```(?:json|JSON)?\s*\n?/i, '');
      cleanContent = cleanContent.replace(/\n?\s*```\s*$/i, '');
      
      // Remove any remaining backticks at start/end
      cleanContent = cleanContent.replace(/^`+/g, '').replace(/`+$/g, '');
      
      // Remove any remaining newlines or whitespace
      cleanContent = cleanContent.trim();
      
      // Additional safety: if content starts with non-JSON characters, try to find JSON block
      if (!cleanContent.startsWith('{')) {
        const jsonMatch = cleanContent.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          cleanContent = jsonMatch[0];
        }
      }
      
      const analysis = JSON.parse(cleanContent);
      log(`[dnstwist] ✅ OpenAI API: Analysis complete for ${originalDomain} vs ${typosquatDomain} - Score: ${analysis.similarityScore}%, Confidence: ${analysis.confidence}%`);
      return {
        similarityScore: analysis.similarityScore || 0,
        reasoning: analysis.reasoning || 'AI analysis completed',
        confidence: analysis.confidence || 0
      };
    } catch (error) {
      log(`[dnstwist] ❌ OpenAI API error for ${originalDomain} vs ${typosquatDomain}: ${(error as Error).message}`);
      return { similarityScore: 0, reasoning: `AI analysis failed: ${(error as Error).message}`, confidence: 0 };
    }
  });
}

/**
 * Get WHOIS data for registrar comparison using hybrid RDAP+Whoxy or legacy WhoisXML
 */
async function getWhoisData(domain: string): Promise<{ registrar?: string; registrant?: string; error?: string } | null> {
  if (!ENABLE_WHOIS_ENRICHMENT) {
    return null; // Skip WHOIS checks if disabled for cost control
  }

  if (USE_WHOXY_RESOLVER) {
    // New hybrid RDAP+Whoxy resolver (87% cost savings)
    if (!process.env.WHOXY_API_KEY) {
      return { error: 'WHOXY_API_KEY required for Whoxy resolver - configure API key or set USE_WHOXY_RESOLVER=false' };
    }
    
    try {
      const result = await resolveWhoisBatch([domain]);
      const record = result.records[0];
      
      if (!record) {
        return { error: 'No WHOIS data available' };
      }
      
      return {
        registrar: record.registrar,
        registrant: record.registrant_org || record.registrant_name || undefined
      };
      
    } catch (error) {
      return { error: `Whoxy WHOIS lookup failed: ${(error as Error).message}` };
    }
    
  } else {
    // Legacy WhoisXML API
    const apiKey = process.env.WHOISXML_API_KEY || process.env.WHOISXML_KEY;
    if (!apiKey) {
      return { error: 'WHOISXML_API_KEY required for WhoisXML resolver - configure API key or set USE_WHOXY_RESOLVER=true' };
    }

    try {
      const response = await axios.get('https://www.whoisxmlapi.com/whoisserver/WhoisService', {
        params: {
          apiKey,
          domainName: domain,
          outputFormat: 'JSON'
        },
        timeout: WHOIS_TIMEOUT_MS
      });
      
      const whoisRecord = response.data.WhoisRecord;
      if (!whoisRecord) {
        return { error: 'No WHOIS data available' };
      }
      
      return {
        registrar: whoisRecord.registrarName,
        registrant: whoisRecord.registrant?.organization || whoisRecord.registrant?.name || undefined
      };
      
    } catch (error: any) {
      if (error.response?.status === 429) {
        return { error: 'WhoisXML API rate limit exceeded' };
      }
      return { error: `WHOIS lookup failed: ${(error as Error).message}` };
    }
  }
}

/** Similarity-based phishing detection - focuses on impersonation of original site */
async function analyzeWebPageForPhishing(domain: string, originDomain: string): Promise<{ score: number; evidence: string[]; similarityScore: number; impersonationEvidence: string[] }> {
  const evidence: string[] = [];
  const impersonationEvidence: string[] = [];
  let score = 0;
  let similarityScore = 0;

  const html = await fetchWithFallback(domain);
  if (!html) return { score, evidence, similarityScore, impersonationEvidence };

  try {
    const root = parse(html);
    const pageText = root.text.toLowerCase();
    const title = (root.querySelector('title')?.text || '').toLowerCase();
    
    const originalBrand = originDomain.split('.')[0].toLowerCase();
    const originalCompanyName = originalBrand.replace(/[-_]/g, ' ');

    // SIMILARITY & IMPERSONATION DETECTION
    
    // 1. Brand name impersonation in title/content
    const brandVariations = [
      originalBrand,
      originalCompanyName,
      originalBrand.replace(/[-_]/g, ''),
      ...originalBrand.split(/[-_]/) // Handle multi-word brands
    ].filter(v => v.length > 2); // Ignore short words
    
    let brandMentions = 0;
    for (const variation of brandVariations) {
      if (title.includes(variation) || pageText.includes(variation)) {
        brandMentions++;
        impersonationEvidence.push(`References original brand: "${variation}"`);
      }
    }
    
    if (brandMentions > 0) {
      similarityScore += brandMentions * 30;
      evidence.push(`Brand impersonation detected: ${brandMentions} references to original company`);
    }

    // 2. Favicon/logo hotlinking (strong indicator of impersonation)
    const favicon = root.querySelector('link[rel*="icon" i]');
    const faviconHref = favicon?.getAttribute('href') ?? '';
    if (faviconHref.includes(originDomain)) {
      similarityScore += 50;
      evidence.push('Favicon hotlinked from original domain - clear impersonation');
      impersonationEvidence.push(`Hotlinked favicon: ${faviconHref}`);
    }

    // 3. Image hotlinking from original domain
    const images = root.querySelectorAll('img[src*="' + originDomain + '"]');
    if (images.length > 0) {
      similarityScore += 40;
      evidence.push(`${images.length} images hotlinked from original domain`);
      impersonationEvidence.push(`Hotlinked images from ${originDomain}`);
    }

    // 4. CSS/JS resource hotlinking
    const stylesheets = root.querySelectorAll(`link[href*="${originDomain}"], script[src*="${originDomain}"]`);
    if (stylesheets.length > 0) {
      similarityScore += 60;
      evidence.push('Stylesheets/scripts hotlinked from original domain - likely copied site');
      impersonationEvidence.push(`Hotlinked resources from ${originDomain}`);
    }

    // 5. Exact title match or very similar title
    if (title.length > 5) {
      // Get original site title for comparison (would need to fetch original site)
      // For now, check if title contains exact brand match
      if (title === originalBrand || title.includes(`${originalBrand} |`) || title.includes(`| ${originalBrand}`)) {
        similarityScore += 40;
        evidence.push('Page title impersonates original site');
        impersonationEvidence.push(`Suspicious title: "${title}"`);
      }
    }

    // 6. Contact form that mentions original company
    const forms = root.querySelectorAll('form');
    for (const form of forms) {
      const formText = form.text.toLowerCase();
      if (brandVariations.some(brand => formText.includes(brand))) {
        similarityScore += 35;
        evidence.push('Contact form references original company name');
        impersonationEvidence.push('Form impersonation detected');
        break;
      }
    }

    // 7. Meta description impersonation
    const metaDesc = root.querySelector('meta[name="description"]')?.getAttribute('content')?.toLowerCase() || '';
    if (metaDesc && brandVariations.some(brand => metaDesc.includes(brand))) {
      similarityScore += 25;
      evidence.push('Meta description references original brand');
      impersonationEvidence.push(`Meta description: "${metaDesc.substring(0, 100)}"`);
    }

    // ANTI-INDICATORS (reduce score for legitimate differences)
    
    // 8. Clear competitor/alternative branding
    const competitorKeywords = [
      'competitor', 'alternative', 'vs', 'compare', 'review', 'rating',
      'better than', 'similar to', 'like', 'replacement for'
    ];
    
    const hasCompetitorLanguage = competitorKeywords.some(keyword => 
      pageText.includes(keyword) || title.includes(keyword)
    );
    
    if (hasCompetitorLanguage) {
      similarityScore = Math.max(0, similarityScore - 30);
      evidence.push('Site appears to be legitimate competitor/review site');
    }

    // 9. Unique business identity
    const hasOwnBranding = root.querySelectorAll('img[alt*="logo"], .logo, #logo, [class*="brand"]').length > 0;
    if (hasOwnBranding && similarityScore < 50) {
      similarityScore = Math.max(0, similarityScore - 20);
      evidence.push('Site has its own branding elements');
    }

    // 10. Professional business content unrelated to original
    const uniqueBusinessContent = [
      'our team', 'our mission', 'our story', 'we are', 'we provide',
      'established in', 'founded in', 'years of experience'
    ].filter(phrase => pageText.includes(phrase));
    
    if (uniqueBusinessContent.length >= 2 && similarityScore < 70) {
      similarityScore = Math.max(0, similarityScore - 25);
      evidence.push('Site has unique business narrative');
    }

    // Final score is the similarity score (how much it looks like impersonation)
    score = similarityScore;

  } catch (err) {
    log(`[dnstwist] HTML parsing failed for ${domain}:`, (err as Error).message);
  }

  return { score, evidence, similarityScore, impersonationEvidence };
}

// -----------------------------------------------------------------------------
// Main execution entry
// -----------------------------------------------------------------------------
export async function runDnsTwist(job: { domain: string; scanId?: string }): Promise<number> {
  log('[dnstwist] Starting typosquat scan for', job.domain);

  const baseDom = canonical(job.domain);
  let totalFindings = 0;

  // Get WHOIS data for the original domain for comparison
  if (ENABLE_WHOIS_ENRICHMENT) {
    if (USE_WHOXY_RESOLVER) {
      log('[dnstwist] Using hybrid RDAP+Whoxy resolver (87% cheaper than WhoisXML) for original domain:', job.domain);
    } else {
      log('[dnstwist] Using WhoisXML resolver for original domain:', job.domain);
    }
  } else {
    const potentialSavings = USE_WHOXY_RESOLVER ? '$0.05-0.15' : '$0.30-0.75';
    log(`[dnstwist] WHOIS enrichment disabled (saves ~${potentialSavings} per scan) - set ENABLE_WHOIS_ENRICHMENT=true to enable`);
  }
  const originWhois = await getWhoisData(job.domain);
  
  // Get original site content for AI comparison
  log('[dnstwist] Fetching original site content for AI comparison');
  const originalSiteInfo = await getSiteSnippet(job.domain);

  try {
    const { stdout } = await exec('dnstwist', ['-r', job.domain, '--format', 'json'], { timeout: 120_000 }); // Restored to 120s - was working before
    const permutations = JSON.parse(stdout) as Array<{ domain: string; dns_a?: string[]; dns_aaaa?: string[] }>;

    // Pre‑filter: exclude canonical & non‑resolving entries
    const candidates = permutations
      .filter((p) => canonical(p.domain) !== baseDom)
      .filter((p) => (p.dns_a && p.dns_a.length) || (p.dns_aaaa && p.dns_aaaa.length));

    log(`[dnstwist] Found ${candidates.length} registered typosquat candidates to analyze`);

    // --- bucket aggregators ---
    const bucket = {
      malicious: [] as string[],
      suspicious: [] as string[],
      parked: [] as string[],
      benign: [] as string[],
    };

    // Batch processing for rate‑control
    for (let i = 0; i < candidates.length; i += MAX_CONCURRENT_CHECKS) {
      const batch = candidates.slice(i, i + MAX_CONCURRENT_CHECKS);
      log(`[dnstwist] Batch ${i / MAX_CONCURRENT_CHECKS + 1}/${Math.ceil(candidates.length / MAX_CONCURRENT_CHECKS)}`);

      await Promise.all(
        batch.map(async (entry) => {
          totalFindings += 1;

          // ---------------- Threat Classification Analysis ----------------
          log(`[dnstwist] Analyzing threat signals for ${entry.domain}`);
          
          // Pattern detection
          const algorithmicCheck = isAlgorithmicPattern(entry.domain);
          
          // Domain similarity analysis (FIRST - most important)
          const domainSimilarity = analyzeDomainSimilarity(entry.domain, job.domain);
          
          // Domain reality checks
          const [domainResolves, hasMxRecords, hasTlsCert, httpAnalysis] = await Promise.allSettled([
            checkDomainResolution(entry.domain),
            checkMxRecords(entry.domain),
            checkTlsCertificate(entry.domain),
            analyzeHttpContent(entry.domain)
          ]);
          
          const threatSignals = {
            resolves: domainResolves.status === 'fulfilled' ? domainResolves.value : false,
            hasMx: hasMxRecords.status === 'fulfilled' ? hasMxRecords.value : false,
            hasCert: hasTlsCert.status === 'fulfilled' ? hasTlsCert.value : false,
            httpContent: httpAnalysis.status === 'fulfilled' ? httpAnalysis.value : { responds: false, hasLoginForm: false, redirectsToOriginal: false },
            isAlgorithmic: algorithmicCheck.isAlgorithmic,
            algorithmicPattern: algorithmicCheck.pattern,
            confidence: algorithmicCheck.confidence,
            // Add domain similarity data
            domainSimilarity: domainSimilarity.similarityScore,
            emailPhishingRisk: domainSimilarity.emailPhishingRisk,
            domainType: domainSimilarity.domainType,
            similarityEvidence: domainSimilarity.evidence
          };

          // ---------------- Standard enrichment ----------------
          const mxRecords: string[] = [];
          const nsRecords: string[] = [];
          const ctCerts: Array<{ issuer_name: string; common_name: string }> = [];
          let wildcard = false;
          let phishing = { score: 0, evidence: [] as string[] };
          let redirects = false;
          let typoWhois: any = null;
          
          // Declare variables for special case detection
          let isDomainForSale = false;
          let redirectsToOriginal = false;
          
          // Standard DNS check (still needed for legacy data)
          const dnsResults = await getDnsRecords(entry.domain);
          mxRecords.push(...dnsResults.mx);
          nsRecords.push(...dnsResults.ns);
          
          // Quick redirect check
          redirects = await redirectsToOrigin(entry.domain, job.domain) || threatSignals.httpContent.redirectsToOriginal;
          
          // WHOIS enrichment (if enabled)
          if (ENABLE_WHOIS_ENRICHMENT) {
            typoWhois = await getWhoisData(entry.domain);
          }

          // Initialize AI analysis variables (used in artifact metadata)
          let aiContentAnalysis = { similarityScore: 0, reasoning: 'No AI analysis performed', confidence: 0 };
          let typosquatSiteInfo: { snippet: string; title: string; error?: string } = { snippet: '', title: '', error: 'Not fetched' };

          // ---------------- Registrar-based risk assessment ----------------
          let registrarMatch = false;
          let registrantMatch = false;
          let privacyProtected = false;
          const evidence: string[] = [];

          if (originWhois && typoWhois && !typoWhois.error) {
            // Compare registrars - this is the most reliable indicator
            if (originWhois.registrar && typoWhois.registrar) {
              registrarMatch = originWhois.registrar.toLowerCase() === typoWhois.registrar.toLowerCase();
              if (registrarMatch) {
                evidence.push(`Same registrar as original domain: ${typoWhois.registrar}`);
              } else {
                evidence.push(`Different registrars - Original: ${originWhois.registrar}, Typosquat: ${typoWhois.registrar}`);
              }
            }

            // Check for privacy protection patterns
            const privacyPatterns = [
              'redacted for privacy', 'whois privacy', 'domains by proxy', 'perfect privacy',
              'contact privacy inc', 'whoisguard', 'private whois', 'data protected',
              'domain privacy service', 'redacted', 'not disclosed', 'see privacyguardian.org'
            ];
            
            const isPrivacyProtected = (registrant: string) => 
              privacyPatterns.some(pattern => registrant.toLowerCase().includes(pattern));

            // Handle registrant comparison with privacy awareness
            if (originWhois.registrant && typoWhois.registrant) {
              const originPrivacy = isPrivacyProtected(originWhois.registrant);
              const typoPrivacy = isPrivacyProtected(typoWhois.registrant);
              
              if (originPrivacy && typoPrivacy) {
                // Both have privacy - rely on registrar match + additional signals
                privacyProtected = true;
                evidence.push('Both domains use privacy protection - relying on registrar comparison');
                
                // For same registrar + privacy, assume defensive if no malicious indicators
                if (registrarMatch) {
                  registrantMatch = true; // Assume same org if same registrar + both private
                  evidence.push('Likely same organization (same registrar + both privacy protected)');
                }
              } else if (!originPrivacy && !typoPrivacy) {
                // Neither has privacy - direct comparison
                registrantMatch = originWhois.registrant.toLowerCase() === typoWhois.registrant.toLowerCase();
                if (registrantMatch) {
                  evidence.push(`Same registrant as original domain: ${typoWhois.registrant}`);
                } else {
                  evidence.push(`Different registrants - Original: ${originWhois.registrant}, Typosquat: ${typoWhois.registrant}`);
                }
              } else {
                // Mixed privacy - one protected, one not (suspicious pattern)
                evidence.push('Mixed privacy protection - one domain private, one public (unusual)');
                registrantMatch = false; // Treat as different
              }
            }
          } else if (typoWhois?.error) {
            evidence.push(`WHOIS lookup failed: ${typoWhois.error}`);
          }

          // ---------------- Intelligent Threat Classification & Severity -------------
          let threatClass: 'MONITOR' | 'INVESTIGATE' | 'TAKEDOWN';
          let severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
          let threatReasoning: string[] = [];
          let score = 10;

          // Algorithmic domain handling
          if (threatSignals.isAlgorithmic) {
            threatReasoning.push(`Algorithmic pattern detected: ${threatSignals.algorithmicPattern}`);
            
            if (!threatSignals.resolves) {
              // Algorithmic + doesn't resolve = noise
              threatClass = 'MONITOR';
              severity = 'LOW';
              score = 5;
              threatReasoning.push('Domain does not resolve (NXDOMAIN) - likely algorithmic noise');
            } else if (threatSignals.resolves && !threatSignals.httpContent.responds) {
              // Resolves but no HTTP = parked
              threatClass = 'MONITOR';
              severity = 'LOW';
              score = 15;
              threatReasoning.push('Domain resolves but no HTTP response - likely parked');
            } else {
              // Algorithmic but active = low priority (per rubric)
              threatClass = 'MONITOR';
              severity = 'LOW';
              score = 25;
              threatReasoning.push('Unusual pattern but actively hosting content');
            }
          } else {
            // Real domain patterns - assess based on similarity first, then activity
            
            // STEP 1: Domain Name Similarity Analysis (Primary threat indicator)
            score = 10; // Base score
            
            if (threatSignals.domainType === 'impersonation') {
              score += 60;
              threatReasoning.push(`Domain impersonation: ${threatSignals.similarityEvidence.join(', ')}`);
            } else if (threatSignals.domainType === 'variant') {
              score += 35;
              threatReasoning.push(`Domain variant: ${threatSignals.similarityEvidence.join(', ')}`);
            } else if (threatSignals.domainType === 'related') {
              score += 15;
              threatReasoning.push(`Related domain: ${threatSignals.similarityEvidence.join(', ')}`);
            } else {
              score += 5;
              threatReasoning.push('Low domain similarity - likely unrelated business');
            }
            
            // STEP 2: Email Phishing Risk Assessment
            if (threatSignals.emailPhishingRisk > 50 && threatSignals.hasMx) {
              score += 40;
              threatReasoning.push(`High email phishing risk with MX capability`);
            } else if (threatSignals.emailPhishingRisk > 30 && threatSignals.hasMx) {
              score += 20;
              threatReasoning.push(`Moderate email phishing risk with MX capability`);
            }
            
            // STEP 3: Domain Activity Signals
            if (threatSignals.resolves) {
              score += 10;
              threatReasoning.push('Domain resolves to IP address');
            }
            
            if (threatSignals.hasMx) {
              score += 15;
              threatReasoning.push('Has MX records (email capability)');
            }
            
            if (threatSignals.hasCert) {
              score += 10;
              threatReasoning.push('Has TLS certificate (active hosting)');
            }
            
            // STEP 4: Content Similarity Analysis (Secondary verification)
            if (threatSignals.httpContent.responds) {
              score += 10;
              threatReasoning.push('Responds to HTTP requests');
              
              // Get typosquat site content for AI comparison
              typosquatSiteInfo = await getSiteSnippet(entry.domain);
              
              if (!originalSiteInfo.error && !typosquatSiteInfo.error && 
                  originalSiteInfo.snippet && typosquatSiteInfo.snippet) {
                // AI comparison available
                aiContentAnalysis = await compareContentWithAI(
                  job.domain,
                  entry.domain,
                  originalSiteInfo.snippet,
                  typosquatSiteInfo.snippet,
                  originalSiteInfo.title,
                  typosquatSiteInfo.title
                );
                
                if (aiContentAnalysis.similarityScore > 70 && aiContentAnalysis.confidence > 60) {
                  // High AI confidence of impersonation - active threat
                  score += 60;
                  threatReasoning.push(`🤖 AI-confirmed impersonation (${aiContentAnalysis.similarityScore}% similarity): ${aiContentAnalysis.reasoning}`);
                } else if (aiContentAnalysis.similarityScore > 40 && aiContentAnalysis.confidence > 50) {
                  // Moderate AI confidence - suspicious activity
                  score += 30;
                  threatReasoning.push(`🤖 AI-detected content similarity (${aiContentAnalysis.similarityScore}%): ${aiContentAnalysis.reasoning}`);
                } else if (aiContentAnalysis.similarityScore < 30 && aiContentAnalysis.confidence > 60) {
                  // AI confirms it's a different business
                  if (aiContentAnalysis.reasoning.toLowerCase().includes('parked') || 
                      aiContentAnalysis.reasoning.toLowerCase().includes('minimal content')) {
                    // Parked domain = still a threat regardless of AI confidence
                    score = Math.max(score - 10, 35);
                    threatReasoning.push(`🤖 AI-detected parked domain with phishing potential: ${aiContentAnalysis.reasoning}`);
                  } else {
                    // Legitimate different business - dramatically reduce threat
                    score = Math.max(score - 50, 15); // Much larger reduction
                    threatReasoning.push(`🤖 AI-verified legitimate different business: ${aiContentAnalysis.reasoning}`);
                  }
                }
                
                phishing = {
                  score: Math.max(threatSignals.domainSimilarity, aiContentAnalysis.similarityScore),
                  evidence: [...threatSignals.similarityEvidence, `AI Analysis: ${aiContentAnalysis.reasoning}`]
                };
              } else {
                // Fallback to basic HTML analysis for sites without search results
                const contentSimilarity = await analyzeWebPageForPhishing(entry.domain, job.domain);
                
                // Check if we got readable content
                const html = await fetchWithFallback(entry.domain);
                if (!html || html.length < 100) {
                  // Site responds but we can't read content (JS-heavy, blocked, etc.)
                  if (threatSignals.domainSimilarity > 40) {
                    // Similar domain but unreadable - flag for manual review
                    score = Math.min(score + 15, 65); // Cap at MEDIUM to avoid cost spike
                    threatReasoning.push('⚠️  Site unreadable (no search results + no HTML) - manual review recommended');
                    phishing = {
                      score: threatSignals.domainSimilarity,
                      evidence: [...threatSignals.similarityEvidence, 'Content unreadable - requires manual verification']
                    };
                  } else {
                    // Low similarity + unreadable = probably legitimate
                    score += 5;
                    threatReasoning.push('Content unreadable but domain dissimilar - likely legitimate');
                    phishing = {
                      score: threatSignals.domainSimilarity,
                      evidence: threatSignals.similarityEvidence
                    };
                  }
                } else if (contentSimilarity.similarityScore > 50) {
                  // High HTML-based content similarity
                  score += 30; // Lower than AI confidence
                  threatReasoning.push(`HTML-based impersonation detected: ${contentSimilarity.evidence.join(', ')}`);
                  phishing = {
                    score: Math.max(threatSignals.domainSimilarity, contentSimilarity.similarityScore),
                    evidence: [...threatSignals.similarityEvidence, ...contentSimilarity.evidence, ...contentSimilarity.impersonationEvidence]
                  };
                } else {
                  // Low HTML similarity
                  phishing = {
                    score: threatSignals.domainSimilarity,
                    evidence: threatSignals.similarityEvidence
                  };
                }
              }
            } else if (threatSignals.resolves && threatSignals.domainSimilarity > 40) {
              // Domain resolves but no HTTP response + similar name = suspicious
              score += 15;
              threatReasoning.push('⚠️  Domain resolves but no HTTP response - requires manual verification');
              phishing = {
                score: threatSignals.domainSimilarity,
                evidence: [...threatSignals.similarityEvidence, 'No HTTP response - manual verification needed']
              };
            } else {
              // No HTTP response but store domain similarity data
              phishing = {
                score: threatSignals.domainSimilarity,
                evidence: threatSignals.similarityEvidence
              };
            }

            // Registrar-based risk assessment
            if (registrarMatch && registrantMatch) {
              score = Math.max(score - 35, 10);
              threatReasoning.push('Same registrar and registrant (likely defensive)');
            } else if (registrarMatch && privacyProtected) {
              score = Math.max(score - 20, 15);
              threatReasoning.push('Same registrar with privacy protection (likely defensive)');
            } else if (!registrarMatch && originWhois && typoWhois && !typoWhois.error && originWhois.registrar && typoWhois.registrar) {
              score += 30;
              threatReasoning.push('Different registrar and registrant - potential threat');
            } else if ((originWhois && !typoWhois) || (typoWhois?.error) || (!originWhois?.registrar || !typoWhois?.registrar)) {
              score += 10;
              threatReasoning.push('WHOIS verification needed - unable to confirm registrar ownership');
            }

            // Redirect analysis
            if (redirects || threatSignals.httpContent.redirectsToOriginal) {
              if (registrarMatch) {
                score = Math.max(score - 25, 10);
                threatReasoning.push('Redirects to original domain with same registrar (likely legitimate)');
              } else {
                score += 15;
                threatReasoning.push('Redirects to original domain but different registrar (verify ownership)');
              }
            }

            // DOMAIN SALE PAGE DETECTION: Detect registrar sale pages and mark as LOW risk
            isDomainForSale = threatReasoning.some(r => 
              r.toLowerCase().includes('for sale') || 
              r.toLowerCase().includes('domain sale') ||
              r.toLowerCase().includes('registrar sale') ||
              r.toLowerCase().includes('domain marketplace') ||
              r.toLowerCase().includes('domain sale page') ||
              r.toLowerCase().includes('sedo') ||
              r.toLowerCase().includes('godaddy auction') ||
              r.toLowerCase().includes('domain auction')
            );

            if (isDomainForSale) {
              threatClass = 'MONITOR';
              severity = 'LOW';
              score = Math.min(score, 25); // Cap score at 25 for sale pages
              log(`[dnstwist] 🏷️ DOMAIN SALE DETECTED: ${entry.domain} marked as LOW severity - registrar sale page`);
            }

            // LEGITIMATE REDIRECT DETECTION: If domain redirects to original, it's likely legitimate
            redirectsToOriginal = threatSignals.httpContent.redirectsToOriginal || 
                                threatReasoning.some(r => r.includes('redirects to original'));
            
            if (redirectsToOriginal && !isDomainForSale) {
              threatClass = 'MONITOR';
              severity = 'INFO';
              score = Math.min(score, 20); // Very low score for redirects
              log(`[dnstwist] ↪️ LEGITIMATE REDIRECT: ${entry.domain} marked as INFO severity - redirects to original`);
            }

            // AI OVERRIDE: Only override to INFO for actual legitimate businesses with real content
            // Do NOT override parked domains - they remain threats regardless of AI analysis
            const isLegitimateBusinessByAI = threatReasoning.some(r => 
              (r.includes('AI-verified legitimate different business') ||
               r.includes('legitimate different business')) &&
              !r.includes('parked') && 
              !r.includes('minimal content') &&
              !r.includes('for sale')
            );
            
            if (isLegitimateBusinessByAI) {
              threatClass = 'MONITOR';
              severity = 'INFO';
              log(`[dnstwist] 🤖 AI OVERRIDE: ${entry.domain} marked as INFO severity - legitimate different business`);
            } else if (score >= 80 || threatSignals.httpContent.hasLoginForm) {
              threatClass = 'TAKEDOWN';
              severity = 'CRITICAL';
            } else if (score >= 50) {
              threatClass = 'TAKEDOWN';
              severity = 'HIGH';
            } else if (score >= 30) {
              threatClass = 'INVESTIGATE';
              severity = 'MEDIUM';
            } else if (score >= 20) {
              threatClass = 'MONITOR';
              severity = 'LOW';
            } else {
              threatClass = 'MONITOR';
              severity = 'LOW';
            }
          }

          // --- assign to bucket ---
          switch (severity) {
            case 'CRITICAL':
            case 'HIGH':
              bucket.malicious.push(entry.domain);
              break;
            case 'MEDIUM':
              bucket.suspicious.push(entry.domain);
              break;
            case 'LOW':
              bucket.parked.push(entry.domain);
              break;
            case 'INFO':
            default:
              bucket.benign.push(entry.domain);
          }

          // ---------------- Artifact creation ---------------
          let artifactText: string;
          
          // Create artifact text based on threat classification
          if (threatClass === 'MONITOR') {
            artifactText = `${threatSignals.isAlgorithmic ? 'Algorithmic' : 'Low-risk'} typosquat detected: ${entry.domain} [${threatClass}]`;
          } else if (threatClass === 'INVESTIGATE') {
            artifactText = `Suspicious typosquat requiring investigation: ${entry.domain} [${threatClass}]`;
          } else {
            artifactText = `Active typosquat threat detected: ${entry.domain} [${threatClass}]`;
          }
          
          // Add registrar information (even if partial)
          if (originWhois?.registrar || typoWhois?.registrar) {
            const originInfo = originWhois?.registrar || '[WHOIS verification needed]';
            const typoInfo = typoWhois?.registrar || '[WHOIS verification needed]';
            artifactText += ` | Original registrar: ${originInfo}, Typosquat registrar: ${typoInfo}`;
          }
          
          // Add registrant information (even if partial)
          if ((originWhois?.registrant || typoWhois?.registrant) && !privacyProtected) {
            const originRegInfo = originWhois?.registrant || '[WHOIS lookup failed]';
            const typoRegInfo = typoWhois?.registrant || '[WHOIS lookup failed]';
            artifactText += ` | Original registrant: ${originRegInfo}, Typosquat registrant: ${typoRegInfo}`;
          }
          
          // Add threat reasoning
          if (threatReasoning.length > 0) {
            artifactText += ` | Analysis: ${threatReasoning.join('; ')}`;
          }

          const artifactId = await insertArtifact({
            type: 'typo_domain',
            val_text: artifactText,
            severity,
            meta: {
              scan_id: job.scanId,
              scan_module: 'dnstwist',
              typosquatted_domain: entry.domain,
              ips: [...(entry.dns_a ?? []), ...(entry.dns_aaaa ?? [])],
              mx_records: mxRecords,
              ns_records: nsRecords,
              ct_log_certs: ctCerts,
              has_wildcard_dns: wildcard,
              redirects_to_origin: redirects,
              phishing_score: phishing.score,
              phishing_evidence: phishing.evidence,
              severity_score: score,
              // WHOIS intelligence
              registrar_match: registrarMatch,
              registrant_match: registrantMatch,
              privacy_protected: privacyProtected,
              typo_registrar: typoWhois?.registrar,
              typo_registrant: typoWhois?.registrant,
              origin_registrar: originWhois?.registrar,
              origin_registrant: originWhois?.registrant,
              whois_evidence: evidence,
              // Threat classification data
              threat_class: threatClass,
              threat_reasoning: threatReasoning,
              threat_signals: {
                resolves: threatSignals.resolves,
                has_mx: threatSignals.hasMx,
                has_cert: threatSignals.hasCert,
                responds_http: threatSignals.httpContent.responds,
                has_login_form: threatSignals.httpContent.hasLoginForm,
                redirects_to_original: threatSignals.httpContent.redirectsToOriginal,
                is_algorithmic: threatSignals.isAlgorithmic,
                algorithmic_pattern: threatSignals.algorithmicPattern,
                pattern_confidence: threatSignals.confidence,
                http_status: threatSignals.httpContent.statusCode,
                content_type: threatSignals.httpContent.contentType
              },
              // AI Content Analysis
              ai_content_analysis: aiContentAnalysis,
              original_site_info: originalSiteInfo,
              typosquat_site_info: typosquatSiteInfo
            },
          });

          // ---------------- Finding creation ----------------
          // Create findings for all severity levels, but with different types
          let findingType: string;
          let description: string;
          let recommendation: string;

          // Determine finding type and recommendation based on threat classification
          if (severity === 'INFO') {
            // AI-verified legitimate different business OR legitimate redirect
            if (redirectsToOriginal) {
              findingType = 'LEGITIMATE_REDIRECT';
              recommendation = `Low Priority: Domain redirects to original - verify it's officially managed by the brand owner`;
              description = `LEGITIMATE REDIRECT: ${entry.domain} redirects to the original domain - likely legitimate business operation or redirect service. ${threatReasoning.join('. ')}`;
            } else {
              findingType = 'SIMILAR_DOMAIN';
              recommendation = `Monitor for potential brand confusion - ${entry.domain} is a legitimate different business`;
              description = `SIMILAR DOMAIN: ${entry.domain} is a legitimate different business with similar domain name. ${threatReasoning.join('. ')}`;
            }
          } else if (threatClass === 'MONITOR') {
            if (isDomainForSale) {
              findingType = 'DOMAIN_FOR_SALE';
              recommendation = `Monitor: Domain is currently for sale - verify if acquired by malicious actors in the future`;
              description = `DOMAIN FOR SALE: ${entry.domain} appears to be a domain registrar sale page - low immediate threat but monitor for future acquisition. ${threatReasoning.join('. ')}`;
            } else {
              findingType = threatSignals.isAlgorithmic ? 'ALGORITHMIC_TYPOSQUAT' : 'PARKED_TYPOSQUAT';
              recommendation = `Monitor for changes - add to watchlist and check monthly for activation`;
              
              if (threatSignals.isAlgorithmic) {
                description = `ALGORITHMIC TYPOSQUAT: ${entry.domain} shows automated generation pattern (${threatSignals.algorithmicPattern}). ${threatReasoning.join('. ')}`;
              } else {
                description = `LOW-RISK TYPOSQUAT: ${entry.domain} identified for monitoring. ${threatReasoning.join('. ')}`;
              }
            }
            
          } else if (threatClass === 'INVESTIGATE') {
            findingType = 'SUSPICIOUS_TYPOSQUAT';
            recommendation = `Investigate domain ${entry.domain} further - verify ownership, check content, and assess for active abuse`;
            description = `SUSPICIOUS TYPOSQUAT: ${entry.domain} requires investigation due to suspicious indicators. ${threatReasoning.join('. ')}`;
            
          } else { // TAKEDOWN - All malicious typosquats use same finding type
            findingType = 'MALICIOUS_TYPOSQUAT';
            
            if (threatSignals.httpContent.hasLoginForm) {
              recommendation = `Immediate takedown recommended - active phishing site detected with login forms at ${entry.domain}`;
              description = `MALICIOUS TYPOSQUAT (Phishing Site): ${entry.domain} is hosting login forms and actively targeting your customers. ${threatReasoning.join('. ')}`;
            } else if (threatSignals.hasMx && !registrarMatch && !threatReasoning.some(r => r.includes('AI-verified legitimate different business'))) {
              // Only label as email phishing if AI hasn't verified it's a legitimate business
              recommendation = `Urgent: Initiate takedown procedures - email phishing capability detected at ${entry.domain}`;
              description = `MALICIOUS TYPOSQUAT (Email Phishing): ${entry.domain} has email functionality and different registrar - high risk for email-based attacks. ${threatReasoning.join('. ')}`;
            } else {
              recommendation = `Initiate takedown procedures - active threat with suspicious indicators at ${entry.domain}`;
              description = `MALICIOUS TYPOSQUAT (Active Threat): ${entry.domain} showing suspicious activity requiring immediate action. ${threatReasoning.join('. ')}`;
            }
          }

          // Add registrar details to description
          let registrarDetails = '';
          if (originWhois?.registrar && typoWhois?.registrar) {
            registrarDetails = ` | Original registrar: ${originWhois.registrar}, Typosquat registrar: ${typoWhois.registrar}`;
          } else if (originWhois?.registrar) {
            registrarDetails = ` | Original registrar: ${originWhois.registrar}, Typosquat registrar: [WHOIS verification needed]`;
          } else if (typoWhois?.registrar) {
            registrarDetails = ` | Original registrar: [WHOIS verification needed], Typosquat registrar: ${typoWhois.registrar}`;
          } else {
            registrarDetails = ` | WHOIS verification needed for both domains`;
          }

          let registrantDetails = '';
          if (originWhois?.registrant && typoWhois?.registrant && !privacyProtected) {
            registrantDetails = ` | Original registrant: ${originWhois.registrant}, Typosquat registrant: ${typoWhois.registrant}`;
          } else if (originWhois?.registrant && !privacyProtected) {
            registrantDetails = ` | Original registrant: ${originWhois.registrant}, Typosquat registrant: [WHOIS verification needed]`;
          } else if (typoWhois?.registrant && !privacyProtected) {
            registrantDetails = ` | Original registrant: [WHOIS verification needed], Typosquat registrant: ${typoWhois.registrant}`;
          }

          description += registrarDetails + registrantDetails;

          await insertFinding(
            artifactId,
            findingType,
            recommendation,
            description,
          );
        })
      );

      if (i + MAX_CONCURRENT_CHECKS < candidates.length) {
        await new Promise((res) => setTimeout(res, DELAY_BETWEEN_BATCHES_MS));
      }
    }

    // --- consolidated Findings ---
    const totalAnalysed = Object.values(bucket).reduce((n, arr) => n + arr.length, 0);

    // Create a summary artifact for consolidated findings
    const summaryArtifactId = await insertArtifact({
      type: 'typosquat_summary',
      val_text: `DNS Twist scan summary for ${job.domain}: ${totalAnalysed} domains analyzed across 4 risk categories`,
      severity: totalAnalysed > 0 ? 'INFO' : 'LOW',
      meta: {
        scan_id: job.scanId,
        scan_module: 'dnstwist',
        total_analyzed: totalAnalysed,
        malicious_count: bucket.malicious.length,
        suspicious_count: bucket.suspicious.length,
        parked_count: bucket.parked.length,
        benign_count: bucket.benign.length,
      },
    });

    const makeFinding = async (
      type: string,
      sev: 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFO',
      domains: string[],
      reason: string,
    ) => {
      if (!domains.length) return;
      await insertFinding(
        summaryArtifactId,
        type,
        reason,
        `**${domains.length} / ${totalAnalysed} domains**\n\n` +
        domains.map(d => `• ${d}`).join('\n')
      );
    };

    await makeFinding(
      'MALICIOUS_TYPOSQUAT_GROUP',
      'CRITICAL',
      bucket.malicious,
      'Immediate takedown recommended for these active phishing or high-risk domains.'
    );

    await makeFinding(
      'SUSPICIOUS_TYPOSQUAT_GROUP',
      'MEDIUM',
      bucket.suspicious,
      'Investigate these domains – suspicious similarity or activity detected.'
    );

    await makeFinding(
      'PARKED_TYPOSQUAT_GROUP',
      'LOW',
      bucket.parked,
      'Domains are parked / for sale or resolve with no content. Monitor for changes.'
    );

    await makeFinding(
      'BENIGN_TYPOSQUAT_GROUP',
      'INFO',
      bucket.benign,
      'Legitimate redirects or unrelated businesses with similar names.'
    );

    log('[dnstwist] Scan completed –', totalFindings, 'domains analysed');
    return totalFindings;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      log('[dnstwist] dnstwist binary not found – install it or add to PATH');
      await insertArtifact({
        type: 'scan_error',
        val_text: 'dnstwist command not found',
        severity: 'INFO',
        meta: { scan_id: job.scanId, scan_module: 'dnstwist' },
      });
    } else {
      log('[dnstwist] Unhandled error:', (err as Error).message);
    }
    return 0;
  }
}
</file>

<file path="documentExposure.ts">
/* =============================================================================
 * MODULE: documentExposure.ts  (Security-Hardened Refactor v8 – false‑positive tuned)
 * =============================================================================
 * Purpose: Discover truly exposed documents (PDF/DOCX/XLSX) linked to a brand
 *          while eliminating noisy public webpages (e.g. LinkedIn profiles).
 *
 *  ➟  Skips common social/media hosts (LinkedIn, X/Twitter, Facebook, Instagram).
 *  ➟  Processes ONLY well‑defined, downloadable doc formats – PDF/DOCX/XLSX.
 *  ➟  Adds ALLOWED_MIME and SKIP_HOSTS guards in downloadAndAnalyze().
 *  ➟  Maintains v7 lint fixes (strict booleans, renamed `conf`, etc.).
 * =============================================================================
 */

import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import * as crypto from 'node:crypto';
import { createRequire } from 'node:module';
import axios, { AxiosResponse } from 'axios';
import { fileTypeFromBuffer } from 'file-type';
import { getDocument, GlobalWorkerOptions } from 'pdfjs-dist';
import luhn from 'luhn';
import mammoth from 'mammoth';
import xlsx from 'xlsx';
import yauzl from 'yauzl';
import { URL } from 'node:url';
import { OpenAI } from 'openai';

import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { uploadFile } from '../core/objectStore.js';
import { log } from '../core/logger.js';

/* ---------------------------------------------------------------------------
 * 0.  Types & Interfaces
 * ------------------------------------------------------------------------ */

interface BrandSignature {
  primary_domain: string;
  alt_domains: string[];
  core_terms: string[];
  excluded_terms: string[];
  industry?: string;
}

interface AnalysisResult {
  sha256: string;
  mimeInfo: { reported: string; verified: string };
  localPath: string;
  sensitivity: number;
  findings: string[];
  language: string;
}

interface IndustryGuard {
  industry: string;
  conf: number;
}

/* ---------------------------------------------------------------------------
 * 1.  Constants / Runtime Config
 * ------------------------------------------------------------------------ */

const SERPER_URL = 'https://google.serper.dev/search';
const FILE_PROCESSING_TIMEOUT_MS = 30_000;
const MAX_UNCOMPRESSED_ZIP_SIZE_MB = 50;
const MAX_CONTENT_ANALYSIS_BYTES = 250_000;
const MAX_WORKER_MEMORY_MB = 512;

const GPT_MODEL = process.env.OPENAI_MODEL ?? 'gpt-4o-mini-2024-07-18';

const GPT_REL_SYS =
  'You are a binary relevance filter for brand-exposure scans. Reply ONLY with YES or NO.';
const GPT_IND_SYS =
  'You are a company profiler. Return strict JSON: {"industry":"<label>","conf":0-1}. No prose.';

const MAX_REL_TOKENS = 1;
const MAX_IND_TOKENS = 20;
const MAX_CONTENT_FOR_GPT = 3_000;

// New: only treat these MIME types as true “documents”
const ALLOWED_MIME = new Set<string>([
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
]);

// New: skip obvious public‑profile / non‑doc hosts
const SKIP_HOSTS = new Set<string>([
  'linkedin.com',
  'www.linkedin.com',
  'twitter.com',
  'x.com',
  'facebook.com',
  'instagram.com'
]);

/* ---------------------------------------------------------------------------
 * 2.  pdf.js worker initialisation
 * ------------------------------------------------------------------------ */

const require = createRequire(import.meta.url);
try {
  const pdfWorkerPath = require.resolve('pdfjs-dist/build/pdf.worker.mjs');
  GlobalWorkerOptions.workerSrc = pdfWorkerPath;
} catch (err) {
  log('[documentExposure] pdf.worker.mjs not found:', (err as Error).message);
}

/* ---------------------------------------------------------------------------
 * 3.  Brand-Signature Loader
 * ------------------------------------------------------------------------ */

async function loadBrandSignature(
  companyName: string,
  domain: string
): Promise<BrandSignature> {
  const cfgDir = path.resolve(process.cwd(), 'config', 'brand-signatures');
  const candidates = [
    path.join(cfgDir, `${domain}.json`),
    path.join(cfgDir, `${companyName.replace(/\s+/g, '_').toLowerCase()}.json`)
  ];

  for (const file of candidates) {
    try {
      return JSON.parse(await fs.readFile(file, 'utf-8')) as BrandSignature;
    } catch {/* next */}
  }
  return {
    primary_domain: domain.toLowerCase(),
    alt_domains: [],
    core_terms: [companyName.toLowerCase()],
    excluded_terms: []
  };
}

/* ---------------------------------------------------------------------------
 * 4.  Static Heuristic Helpers
 * ------------------------------------------------------------------------ */

function domainMatches(h: string, sig: BrandSignature): boolean {
  return h.endsWith(sig.primary_domain) || sig.alt_domains.some((d) => h.endsWith(d));
}
function isSearchHitRelevant(
  urlStr: string,
  title: string,
  snippet: string,
  sig: BrandSignature
): boolean {
  const blob = `${title} ${snippet}`.toLowerCase();
  try {
    const { hostname } = new URL(urlStr.toLowerCase());
    if (domainMatches(hostname, sig)) return true;
    if (SKIP_HOSTS.has(hostname)) return false;
    if (sig.excluded_terms.some((t) => blob.includes(t))) return false;
    return sig.core_terms.some((t) => blob.includes(t));
  } catch {
    return false;
  }
}
function isContentRelevant(content: string, sig: BrandSignature, urlStr: string): boolean {
  try {
    if (domainMatches(new URL(urlStr).hostname, sig)) return true;
  } catch {/* ignore */}
  const lc = content.toLowerCase();
  if (sig.excluded_terms.some((t) => lc.includes(t))) return false;
  return sig.core_terms.some((t) => lc.includes(t));
}

/* ---------------------------------------------------------------------------
 * 5.  OpenAI helpers
 * ------------------------------------------------------------------------ */

const openai = process.env.OPENAI_API_KEY ? new OpenAI({ timeout: 8_000 }) : null;

/* 5.1 YES/NO relevance */
async function gptRelevant(sample: string, sig: BrandSignature): Promise<boolean> {
  if (!openai) return true;
  
  // Sanitize domain to prevent prompt injection
  const safeDomain = sig.primary_domain.replace(/[^a-zA-Z0-9.-]/g, '').slice(0, 253);
  const safeSample = sample.slice(0, MAX_CONTENT_FOR_GPT).replace(/["`]/g, "'");
  
  const prompt =
    `Does the text below clearly relate to the company whose domain is "${safeDomain}"? ` +
    'Reply YES or NO.\n\n' + safeSample;
  try {
    const { choices } = await openai.chat.completions.create({
      model: GPT_MODEL,
      temperature: 0,
      max_tokens: MAX_REL_TOKENS,
      messages: [
        { role: 'system', content: GPT_REL_SYS },
        { role: 'user', content: prompt }
      ]
    });
    const answer =
      choices?.[0]?.message?.content?.trim().toUpperCase() ?? 'NO';
    return answer.startsWith('Y');
  } catch (err) {
    log('[documentExposure] GPT relevance error – fail-open:', (err as Error).message);
    return true;
  }
}

/* 5.2 Industry label */
async function fetchSnippet(domain: string): Promise<string> {
  if (!process.env.SERPER_KEY) return '';
  try {
    const { data } = await axios.post(
      SERPER_URL,
      { q: `site:${domain}`, num: 1 },
      { headers: { 'X-API-KEY': process.env.SERPER_KEY } }
    );
    return data.organic?.[0]?.snippet ?? '';
  } catch {
    return '';
  }
}
async function gptIndustry(company: string, domain: string): Promise<IndustryGuard> {
  if (!openai) return { industry: 'Unknown', conf: 0 };
  
  // Sanitize inputs to prevent prompt injection
  const safeCompany = company.replace(/["`]/g, "'").slice(0, 200);
  const safeDomain = domain.replace(/[^a-zA-Z0-9.-]/g, '').slice(0, 253);
  
  const snippet = await fetchSnippet(safeDomain);
  const safeSnippet = snippet.replace(/["`]/g, "'").slice(0, 500);
  
  try {
    const { choices } = await openai.chat.completions.create({
      model: GPT_MODEL,
      temperature: 0,
      max_tokens: MAX_IND_TOKENS,
      messages: [
        { role: 'system', content: GPT_IND_SYS },
        {
          role: 'user',
          content:
            `Company: ${safeCompany}\nDomain: ${safeDomain}\nSnippet: ${safeSnippet}\nIdentify primary industry:` }
      ]
    });
    return JSON.parse(choices[0]?.message?.content ?? '{"industry":"Unknown","conf":0}') as IndustryGuard;
  } catch (err) {
    log('[documentExposure] GPT industry error – fail-open:', (err as Error).message);
    return { industry: 'Unknown', conf: 0 };
  }
}

/* ---------------------------------------------------------------------------
 * 6.  Search-dork helpers
 * ------------------------------------------------------------------------ */

async function getDorks(company: string, domain: string): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  try {
    const raw = await fs.readFile(
      path.resolve(process.cwd(), 'apps/workers/templates/dorks-optimized.txt'),
      'utf-8'
    );
    let cat = 'default';
    for (const ln of raw.split('\n')) {
      const t = ln.trim();
      if (t.startsWith('# ---')) {
        cat = t.replace('# ---', '').trim().toLowerCase();
      } else if (t && !t.startsWith('#')) {
        const rep = t.replace(/COMPANY_NAME/g, `"${company}"`).replace(/DOMAIN/g, domain);
        if (!out.has(cat)) out.set(cat, []);
        out.get(cat)!.push(rep);
      }
    }
    return out;
  } catch {
    return new Map([['fallback', [`site:*.${domain} "${company}" (filetype:pdf OR filetype:docx OR filetype:xlsx)`]]]);
  }
}
function getPlatform(urlStr: string): string {
  const u = urlStr.toLowerCase();
  if (u.includes('hubspot')) return 'HubSpot';
  if (u.includes('force.com') || u.includes('salesforce')) return 'Salesforce';
  if (u.includes('docs.google.com')) return 'Google Drive';
  if (u.includes('sharepoint.com')) return 'SharePoint';
  if (u.includes('linkedin.com')) return 'LinkedIn';
  return 'Unknown Cloud Storage';
}

/* ---------------------------------------------------------------------------
 * 7.  Security utilities  (magic bytes, zip-bomb, etc.)
 * ------------------------------------------------------------------------ */

const MAGIC_BYTES: Record<string, Buffer> = {
  'application/pdf': Buffer.from([0x25, 0x50, 0x44, 0x46]),
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': Buffer.from([0x50, 0x4b, 0x03, 0x04])
};
function validateHeader(buf: Buffer, mime: string): boolean {
  const exp = MAGIC_BYTES[mime];
  return exp ? buf.slice(0, exp.length).equals(exp) : true;
}
function memGuard(): void {
  const rss = process.memoryUsage().rss / 1024 / 1024;
  if (rss > MAX_WORKER_MEMORY_MB) throw new Error('Memory limit exceeded');
}
async function safeZip(buf: Buffer): Promise<boolean> {
  return new Promise((res, rej) => {
    yauzl.fromBuffer(buf, { lazyEntries: true }, (err, zip) => {
      if (err || !zip) return rej(err || new Error('Invalid zip'));
      let total = 0;
      zip.readEntry();
      zip.on('entry', (e) => {
        total += e.uncompressedSize;
        if (total > MAX_UNCOMPRESSED_ZIP_SIZE_MB * 1024 * 1024) return res(false);
        zip.readEntry();
      });
      zip.on('end', () => res(true));
      zip.on('error', rej);
    });
  });
}

/* ---------------------------------------------------------------------------
 * 8.  File parsing
 * ------------------------------------------------------------------------ */

async function parseBuffer(
  buf: Buffer,
  mime: string
): Promise<string> {
  switch (mime) {
    case 'application/pdf': {
      const pdf = await getDocument({ data: buf }).promise;
      let txt = '';
      for (let p = 1; p <= pdf.numPages; p++) {
        const c = await pdf.getPage(p).then((pg) => pg.getTextContent());
        txt += c.items.map((i: any) => i.str).join(' ') + '\n';
      }
      return txt;
    }
    case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
      if (!(await safeZip(buf))) throw new Error('Zip-bomb DOCX');
      return (await mammoth.extractRawText({ buffer: buf })).value;
    case 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':
      if (!(await safeZip(buf))) throw new Error('Zip-bomb XLSX');
      return xlsx
        .read(buf, { type: 'buffer' })
        .SheetNames.map((n) => xlsx.utils.sheet_to_csv(xlsx.read(buf, { type: 'buffer' }).Sheets[n]))
        .join('\n');
    default:
      return buf.toString('utf8', 0, MAX_CONTENT_ANALYSIS_BYTES);
  }
}

/* ---------------------------------------------------------------------------
 * 9.  Sensitivity scoring
 * ------------------------------------------------------------------------ */

function score(content: string): { sensitivity: number; findings: string[] } {
  const finds: string[] = [];
  let s = 0;
  const lc = content.toLowerCase();

  if ((content.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) ?? []).length > 5) {
    s += 10; finds.push('Bulk e-mails');
  }
  if ((content.match(/(?:\+?\d{1,3})?[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g) ?? []).length) {
    s += 5; finds.push('Phone numbers');
  }
  if (/[A-Za-z0-9+/]{40,}={0,2}/.test(content)) {
    s += 15; finds.push('High-entropy strings');
  }
  const cc = content.match(/\b(?:\d[ -]*?){13,19}\b/g) ?? [];
  if (cc.some((c) => luhn.validate(c.replace(/\D/g, '')))) {
    s += 25; finds.push('Credit-card data?');
  }
  if (['confidential', 'proprietary', 'internal use only', 'restricted'].some((k) => lc.includes(k))) {
    s += 10; finds.push('Confidential markings');
  }
  return { sensitivity: s, findings: finds };
}
function sev(s: number): 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  return s >= 40 ? 'CRITICAL' : s >= 25 ? 'HIGH' : s >= 15 ? 'MEDIUM' : s > 0 ? 'LOW' : 'INFO';
}

/* ---------------------------------------------------------------------------
 * 10.  Download → AI-filter → Analysis
 * ------------------------------------------------------------------------ */

async function downloadAndAnalyze(
  urlStr: string,
  sig: BrandSignature,
  guard: IndustryGuard,
  scanId?: string
): Promise<AnalysisResult | null> {
  let localPath: string | null = null;
  try {
    const { hostname } = new URL(urlStr);
    if (SKIP_HOSTS.has(hostname)) return null; // ← Skip obvious public pages

    const head = await axios.head(urlStr, { timeout: 10_000 }).catch<AxiosResponse | null>(() => null);
    if (parseInt(head?.headers['content-length'] ?? '0', 10) > 15 * 1024 * 1024) return null;

    /* -------------------------------------------------------------------- */
    /* Only proceed if Content-Type OR verified MIME is allowed document     */
    /* -------------------------------------------------------------------- */
    const reported = head?.headers['content-type'] ?? 'application/octet-stream';
    if (!ALLOWED_MIME.has(reported.split(';')[0])) {
      // Quick positive filter: if content-type is not clearly doc, bail early.
      if (!/\.pdf$|\.docx$|\.xlsx$/i.test(urlStr)) return null;
    }

    const res = await axios.get<ArrayBuffer>(urlStr, { responseType: 'arraybuffer', timeout: 30_000 });
    const buf = Buffer.from(res.data);

    const mimeInfo = await fileTypeFromBuffer(buf).then((ft) => ({
      reported,
      verified: ft?.mime ?? reported.split(';')[0]
    }));
    if (!ALLOWED_MIME.has(mimeInfo.verified)) return null; // Enforce allowed formats

    if (!validateHeader(buf, mimeInfo.verified)) throw new Error('Magic-byte mismatch');
    memGuard();

    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const ext = path.extname(new URL(urlStr).pathname) || '.tmp';
    localPath = path.join('/tmp', `doc_${sha256}${ext}`);
    await fs.writeFile(localPath, buf);

    const textContent = await Promise.race([
      parseBuffer(buf, mimeInfo.verified),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('Timeout')), FILE_PROCESSING_TIMEOUT_MS))
    ]);

    if (!isContentRelevant(textContent, sig, urlStr)) return null;
    if (!(await gptRelevant(textContent, sig))) return null;
    if (guard.conf > 0.7 && !textContent.toLowerCase().includes(guard.industry.toLowerCase())) return null;

    const { sensitivity, findings } = score(textContent);
    return {
      sha256,
      mimeInfo,
      localPath,
      sensitivity,
      findings,
      language: 'unknown'
    };
  } catch (err) {
    log('[documentExposure] process error:', (err as Error).message);
    return null;
  } finally {
    if (localPath) await fs.unlink(localPath).catch(() => null);
  }
}

/* ---------------------------------------------------------------------------
 * 11.  Main Runner
 * ------------------------------------------------------------------------ */

export async function runDocumentExposure(job: {
  companyName: string;
  domain: string;
  scanId?: string;
}): Promise<number> {
  const { companyName, domain, scanId } = job;
  if (!process.env.SERPER_KEY) {
    log('[documentExposure] SERPER_KEY missing');
    return 0;
  }
  
  // Cost control - limit search queries to prevent excessive Serper usage
  const MAX_SEARCH_QUERIES = parseInt(process.env.MAX_DOCUMENT_SEARCHES || '10');
  log(`[documentExposure] Cost control: limiting to ${MAX_SEARCH_QUERIES} search queries max`);

  const sig = await loadBrandSignature(companyName, domain);
  const industryLabel = await gptIndustry(companyName, domain);
  sig.industry = industryLabel.industry;

  const dorks = await getDorks(companyName, domain);
  const headers = { 'X-API-KEY': process.env.SERPER_KEY };

  const seen = new Set<string>();
  let total = 0;

  // Collect all queries to batch in parallel
  const allQueries: Array<{query: string, category: string}> = [];
  for (const [category, qs] of dorks.entries()) {
    for (const q of qs) {
      if (allQueries.length >= MAX_SEARCH_QUERIES) break;
      allQueries.push({query: q, category});
    }
  }

  log(`[documentExposure] Starting ${allQueries.length} parallel Serper queries`);
  
  // Execute all queries in parallel
  const queryResults = await Promise.allSettled(
    allQueries.map(async ({query, category}, index) => {
      try {
        log(`[documentExposure] Serper API call ${index + 1}: "${query}"`);
        const { data } = await axios.post(SERPER_URL, { q: query, num: 20 }, { headers });
        const results = data.organic ?? [];
        log(`[documentExposure] Query ${index + 1} returned ${results.length} results`);
        return { category, query, results, success: true };
      } catch (error) {
        log(`[documentExposure] Query ${index + 1} failed: ${(error as Error).message}`);
        return { category, query, results: [], success: false, error };
      }
    })
  );

  // Process all results
  for (const result of queryResults) {
    if (result.status === 'rejected') continue;
    
    const { results } = result.value;
    for (const hit of results) {
      const urlStr: string = hit.link;
      if (seen.has(urlStr)) continue;
      seen.add(urlStr);

      if (!isSearchHitRelevant(urlStr, hit.title ?? '', hit.snippet ?? '', sig)) continue;

      const platform = getPlatform(urlStr);
      const res = await downloadAndAnalyze(urlStr, sig, industryLabel, scanId);
      if (!res) continue;

      const key = `exposed_docs/${platform.toLowerCase()}/${res.sha256}${path.extname(urlStr)}`;
      const storageUrl = await uploadFile(res.localPath, key, res.mimeInfo.verified);

      const artifactId = await insertArtifact({
        type: 'exposed_document',
        val_text: `${platform} exposed file: ${path.basename(urlStr)}`,
        severity: sev(res.sensitivity),
        src_url: urlStr,
        sha256: res.sha256,
        mime: res.mimeInfo.verified,
        meta: {
          scan_id: scanId,
          scan_module: 'documentExposure',
          platform,
          storage_url: storageUrl,
          sensitivity_score: res.sensitivity,
          analysis_findings: res.findings,
          industry_label: industryLabel
        }
      });

      if (res.sensitivity >= 15) {
        await insertFinding(
          artifactId,
          'DATA_EXPOSURE',
          `Secure the ${platform} service by reviewing file permissions.`,
          `Sensitive document found on ${platform}. Score: ${res.sensitivity}.`
        );
      }
      total++;
    }
  }

  const estimatedCost = (allQueries.length * 0.003).toFixed(3); // Rough estimate at $0.003/search
  log(`[documentExposure] Completed: ${total} files found, ${allQueries.length} parallel Serper calls (~$${estimatedCost})`);

  await insertArtifact({
    type: 'scan_summary',
    val_text: `Document exposure scan completed: ${total} exposed files`,
    severity: 'INFO',
    meta: {
      scan_id: scanId,
      scan_module: 'documentExposure',
      total_findings: total,
      queries_executed: allQueries.length,
      estimated_cost_usd: estimatedCost,
      timestamp: new Date().toISOString(),
      industry_label: industryLabel
    }
  });

  return total;
}

/* eslint-enable @typescript-eslint/strict-boolean-expressions */
</file>

<file path="emailBruteforceSurface.ts">
/**
 * Email Bruteforce Surface Module
 * 
 * Uses Nuclei templates to detect exposed email services that could be targets
 * for bruteforce attacks, including OWA, Exchange, IMAP, and SMTP services.
 */

import * as fs from 'node:fs/promises';
import { insertArtifact, insertFinding, pool } from '../core/artifactStore.js';
import { log as rootLog } from '../core/logger.js';
import { runNuclei, createTargetsFile, cleanupFile } from '../util/nucleiWrapper.js';

// Configuration constants
const NUCLEI_TIMEOUT_MS = 300_000; // 5 minutes
const MAX_TARGETS = 50;
const CONCURRENCY = 6;

// Enhanced logging
const log = (...args: unknown[]) => rootLog('[emailBruteforceSurface]', ...args);

// Email service Nuclei templates
const EMAIL_TEMPLATES = [
  'technologies/microsoft-exchange-server-detect.yaml',
  'technologies/outlook-web-access-detect.yaml',
  'technologies/owa-detect.yaml',
  'network/smtp-detect.yaml',
  'network/imap-detect.yaml',
  'network/pop3-detect.yaml',
  'technologies/exchange-autodiscover.yaml',
  'technologies/activesync-detect.yaml',
  'misconfiguration/exchange-server-login.yaml',
  'misconfiguration/owa-login-portal.yaml'
];

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
  };
  type: string;
  host: string;
  'matched-at': string;
  'extracted-results'?: string[];
  timestamp: string;
}

interface EmailScanSummary {
  totalTargets: number;
  exchangeServices: number;
  owaPortals: number;
  smtpServices: number;
  imapServices: number;
  bruteforceTargets: number;
  templatesExecuted: number;
}

/**
 * Get target URLs for email service scanning
 */
async function getEmailTargets(scanId: string, domain: string): Promise<string[]> {
  const targets = new Set<string>();
  
  try {
    // Get URLs from previous scans
    const { rows: urlRows } = await pool.query(
      `SELECT val_text FROM artifacts 
       WHERE type='url' AND meta->>'scan_id'=$1`,
      [scanId]
    );
    
    urlRows.forEach(row => {
      targets.add(row.val_text.trim());
    });
    
    // Get hostnames and subdomains
    const { rows: hostRows } = await pool.query(
      `SELECT val_text FROM artifacts 
       WHERE type IN ('hostname', 'subdomain') AND meta->>'scan_id'=$1`,
      [scanId]
    );
    
    const hosts = new Set([domain]);
    hostRows.forEach(row => {
      hosts.add(row.val_text.trim());
    });
    
    // Generate common email service URLs and subdomains
    const emailPaths = [
      '',
      '/owa',
      '/exchange',
      '/mail',
      '/webmail',
      '/outlook',
      '/autodiscover',
      '/Microsoft-Server-ActiveSync',
      '/EWS/Exchange.asmx',
      '/Autodiscover/Autodiscover.xml'
    ];
    
    const emailSubdomains = [
      'mail',
      'webmail',
      'owa',
      'exchange',
      'outlook',
      'smtp',
      'imap',
      'pop',
      'pop3',
      'autodiscover',
      'activesync'
    ];
    
    // Add email-specific subdomains
    const baseDomain = domain.replace(/^www\./, '');
    emailSubdomains.forEach(subdomain => {
      hosts.add(`${subdomain}.${baseDomain}`);
    });
    
    // Generate URLs
    hosts.forEach(host => {
      ['https', 'http'].forEach(protocol => {
        emailPaths.forEach(path => {
          const url = `${protocol}://${host}${path}`;
          targets.add(url);
        });
        
        // Add common email ports
        const emailPorts = [25, 587, 993, 995, 110, 143, 465];
        emailPorts.forEach(port => {
          targets.add(`${protocol}://${host}:${port}`);
        });
      });
    });
    
    log(`Generated ${targets.size} email service targets`);
    return Array.from(targets).slice(0, MAX_TARGETS);
    
  } catch (error) {
    log(`Error getting email targets: ${(error as Error).message}`);
    return [];
  }
}

/**
 * Run Nuclei with email service templates
 */
async function runNucleiEmailScan(targets: string[]): Promise<NucleiResult[]> {
  if (targets.length === 0) {
    return [];
  }
  
  try {
    // Create temporary targets file
    const targetsFile = await createTargetsFile(targets, 'nuclei-email-targets');
    
    log(`Running Nuclei with ${EMAIL_TEMPLATES.length} email templates against ${targets.length} targets`);
    
    // Use the standardized nuclei wrapper with specific email templates
    const result = await runNuclei({
      targetList: targetsFile,
      templates: EMAIL_TEMPLATES,
      retries: 2,
      concurrency: CONCURRENCY,
      headless: true // Email services may need headless for form detection
    });
    
    // Cleanup targets file
    await cleanupFile(targetsFile);
    
    if (!result.success) {
      log(`Nuclei email scan failed with exit code ${result.exitCode}`);
      return [];
    }
    
    // Enhanced stderr logging - capture full output for better debugging
    if (result.stderr) {
      log(`Nuclei stderr: ${result.stderr}`);
    }
    
    log(`Nuclei email scan completed: ${result.results.length} findings`);
    return result.results as NucleiResult[];
    
  } catch (error) {
    log(`Nuclei email scan failed: ${(error as Error).message}`);
    return [];
  }
}

/**
 * Analyze Nuclei result for email service type and bruteforce potential
 */
function analyzeEmailService(result: NucleiResult): {
  serviceType: string;
  isBruteforceTarget: boolean;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH';
  description: string;
  evidence: string;
} {
  const tags = result.info.tags || [];
  const templateName = result.info.name.toLowerCase();
  const host = result.host;
  
  let serviceType = 'EMAIL_SERVICE';
  let isBruteforceTarget = false;
  let severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' = 'INFO';
  
  // Determine service type and bruteforce potential
  if (tags.includes('exchange') || templateName.includes('exchange')) {
    serviceType = 'EXCHANGE_SERVER';
    isBruteforceTarget = true;
    severity = 'MEDIUM';
  } else if (tags.includes('owa') || templateName.includes('owa') || templateName.includes('outlook')) {
    serviceType = 'OWA_PORTAL';
    isBruteforceTarget = true;
    severity = 'HIGH'; // OWA is high-value target
  } else if (tags.includes('smtp') || templateName.includes('smtp')) {
    serviceType = 'SMTP_SERVICE';
    isBruteforceTarget = true;
    severity = 'MEDIUM';
  } else if (tags.includes('imap') || templateName.includes('imap')) {
    serviceType = 'IMAP_SERVICE';
    isBruteforceTarget = true;
    severity = 'MEDIUM';
  } else if (templateName.includes('login') || templateName.includes('portal')) {
    serviceType = 'EMAIL_LOGIN_PORTAL';
    isBruteforceTarget = true;
    severity = 'HIGH';
  }
  
  const description = `${serviceType.replace('_', ' ')} detected: ${result.info.name} on ${host}`;
  const evidence = `Template: ${result['template-id']} | URL: ${result['matched-at']}`;
  
  return {
    serviceType,
    isBruteforceTarget,
    severity,
    description,
    evidence
  };
}

/**
 * Generate email service summary
 */
function generateEmailSummary(results: NucleiResult[]): EmailScanSummary {
  const summary: EmailScanSummary = {
    totalTargets: 0,
    exchangeServices: 0,
    owaPortals: 0,
    smtpServices: 0,
    imapServices: 0,
    bruteforceTargets: 0,
    templatesExecuted: EMAIL_TEMPLATES.length
  };
  
  results.forEach(result => {
    const analysis = analyzeEmailService(result);
    
    if (analysis.serviceType === 'EXCHANGE_SERVER') summary.exchangeServices++;
    if (analysis.serviceType === 'OWA_PORTAL') summary.owaPortals++;
    if (analysis.serviceType === 'SMTP_SERVICE') summary.smtpServices++;
    if (analysis.serviceType === 'IMAP_SERVICE') summary.imapServices++;
    if (analysis.isBruteforceTarget) summary.bruteforceTargets++;
  });
  
  return summary;
}

/**
 * Main email bruteforce surface scan function
 */
export async function runEmailBruteforceSurface(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;
  const startTime = Date.now();
  
  log(`Starting email bruteforce surface scan for domain="${domain}"`);
  
  try {
    // Get email service targets
    const targets = await getEmailTargets(scanId, domain);
    
    if (targets.length === 0) {
      log('No targets found for email service scanning');
      return 0;
    }
    
    // Run Nuclei email service scan
    const nucleiResults = await runNucleiEmailScan(targets);
    
    if (nucleiResults.length === 0) {
      log('No email services detected');
      return 0;
    }
    
    // Generate summary
    const summary = generateEmailSummary(nucleiResults);
    summary.totalTargets = targets.length;
    
    log(`Email service scan complete: ${nucleiResults.length} services found, ${summary.bruteforceTargets} bruteforce targets`);
    
    // Create summary artifact
    const severity = summary.owaPortals > 0 ? 'HIGH' : 
                    summary.bruteforceTargets > 0 ? 'MEDIUM' : 'LOW';
    
    const artifactId = await insertArtifact({
      type: 'email_surface_summary',
      val_text: `Email bruteforce surface: ${summary.bruteforceTargets} attackable email services found`,
      severity,
      meta: {
        scan_id: scanId,
        scan_module: 'emailBruteforceSurface',
        domain,
        summary,
        total_results: nucleiResults.length,
        scan_duration_ms: Date.now() - startTime
      }
    });
    
    let findingsCount = 0;
    
    // Process each detected email service
    for (const result of nucleiResults) {
      const analysis = analyzeEmailService(result);
      
      // Only create findings for bruteforce targets
      if (analysis.isBruteforceTarget) {
        await insertFinding(
          artifactId,
          'MAIL_BRUTEFORCE_SURFACE',
          analysis.description,
          analysis.evidence
        );
        
        findingsCount++;
      }
    }
    
    const duration = Date.now() - startTime;
    log(`Email bruteforce surface scan completed: ${findingsCount} findings in ${duration}ms`);
    
    return findingsCount;
    
  } catch (error) {
    const errorMsg = (error as Error).message;
    log(`Email bruteforce surface scan failed: ${errorMsg}`);
    
    await insertArtifact({
      type: 'scan_error',
      val_text: `Email bruteforce surface scan failed: ${errorMsg}`,
      severity: 'MEDIUM',
      meta: {
        scan_id: scanId,
        scan_module: 'emailBruteforceSurface',
        scan_duration_ms: Date.now() - startTime
      }
    });
    
    return 0;
  }
}
</file>

<file path="endpointDiscovery.ts">
/* =============================================================================
 * MODULE: endpointDiscovery.ts (Consolidated v5 – 2025‑06‑15)
 * =============================================================================
 * - Discovers endpoints via robots.txt, sitemaps, crawling, JS analysis, and brute-force
 * - Integrates endpoint visibility checking to label whether each discovered route is:
 *     • public GET‑only (no auth)  → likely static content
 *     • requires auth             → sensitive / attack surface
 *     • allows state‑changing verbs (POST / PUT / …)
 * - Consolidated implementation with no external module dependencies
 * =============================================================================
 */

import axios, { AxiosRequestConfig, AxiosResponse } from 'axios';
import { parse } from 'node-html-parser';
import { insertArtifact } from '../core/artifactStore.js';
import { log } from '../core/logger.js';
import { URL } from 'node:url';
import * as https from 'node:https';

// ---------- Configuration ----------------------------------------------------

const MAX_CRAWL_DEPTH = 2;
const MAX_CONCURRENT_REQUESTS = 5;
const REQUEST_TIMEOUT = 8_000;
const DELAY_BETWEEN_CHUNKS_MS = 500;
const MAX_JS_FILE_SIZE_BYTES = 1 * 1024 * 1024; // 1 MB
const VIS_PROBE_CONCURRENCY = 5;
const VIS_PROBE_TIMEOUT = 10_000;

const ENDPOINT_WORDLIST = [
  'api',
  'admin',
  'app',
  'auth',
  'login',
  'register',
  'dashboard',
  'config',
  'settings',
  'user',
  'users',
  'account',
  'profile',
  'upload',
  'download',
  'files',
  'docs',
  'documentation',
  'help',
  'support',
  'contact',
  'about',
  'status',
  'health',
  'ping',
  'test',
  'dev',
  'debug',
  'staging',
  'prod',
  'production',
  'v1',
  'v2',
  'graphql',
  'rest',
  'webhook',
  'callback',
  'oauth',
  'token',
  'jwt',
  'session',
  'logout',
  'forgot',
  'reset',
  'verify',
  'confirm',
  'activate',
  'wordpress'
];

const AUTH_PROBE_HEADERS = [
  { Authorization: 'Bearer test' },
  { 'X-API-Key': 'test' },
  { 'x-access-token': 'test' },
  { 'X-Auth-Token': 'test' },
  { Cookie: 'session=test' },
  { 'X-Forwarded-User': 'test' }
];

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  'curl/8.8.0',
  'python-requests/2.32.0',
  'Go-http-client/2.0'
];

const VERBS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
const HTTPS_AGENT = new https.Agent({ rejectUnauthorized: true });

// ---------- Types ------------------------------------------------------------

interface DiscoveredEndpoint {
  url: string;
  path: string;
  confidence: 'high' | 'medium' | 'low';
  source:
    | 'robots.txt'
    | 'sitemap.xml'
    | 'crawl_link'
    | 'js_analysis'
    | 'wordlist_enum'
    | 'auth_probe';
  statusCode?: number;
  visibility?: 'public_get' | 'auth_required' | 'state_changing';
}

interface WebAsset {
  url: string;
  type: 'javascript' | 'css' | 'html' | 'json' | 'sourcemap' | 'other';
  size?: number;
  confidence: 'high' | 'medium' | 'low';
  source: 'crawl' | 'js_analysis' | 'sourcemap_hunt' | 'targeted_probe';
  content?: string;
  mimeType?: string;
}

interface SafeResult {
  ok: boolean;
  status?: number;
  data?: unknown;
  error?: string;
}

interface EndpointReport {
  url: string;
  publicGET: boolean;
  allowedVerbs: string[];
  authNeeded: boolean;
  notes: string[];
}

// ---------- Endpoint Visibility Checking ------------------------------------

async function safeVisibilityRequest(method: string, target: string): Promise<AxiosResponse | null> {
  try {
    return await axios.request({
      url: target,
      method: method as any,
      timeout: VIS_PROBE_TIMEOUT,
      httpsAgent: HTTPS_AGENT,
      maxRedirects: 5,
      validateStatus: () => true
    });
  } catch {
    return null;
  }
}

async function checkEndpoint(urlStr: string): Promise<EndpointReport> {
  const notes: string[] = [];
  const result: EndpointReport = {
    url: urlStr,
    publicGET: false,
    allowedVerbs: [],
    authNeeded: false,
    notes
  };

  /* Validate URL */
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    notes.push('Invalid URL');
    return result;
  }

  /* OPTIONS preflight to discover allowed verbs */
  const optRes = await safeVisibilityRequest('OPTIONS', urlStr);
  if (optRes) {
    const allow = (optRes.headers['allow'] as string | undefined)?.split(',');
    if (allow) {
      result.allowedVerbs = allow.map((v) => v.trim().toUpperCase()).filter(Boolean);
    }
  }

  /* Anonymous GET */
  const getRes = await safeVisibilityRequest('GET', urlStr);
  if (!getRes) {
    notes.push('GET request failed');
    return result;
  }
  result.publicGET = getRes.status === 200;

  /* Check auth headers and common tokens */
  if (getRes.status === 401 || getRes.status === 403) {
    result.authNeeded = true;
    return result;
  }
  const wwwAuth = getRes.headers['www-authenticate'];
  if (wwwAuth) {
    result.authNeeded = true;
    notes.push(`WWW-Authenticate: ${wwwAuth}`);
  }

  /* Test side‑effect verbs only if OPTIONS permitted them */
  for (const verb of VERBS.filter((v) => v !== 'GET')) {
    if (!result.allowedVerbs.includes(verb)) continue;
    const res = await safeVisibilityRequest(verb, urlStr);
    if (!res) continue;
    if (res.status < 400) {
      notes.push(`${verb} responded with status ${res.status}`);
    }
  }

  return result;
}

// ---------- Discovery Helpers -----------------------------------------------

const discovered = new Map<string, DiscoveredEndpoint>();
const webAssets = new Map<string, WebAsset>();

const getRandomUA = (): string =>
  USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

const safeRequest = async (
  url: string,
  cfg: AxiosRequestConfig
): Promise<SafeResult> => {
  try {
    const res: AxiosResponse = await axios({ url, ...cfg });
    return { ok: true, status: res.status, data: res.data };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown network error';
    return { ok: false, error: message };
  }
};

const addEndpoint = (
  baseUrl: string,
  ep: Omit<DiscoveredEndpoint, 'url'>
): void => {
  if (discovered.has(ep.path)) return;
  const fullUrl = `${baseUrl}${ep.path}`;
  discovered.set(ep.path, { ...ep, url: fullUrl });
  log(`[endpointDiscovery] +${ep.source} ${ep.path} (${ep.statusCode ?? '-'})`);
};

const addWebAsset = (asset: WebAsset): void => {
  if (webAssets.has(asset.url)) return;
  webAssets.set(asset.url, asset);
  log(`[endpointDiscovery] +web_asset ${asset.type} ${asset.url} (${asset.size ?? '?'} bytes)`);
};

const getAssetType = (url: string, mimeType?: string): WebAsset['type'] => {
  if (url.endsWith('.js.map')) return 'sourcemap';
  if (url.endsWith('.js') || mimeType?.includes('javascript')) return 'javascript';
  if (url.endsWith('.css') || mimeType?.includes('css')) return 'css';
  if (url.endsWith('.json') || mimeType?.includes('json')) return 'json';
  if (url.endsWith('.html') || url.endsWith('.htm') || mimeType?.includes('html')) return 'html';
  return 'other';
};

// ---------- Passive Discovery ------------------------------------------------

const parseRobotsTxt = async (baseUrl: string): Promise<void> => {
  const res = await safeRequest(`${baseUrl}/robots.txt`, {
    timeout: REQUEST_TIMEOUT,
    headers: { 'User-Agent': getRandomUA() },
    validateStatus: () => true
  });
  if (!res.ok || typeof res.data !== 'string') return;

  for (const raw of res.data.split('\n')) {
    const [directiveRaw, pathRaw] = raw.split(':').map((p) => p.trim());
    if (!directiveRaw || !pathRaw) continue;

    const directive = directiveRaw.toLowerCase();
    if ((directive === 'disallow' || directive === 'allow') && pathRaw.startsWith('/')) {
      addEndpoint(baseUrl, {
        path: pathRaw,
        confidence: 'medium',
        source: 'robots.txt'
      });
    } else if (directive === 'sitemap') {
      await parseSitemap(new URL(pathRaw, baseUrl).toString(), baseUrl);
    }
  }
};

const parseSitemap = async (sitemapUrl: string, baseUrl: string): Promise<void> => {
  const res = await safeRequest(sitemapUrl, {
    timeout: REQUEST_TIMEOUT,
    headers: { 'User-Agent': getRandomUA() },
    validateStatus: () => true
  });
  if (!res.ok || typeof res.data !== 'string') return;

  const root = parse(res.data);
  const locElems = root.querySelectorAll('loc');
  for (const el of locElems) {
    try {
      const url = new URL(el.text);
      addEndpoint(baseUrl, {
        path: url.pathname,
        confidence: 'high',
        source: 'sitemap.xml'
      });
    } catch {
      /* ignore bad URL */
    }
  }
};

// ---------- Active Discovery -------------------------------------------------

const analyzeJsFile = async (jsUrl: string, baseUrl: string): Promise<void> => {
  const res = await safeRequest(jsUrl, {
    timeout: REQUEST_TIMEOUT,
    maxContentLength: MAX_JS_FILE_SIZE_BYTES,
    headers: { 'User-Agent': getRandomUA() },
    validateStatus: () => true
  });
  if (!res.ok || typeof res.data !== 'string') return;

  // Save the JavaScript file as a web asset for secret scanning
  addWebAsset({
    url: jsUrl,
    type: 'javascript',
    size: res.data.length,
    confidence: 'high',
    source: 'js_analysis',
    content: res.data.length > 50000 ? res.data.substring(0, 50000) + '...[truncated]' : res.data,
    mimeType: 'application/javascript'
  });

  // Hunt for corresponding source map
  await huntSourceMap(jsUrl, baseUrl);

  // Extract endpoint patterns (existing functionality)
  const re = /['"`](\/[a-zA-Z0-9\-._/]*(?:api|auth|v\d|graphql|jwt|token)[a-zA-Z0-9\-._/]*)['"`]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(res.data)) !== null) {
    addEndpoint(baseUrl, {
      path: m[1],
      confidence: 'medium',
      source: 'js_analysis'
    });
  }

  // Look for potential data endpoints that might contain secrets
  const dataEndpointRe = /fetch\s*\(['"`]([^'"`]+)['"`]\)|axios\.[get|post|put|delete]+\(['"`]([^'"`]+)['"`]\)|\$\.get\(['"`]([^'"`]+)['"`]\)/g;
  let dataMatch: RegExpExecArray | null;
  while ((dataMatch = dataEndpointRe.exec(res.data)) !== null) {
    const endpoint = dataMatch[1] || dataMatch[2] || dataMatch[3];
    if (endpoint && endpoint.startsWith('/')) {
      addEndpoint(baseUrl, {
        path: endpoint,
        confidence: 'high',
        source: 'js_analysis'
      });
    }
  }
};

// Hunt for source maps that might expose backend secrets
const huntSourceMap = async (jsUrl: string, baseUrl: string): Promise<void> => {
  try {
    const sourceMapUrl = jsUrl + '.map';
    const res = await safeRequest(sourceMapUrl, {
      timeout: REQUEST_TIMEOUT,
      maxContentLength: 10 * 1024 * 1024, // 10MB max for source maps
      headers: { 'User-Agent': getRandomUA() },
      validateStatus: () => true
    });
    
    if (res.ok && typeof res.data === 'string') {
      log(`[endpointDiscovery] Found source map: ${sourceMapUrl}`);
      addWebAsset({
        url: sourceMapUrl,
        type: 'sourcemap',
        size: res.data.length,
        confidence: 'high',
        source: 'sourcemap_hunt',
        content: res.data.length > 100000 ? res.data.substring(0, 100000) + '...[truncated]' : res.data,
        mimeType: 'application/json'
      });
    }
  } catch (error) {
    // Source map hunting is opportunistic - don't log errors
  }
};

const crawlPage = async (
  url: string,
  depth: number,
  baseUrl: string,
  seen: Set<string>
): Promise<void> => {
  if (depth > MAX_CRAWL_DEPTH || seen.has(url)) return;
  seen.add(url);

  const res = await safeRequest(url, {
    timeout: REQUEST_TIMEOUT,
    headers: { 'User-Agent': getRandomUA() },
    validateStatus: () => true
  });
  if (!res.ok || typeof res.data !== 'string') return;

  // Save HTML content as web asset for secret scanning
  const contentType = typeof res.data === 'object' && res.data && 'headers' in res.data ? 
    (res.data as any).headers?.['content-type'] || '' : '';
  addWebAsset({
    url,
    type: getAssetType(url, contentType),
    size: res.data.length,
    confidence: 'high',
    source: 'crawl',
    content: res.data.length > 100000 ? res.data.substring(0, 100000) + '...[truncated]' : res.data,
    mimeType: contentType
  });

  const root = parse(res.data);
  const pageLinks = new Set<string>();

  root.querySelectorAll('a[href]').forEach((a) => {
    try {
      const abs = new URL(a.getAttribute('href')!, baseUrl).toString();
      if (abs.startsWith(baseUrl)) {
        addEndpoint(baseUrl, {
          path: new URL(abs).pathname,
          confidence: 'low',
          source: 'crawl_link'
        });
        pageLinks.add(abs);
      }
    } catch {
      /* ignore */
    }
  });

  root.querySelectorAll('script[src]').forEach((s) => {
    try {
      const abs = new URL(s.getAttribute('src')!, baseUrl).toString();
      if (abs.startsWith(baseUrl)) void analyzeJsFile(abs, baseUrl);
    } catch {
      /* ignore */
    }
  });

  // Extract CSS files
  root.querySelectorAll('link[rel="stylesheet"][href]').forEach((link) => {
    try {
      const abs = new URL(link.getAttribute('href')!, baseUrl).toString();
      if (abs.startsWith(baseUrl)) {
        void analyzeCssFile(abs, baseUrl);
      }
    } catch {
      /* ignore */
    }
  });

  // Look for inline scripts with potential secrets
  root.querySelectorAll('script:not([src])').forEach((script, index) => {
    const content = script.innerHTML;
    if (content.length > 100) { // Only save substantial inline scripts
      addWebAsset({
        url: `${url}#inline-script-${index}`,
        type: 'javascript',
        size: content.length,
        confidence: 'high',
        source: 'crawl',
        content: content.length > 10000 ? content.substring(0, 10000) + '...[truncated]' : content,
        mimeType: 'application/javascript'
      });
    }
  });

  for (const link of pageLinks) {
    await crawlPage(link, depth + 1, baseUrl, seen);
  }
};

// Analyze CSS files for potential secrets (background URLs with tokens, etc.)
const analyzeCssFile = async (cssUrl: string, baseUrl: string): Promise<void> => {
  const res = await safeRequest(cssUrl, {
    timeout: REQUEST_TIMEOUT,
    maxContentLength: 2 * 1024 * 1024, // 2MB max for CSS
    headers: { 'User-Agent': getRandomUA() },
    validateStatus: () => true
  });
  if (!res.ok || typeof res.data !== 'string') return;

  addWebAsset({
    url: cssUrl,
    type: 'css',
    size: res.data.length,
    confidence: 'medium',
    source: 'crawl',
    content: res.data.length > 50000 ? res.data.substring(0, 50000) + '...[truncated]' : res.data,
    mimeType: 'text/css'
  });
};

// ---------- Brute-Force / Auth Probe -----------------------------------------

const bruteForce = async (baseUrl: string): Promise<void> => {
  const tasks = ENDPOINT_WORDLIST.flatMap((word) => {
    const path = `/${word}`;
    const uaHeader = { 'User-Agent': getRandomUA() };

    const basic = {
      promise: safeRequest(`${baseUrl}${path}`, {
        method: 'HEAD',
        timeout: REQUEST_TIMEOUT,
        headers: uaHeader,
        validateStatus: () => true
      }),
      path,
      source: 'wordlist_enum' as const
    };

    const auths = AUTH_PROBE_HEADERS.map((h) => ({
      promise: safeRequest(`${baseUrl}${path}`, {
        method: 'GET',
        timeout: REQUEST_TIMEOUT,
        headers: { ...uaHeader, ...h },
        validateStatus: () => true
      }),
      path,
      source: 'auth_probe' as const
    }));

    return [basic, ...auths];
  });

  for (let i = 0; i < tasks.length; i += MAX_CONCURRENT_REQUESTS) {
    const slice = tasks.slice(i, i + MAX_CONCURRENT_REQUESTS);
    const settled = await Promise.all(slice.map((t) => t.promise));

    settled.forEach((res, idx) => {
      if (!res.ok) return;
      const { path, source } = slice[idx];
      if (res.status !== undefined && (res.status < 400 || res.status === 401 || res.status === 403)) {
        addEndpoint(baseUrl, {
          path,
          confidence: 'low',
          source,
          statusCode: res.status
        });
      }
    });

    await new Promise((r) => setTimeout(r, DELAY_BETWEEN_CHUNKS_MS));
  }
};

// ---------- Visibility Probe -------------------------------------------------

async function enrichVisibility(endpoints: DiscoveredEndpoint[]): Promise<void> {
  const worker = async (ep: DiscoveredEndpoint): Promise<void> => {
    try {
      const rep: EndpointReport = await checkEndpoint(ep.url);
      if (rep.authNeeded) {
        ep.visibility = 'auth_required';
      } else if (rep.allowedVerbs.some((v: string) => v !== 'GET')) {
        ep.visibility = 'state_changing';
      } else {
        ep.visibility = 'public_get';
      }
    } catch (err) {
      /* swallow errors – leave visibility undefined */
    }
  };

  // Process endpoints in chunks with controlled concurrency
  for (let i = 0; i < endpoints.length; i += VIS_PROBE_CONCURRENCY) {
    const chunk = endpoints.slice(i, i + VIS_PROBE_CONCURRENCY);
    const chunkTasks = chunk.map(worker);
    await Promise.allSettled(chunkTasks);
  }
}

// Target high-value paths that might contain secrets
const probeHighValuePaths = async (baseUrl: string): Promise<void> => {
  const highValuePaths = [
    '/.env',
    '/config.json',
    '/app.config.json',
    '/settings.json',
    '/manifest.json',
    '/.env.local',
    '/.env.production',
    '/api/config',
    '/api/settings',
    '/_next/static/chunks/webpack.js',
    '/static/js/main.js',
    '/assets/config.js',
    '/config.js',
    '/build/config.json'
  ];

  const tasks = highValuePaths.map(async (path) => {
    try {
      const fullUrl = `${baseUrl}${path}`;
      const res = await safeRequest(fullUrl, {
        timeout: 5000,
        maxContentLength: 5 * 1024 * 1024, // 5MB max
        headers: { 'User-Agent': getRandomUA() },
        validateStatus: () => true
      });
      
      if (res.ok && res.data) {
        const contentType = '';
        addWebAsset({
          url: fullUrl,
          type: getAssetType(fullUrl, contentType),
          size: typeof res.data === 'string' ? res.data.length : 0,
          confidence: 'high',
          source: 'targeted_probe',
          content: typeof res.data === 'string' ? 
            (res.data.length > 50000 ? res.data.substring(0, 50000) + '...[truncated]' : res.data) : 
            '[binary content]',
          mimeType: contentType
        });
        
        log(`[endpointDiscovery] Found high-value asset: ${fullUrl}`);
      }
    } catch (error) {
      // Expected for most paths - don't log
    }
  });

  await Promise.all(tasks);
};

// ---------- Main Export ------------------------------------------------------

export async function runEndpointDiscovery(job: { domain: string; scanId?: string }): Promise<number> {
  log(`[endpointDiscovery] ⇢ start ${job.domain}`);
  const baseUrl = `https://${job.domain}`;
  discovered.clear();
  webAssets.clear();

  // Existing discovery methods
  await parseRobotsTxt(baseUrl);
  await parseSitemap(`${baseUrl}/sitemap.xml`, baseUrl);
  await crawlPage(baseUrl, 1, baseUrl, new Set<string>());
  await bruteForce(baseUrl);
  
  // New: Probe high-value paths for secrets
  await probeHighValuePaths(baseUrl);

  const endpoints = [...discovered.values()];
  const assets = [...webAssets.values()];

  /* ------- Visibility enrichment (public/static vs. auth) ---------------- */
  await enrichVisibility(endpoints);

  // Save discovered endpoints
  if (endpoints.length) {
    await insertArtifact({
      type: 'discovered_endpoints',
      val_text: `Discovered ${endpoints.length} unique endpoints for ${job.domain}`,
      severity: 'INFO',
      meta: {
        scan_id: job.scanId,
        scan_module: 'endpointDiscovery',
        endpoints
      }
    });
  }

  // Save discovered web assets for secret scanning
  if (assets.length) {
    await insertArtifact({
      type: 'discovered_web_assets',
      val_text: `Discovered ${assets.length} web assets for secret scanning on ${job.domain}`,
      severity: 'INFO',
      meta: {
        scan_id: job.scanId,
        scan_module: 'endpointDiscovery',
        assets,
        asset_breakdown: {
          javascript: assets.filter(a => a.type === 'javascript').length,
          css: assets.filter(a => a.type === 'css').length,
          html: assets.filter(a => a.type === 'html').length,
          json: assets.filter(a => a.type === 'json').length,
          sourcemap: assets.filter(a => a.type === 'sourcemap').length,
          other: assets.filter(a => a.type === 'other').length
        }
      }
    });
  }

  log(`[endpointDiscovery] ⇢ done – ${endpoints.length} endpoints, ${assets.length} web assets`);
  // Return 0 as this module doesn't create findings, only artifacts
  return 0;
}
</file>

<file path="nuclei.ts">
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
import { log } from '../core/logger.js';
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
</file>

<file path="openvasScan.ts">
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
</file>

<file path="rateLimitScan.ts">
/*
 * =============================================================================
 * MODULE: rateLimitScan.ts (Consolidated & Refactored)
 * =============================================================================
 * This module replaces zapRateIp.ts, zapRateTest.ts, and zapRateToken.ts
 * with a single, comprehensive rate limit testing engine.
 *
 * Key Improvements:
 * 1.  **Integrated Endpoint Discovery:** Uses the output from the endpointDiscovery
 * module to find the best targets (login, API, auth endpoints) for testing.
 * 2.  **Structured Testing:** Establishes a baseline to confirm a rate limit
 * exists before attempting a wide range of bypass techniques.
 * 3.  **Expanded Bypass Techniques:** Tests for bypasses via IP spoofing headers,
 * HTTP method switching, path variations, and parameter pollution.
 * 4.  **Consolidated Findings:** Groups all successful bypass methods for a
 * single endpoint into one actionable artifact.
 * =============================================================================
 */

import axios, { Method } from 'axios';
import { insertArtifact, insertFinding, pool } from '../core/artifactStore.js';
import { log } from '../core/logger.js';

const REQUEST_BURST_COUNT = 25; // Number of requests to send to trigger a baseline limit.
const REQUEST_TIMEOUT = 5000;

interface DiscoveredEndpoint {
  url: string;
  path: string;
  method?: string; // Original method, may not be present
}

interface RateLimitTestResult {
    bypassed: boolean;
    technique: string;
    details: string;
    statusCode?: number;
}

const IP_SPOOFING_HEADERS = [
    { 'X-Forwarded-For': '127.0.0.1' }, { 'X-Real-IP': '127.0.0.1' },
    { 'X-Client-IP': '127.0.0.1' }, { 'X-Originating-IP': '127.0.0.1' },
    { 'X-Remote-IP': '127.0.0.1' }, { 'Forwarded': 'for=127.0.0.1' },
    { 'X-Forwarded': '127.0.0.1' }, { 'Forwarded-For': '127.0.0.1' },
];

/**
 * Fetches interesting endpoints discovered by other modules.
 */
async function getTestableEndpoints(scanId: string, domain: string): Promise<DiscoveredEndpoint[]> {
    try {
        const result = await pool.query(
            `SELECT meta FROM artifacts WHERE type = 'discovered_endpoints' AND meta->>'scan_id' = $1 LIMIT 1`,
            [scanId]
        );
        if (result.rows.length > 0 && result.rows[0].meta.endpoints) {
            const endpoints = result.rows[0].meta.endpoints as DiscoveredEndpoint[];
            // Filter for endpoints most likely to have rate limits
            return endpoints.filter(e => 
                e.path.includes('login') || e.path.includes('register') || 
                e.path.includes('auth') || e.path.includes('api') || e.path.includes('password')
            );
        }
    } catch (e) {
        log('[rateLimitScan] [ERROR] Could not fetch endpoints from database:', (e as Error).message);
    }
    // Fallback if no discovered endpoints are found
    log('[rateLimitScan] No discovered endpoints found, using fallback list.');
    return [
        { url: `https://${domain}/login`, path: '/login' },
        { url: `https://${domain}/api/login`, path: '/api/login' },
        { url: `https://${domain}/auth/login`, path: '/auth/login' },
        { url: `https://${domain}/password/reset`, path: '/password/reset' },
    ];
}

/**
 * Sends a burst of requests to establish a baseline and see if a rate limit is triggered.
 * Now includes inter-burst delays and full response distribution analysis.
 */
async function establishBaseline(endpoint: DiscoveredEndpoint): Promise<{ hasRateLimit: boolean; responseDistribution: Record<number, number> }> {
    log(`[rateLimitScan] Establishing baseline for ${endpoint.url}...`);
    
    const responseDistribution: Record<number, number> = {};
    const chunkSize = 5; // Send requests in smaller chunks
    const interBurstDelay = 100; // 100ms delay between chunks
    
    for (let chunk = 0; chunk < REQUEST_BURST_COUNT / chunkSize; chunk++) {
        const promises = [];
        
        // Send chunk of requests
        for (let i = 0; i < chunkSize; i++) {
            promises.push(
                axios.post(endpoint.url, {u:'test',p:'test'}, { 
                    timeout: REQUEST_TIMEOUT, 
                    validateStatus: () => true 
                }).catch(error => ({ 
                    status: error.response?.status || 0 
                }))
            );
        }
        
        const responses = await Promise.allSettled(promises);
        
        // Collect response status codes
        for (const response of responses) {
            if (response.status === 'fulfilled') {
                const statusCode = response.value.status;
                responseDistribution[statusCode] = (responseDistribution[statusCode] || 0) + 1;
            }
        }
        
        // Add delay between chunks (except for the last chunk)
        if (chunk < (REQUEST_BURST_COUNT / chunkSize) - 1) {
            await new Promise(resolve => setTimeout(resolve, interBurstDelay));
        }
    }
    
    log(`[rateLimitScan] Response distribution for ${endpoint.url}:`, responseDistribution);
    
    // Analyze the response distribution to determine if rate limiting is present
    const has429 = responseDistribution[429] > 0;
    const hasProgressiveFailure = Object.keys(responseDistribution).length > 2; // Multiple status codes suggest rate limiting
    const successRate = (responseDistribution[200] || 0) / REQUEST_BURST_COUNT;
    
    // Rate limiting is likely present if:
    // 1. We got 429 responses, OR
    // 2. We have progressive failure patterns (multiple status codes), OR  
    // 3. Success rate drops significantly (< 80%)
    const hasRateLimit = has429 || hasProgressiveFailure || successRate < 0.8;
    
    return { hasRateLimit, responseDistribution };
}

/**
 * Attempts to bypass a rate limit using various techniques.
 * Now includes delays between bypass attempts to avoid interference.
 */
async function testBypassTechniques(endpoint: DiscoveredEndpoint): Promise<RateLimitTestResult[]> {
    const results: RateLimitTestResult[] = [];
    const testPayload = { user: 'testuser', pass: 'testpass' };
    const bypassDelay = 200; // 200ms delay between bypass attempts

    // 1. IP Spoofing Headers
    for (const header of IP_SPOOFING_HEADERS) {
        try {
            const response = await axios.post(endpoint.url, testPayload, { 
                headers: header, 
                timeout: REQUEST_TIMEOUT, 
                validateStatus: () => true 
            });
            if (response.status !== 429) {
                results.push({ 
                    bypassed: true, 
                    technique: 'IP_SPOOFING_HEADER', 
                    details: `Header: ${Object.keys(header)[0]}`, 
                    statusCode: response.status 
                });
            }
            await new Promise(resolve => setTimeout(resolve, bypassDelay));
        } catch { /* ignore */ }
    }

    // 2. HTTP Method Switching
    try {
        const response = await axios.get(endpoint.url, { 
            params: testPayload, 
            timeout: REQUEST_TIMEOUT, 
            validateStatus: () => true 
        });
        if (response.status !== 429) {
            results.push({ 
                bypassed: true, 
                technique: 'HTTP_METHOD_SWITCH', 
                details: 'Used GET instead of POST', 
                statusCode: response.status 
            });
        }
        await new Promise(resolve => setTimeout(resolve, bypassDelay));
    } catch { /* ignore */ }
    
    // 3. Path Variation
    for (const path of [`${endpoint.path}/`, `${endpoint.path}.json`, endpoint.path.toUpperCase()]) {
        try {
            const url = new URL(endpoint.url);
            url.pathname = path;
            const response = await axios.post(url.toString(), testPayload, { 
                timeout: REQUEST_TIMEOUT, 
                validateStatus: () => true 
            });
            if (response.status !== 429) {
                results.push({ 
                    bypassed: true, 
                    technique: 'PATH_VARIATION', 
                    details: `Path used: ${path}`, 
                    statusCode: response.status 
                });
            }
            await new Promise(resolve => setTimeout(resolve, bypassDelay));
        } catch { /* ignore */ }
    }

    return results;
}

export async function runRateLimitScan(job: { domain: string, scanId: string }): Promise<number> {
    log('[rateLimitScan] Starting comprehensive rate limit scan for', job.domain);
    let findingsCount = 0;

    const endpoints = await getTestableEndpoints(job.scanId, job.domain);
    if (endpoints.length === 0) {
        log('[rateLimitScan] No testable endpoints found. Skipping.');
        return 0;
    }

    log(`[rateLimitScan] Found ${endpoints.length} endpoints to test.`);

    for (const endpoint of endpoints) {
        const { hasRateLimit, responseDistribution } = await establishBaseline(endpoint);

        if (!hasRateLimit) {
            log(`[rateLimitScan] No baseline rate limit detected on ${endpoint.url}.`);
            const artifactId = await insertArtifact({
                type: 'rate_limit_missing',
                val_text: `No rate limiting detected on endpoint: ${endpoint.path}`,
                severity: 'MEDIUM',
                src_url: endpoint.url,
                meta: { 
                    scan_id: job.scanId, 
                    scan_module: 'rateLimitScan', 
                    endpoint: endpoint.path,
                    response_distribution: responseDistribution
                }
            });
            await insertFinding(artifactId, 'MISSING_RATE_LIMITING', `Implement strict rate limiting on this endpoint (${endpoint.path}) to prevent brute-force attacks.`, `The endpoint did not show rate limiting behavior after ${REQUEST_BURST_COUNT} rapid requests. Response distribution: ${JSON.stringify(responseDistribution)}`);
            findingsCount++;
            continue;
        }

        log(`[rateLimitScan] Baseline rate limit detected on ${endpoint.url}. Testing for bypasses...`);
        
        // Wait a bit before testing bypasses to let any rate limits reset
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        const bypassResults = await testBypassTechniques(endpoint);
        const successfulBypasses = bypassResults.filter(r => r.bypassed);

        if (successfulBypasses.length > 0) {
            log(`[rateLimitScan] [VULNERABLE] Found ${successfulBypasses.length} bypass techniques for ${endpoint.url}`);
            const artifactId = await insertArtifact({
                type: 'rate_limit_bypass',
                val_text: `Rate limit bypass possible on endpoint: ${endpoint.path}`,
                severity: 'HIGH',
                src_url: endpoint.url,
                meta: {
                    scan_id: job.scanId,
                    scan_module: 'rateLimitScan',
                    endpoint: endpoint.path,
                    bypasses: successfulBypasses,
                    baseline_distribution: responseDistribution
                }
            });
            await insertFinding(artifactId, 'RATE_LIMIT_BYPASS', `The rate limiting implementation on ${endpoint.path} can be bypassed. Ensure that the real client IP is correctly identified and that logic is not easily evaded by simple transformations.`, `Successful bypass techniques: ${successfulBypasses.map(b => b.technique).join(', ')}.`);
            findingsCount++;
        } else {
            log(`[rateLimitScan] Rate limiting on ${endpoint.url} appears to be robust.`);
        }
    }

    await insertArtifact({
        type: 'scan_summary',
        val_text: `Rate limit scan completed: ${findingsCount} issues found`,
        severity: 'INFO',
        meta: {
            scan_id: job.scanId,
            scan_module: 'rateLimitScan',
            total_findings: findingsCount,
            endpoints_tested: endpoints.length,
            timestamp: new Date().toISOString()
        }
    });

    return findingsCount;
}
</file>

<file path="rdpVpnTemplates.ts">
/**
 * RDP/VPN Templates Module
 * 
 * Uses Nuclei templates to detect exposed RDP services and vulnerable VPN portals
 * including FortiNet, Palo Alto GlobalProtect, and other remote access solutions.
 */

import * as fs from 'node:fs/promises';
import { insertArtifact, insertFinding, pool } from '../core/artifactStore.js';
import { log as rootLog } from '../core/logger.js';
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
    const { rows: urlRows } = await pool.query(
      `SELECT val_text FROM artifacts 
       WHERE type='url' AND meta->>'scan_id'=$1`,
      [scanId]
    );
    
    urlRows.forEach(row => {
      targets.add(row.val_text.trim());
    });
    
    // Get hostnames and subdomains to construct URLs
    const { rows: hostRows } = await pool.query(
      `SELECT val_text FROM artifacts 
       WHERE type IN ('hostname', 'subdomain') AND meta->>'scan_id'=$1`,
      [scanId]
    );
    
    const hosts = new Set([domain]);
    hostRows.forEach(row => {
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
</file>

<file path="scanGitRepos.ts">
/**
 * Git repository scanning module using TruffleHog
 * Separated from web asset scanning for better resource management
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { log } from '../core/logger.js';
import { TRUFFLEHOG_GIT_DEPTH } from '../core/env.js';

const exec = promisify(execFile);

// Import processTrufflehogOutput from the main module
// This function will be passed as a parameter to avoid circular imports
type ProcessTrufflehogOutputFn = (stdout: string, source_type: 'git' | 'http' | 'file', src_url: string, scanId?: string) => Promise<number>;

/**
 * Scan a single Git repository with TruffleHog
 * @param url - Git repository URL
 * @param scanId - Scan identifier
 * @param processTrufflehogOutput - Function to process TruffleHog output
 * @param depth - Maximum depth for Git history scan
 * @returns Number of findings
 */
export async function scanGitRepo(
    url: string, 
    scanId: string, 
    processTrufflehogOutput: ProcessTrufflehogOutputFn,
    depth: number = TRUFFLEHOG_GIT_DEPTH
): Promise<number> {
    log(`[trufflehog] [Git Scan] Starting scan for repository: ${url} (depth: ${depth})`);
    
    try {
        const { stdout, stderr } = await exec('trufflehog', [
            'git',
            url,
            '--json',
            '--no-verification',
            `--max-depth=${depth}`
        ], { 
            maxBuffer: 20 * 1024 * 1024, // 20MB buffer for Git history
            timeout: 120000 // 2 minute timeout for Git operations
        });

        if (stderr) {
            log(`[trufflehog] [Git Scan] [STDERR] for ${url}:`, stderr);
        }
        
        const findings = await processTrufflehogOutput(stdout, 'git', url, scanId);
        log(`[trufflehog] [Git Scan] Completed scan for ${url}: ${findings} findings`);
        
        return findings;
    } catch (err) {
        log(`[trufflehog] [Git Scan] Error scanning repository ${url}:`, (err as Error).message);
        return 0;
    }
}

/**
 * Scan multiple Git repositories sequentially to control memory usage
 * @param urls - Array of Git repository URLs
 * @param scanId - Scan identifier
 * @param processTrufflehogOutput - Function to process TruffleHog output
 * @param maxRepos - Maximum number of repositories to scan
 * @returns Total number of findings across all repositories
 */
export async function scanGitRepos(
    urls: string[], 
    scanId: string, 
    processTrufflehogOutput: ProcessTrufflehogOutputFn,
    maxRepos: number = 10
): Promise<number> {
    const reposToScan = urls.slice(0, maxRepos);
    log(`[trufflehog] [Git Scan] Starting scan of ${reposToScan.length} repositories (max: ${maxRepos})`);
    
    let totalFindings = 0;
    
    // Process repositories sequentially to avoid memory issues
    for (const url of reposToScan) {
        try {
            const findings = await scanGitRepo(url, scanId, processTrufflehogOutput);
            totalFindings += findings;
            
            // Small delay between repositories to prevent resource exhaustion
            await new Promise(resolve => setTimeout(resolve, 1000));
        } catch (error) {
            log(`[trufflehog] [Git Scan] Failed to scan repository ${url}:`, (error as Error).message);
        }
    }
    
    log(`[trufflehog] [Git Scan] Completed scan of ${reposToScan.length} repositories: ${totalFindings} total findings`);
    return totalFindings;
}

export default scanGitRepo;
</file>

<file path="shodan.ts">
/*
 * =============================================================================
 * MODULE: shodan.ts  (Hardened v2.1 — compile-clean)
 * =============================================================================
 * Queries the Shodan REST API for exposed services and vulnerabilities
 * associated with a target domain and discovered sub-targets.  
 *
 * Key features
 *   • Built-in rate-limit guard (configurable RPS) and exponential back-off
 *   • Pagination (PAGE_LIMIT pages per query) and target-set cap (TARGET_LIMIT)
 *   • CVSS-aware severity escalation and contextual recommendations
 *   • All findings persisted through insertArtifact / insertFinding
 *   • Lint-clean & strict-mode TypeScript
 * =============================================================================
 */

import axios, { AxiosError } from 'axios';
import { insertArtifact, insertFinding, pool } from '../core/artifactStore.js';
import { log } from '../core/logger.js';

/* -------------------------------------------------------------------------- */
/*  Configuration                                                              */
/* -------------------------------------------------------------------------- */

const API_KEY = process.env.SHODAN_API_KEY ?? '';
if (!API_KEY) throw new Error('SHODAN_API_KEY env var must be set');

const RPS          = Number.parseInt(process.env.SHODAN_RPS ?? '1', 10);       // reqs / second
const PAGE_LIMIT   = Number.parseInt(process.env.SHODAN_PAGE_LIMIT ?? '10', 10);
const TARGET_LIMIT = Number.parseInt(process.env.SHODAN_TARGET_LIMIT ?? '100', 10);

const SEARCH_BASE  = 'https://api.shodan.io/shodan/host/search';

/* -------------------------------------------------------------------------- */
/*  Types                                                                      */
/* -------------------------------------------------------------------------- */

interface ShodanMatch {
  ip_str: string;
  port: number;
  location?: { country_name?: string; city?: string };
  org?: string;
  isp?: string;
  product?: string;
  version?: string;
  vulns?: Record<string, { cvss?: number }>;
  ssl?: { cert?: { expired?: boolean } };
  hostnames?: string[];
}

interface ShodanResponse {
  matches: ShodanMatch[];
  total: number;
}

/* -------------------------------------------------------------------------- */
/*  Severity helpers                                                           */
/* -------------------------------------------------------------------------- */

const PORT_RISK: Record<number, 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'> = {
  21:  'MEDIUM',
  22:  'MEDIUM',
  23:  'HIGH',
  25:  'LOW',
  53:  'LOW',
  80:  'LOW',
  110: 'LOW',
  135: 'HIGH',
  139: 'HIGH',
  445: 'HIGH',
  502: 'CRITICAL',  // Modbus TCP
  1883:'CRITICAL',  // MQTT
  3306:'MEDIUM',
  3389:'HIGH',
  5432:'MEDIUM',
  5900:'HIGH',
  6379:'MEDIUM',
  9200:'MEDIUM',
  20000:'CRITICAL', // DNP3
  47808:'CRITICAL', // BACnet
};

type Sev = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

const cvssToSeverity = (s?: number): Sev => {
  if (s === undefined) return 'INFO';
  if (s >= 9) return 'CRITICAL';
  if (s >= 7) return 'HIGH';
  if (s >= 4) return 'MEDIUM';
  return 'LOW';
};

/* -------------------------------------------------------------------------- */
/*  Rate-limited fetch with retry                                              */
/* -------------------------------------------------------------------------- */

const tsQueue: number[] = [];

let apiCallsCount = 0;

async function rlFetch<T>(url: string, attempt = 0): Promise<T> {
  const now = Date.now();
  while (tsQueue.length && now - tsQueue[0] > 1_000) tsQueue.shift();
  if (tsQueue.length >= RPS) {
    await new Promise((r) => setTimeout(r, 1_000 - (now - tsQueue[0])));
  }
  tsQueue.push(Date.now());

  try {
    const res = await axios.get<T>(url, { timeout: 30_000 });
    apiCallsCount++;
    log(`[Shodan] API call ${apiCallsCount} - ${url.includes('search') ? 'search' : 'host'} query`);
    return res.data;
  } catch (err) {
    const ae = err as AxiosError;
    const retriable =
      ae.code === 'ECONNABORTED' || (ae.response && ae.response.status >= 500);
    if (retriable && attempt < 3) {
      const backoff = 500 * 2 ** attempt;
      await new Promise((r) => setTimeout(r, backoff));
      return rlFetch<T>(url, attempt + 1);
    }
    throw err;
  }
}

/* -------------------------------------------------------------------------- */
/*  Recommendation text                                                        */
/* -------------------------------------------------------------------------- */

function buildRecommendation(
  port: number,
  finding: string,
  product: string,
  version: string,
): string {
  if (finding.startsWith('CVE-')) {
    return `Patch ${product || 'service'} ${version || ''} immediately to remediate ${finding}.`;
  }
  if (finding === 'Expired SSL certificate') {
    return 'Renew the TLS certificate and configure automated renewal.';
  }
  switch (port) {
    case 3389:
      return 'Secure RDP with VPN or gateway and enforce MFA.';
    case 445:
    case 139:
      return 'Block SMB/NetBIOS from the Internet; use VPN.';
    case 23:
      return 'Disable Telnet; migrate to SSH.';
    case 5900:
      return 'Avoid exposing VNC publicly; tunnel through SSH or VPN.';
    case 502:
      return 'CRITICAL: Modbus TCP exposed to internet. Isolate OT networks behind firewall/VPN immediately.';
    case 1883:
      return 'CRITICAL: MQTT broker exposed to internet. Implement authentication and network isolation.';
    case 20000:
      return 'CRITICAL: DNP3 protocol exposed to internet. Air-gap industrial control systems immediately.';
    case 47808:
      return 'CRITICAL: BACnet exposed to internet. Isolate building automation systems behind firewall.';
    default:
      return 'Restrict public access and apply latest security hardening guides.';
  }
}

/* -------------------------------------------------------------------------- */
/*  Persist a single Shodan match                                              */
/* -------------------------------------------------------------------------- */

async function persistMatch(
  m: ShodanMatch,
  scanId: string,
  searchTarget: string,
): Promise<number> {
  let inserted = 0;

  /* --- baseline severity ------------------------------------------------- */
  let sev: Sev = (PORT_RISK[m.port] ?? 'INFO') as Sev;
  const findings: string[] = [];

  /* --- ICS/OT protocol detection ----------------------------------------- */
  const ICS_PORTS = [502, 1883, 20000, 47808];
  const ICS_PRODUCTS = ['modbus', 'mqtt', 'bacnet', 'dnp3', 'scada'];
  
  let isICSProtocol = false;
  if (ICS_PORTS.includes(m.port)) {
    isICSProtocol = true;
    sev = 'CRITICAL';
  }
  
  // Check product field for ICS indicators
  const productLower = (m.product ?? '').toLowerCase();
  if (ICS_PRODUCTS.some(ics => productLower.includes(ics))) {
    isICSProtocol = true;
    if (sev === 'INFO') sev = 'CRITICAL';
  }

  if (m.ssl?.cert?.expired) {
    findings.push('Expired SSL certificate');
    if (sev === 'INFO') sev = 'LOW';
  }

  // CVE processing removed - handled by techStackScan module

  const artId = await insertArtifact({
    type: 'shodan_service',
    val_text: `${m.ip_str}:${m.port} ${m.product ?? ''} ${m.version ?? ''}`.trim(),
    severity: sev,
    src_url: `https://www.shodan.io/host/${m.ip_str}`,
    meta: {
      scan_id: scanId,
      search_term: searchTarget,
      ip: m.ip_str,
      port: m.port,
      product: m.product,
      version: m.version,
      hostnames: m.hostnames ?? [],
      location: m.location,
      org: m.org,
      isp: m.isp,
    },
  });
  inserted += 1;

  // Only create findings for genuinely concerning services, not common web ports
  const COMMON_WEB_PORTS = [80, 443, 8080, 8443];
  const shouldCreateFinding = isICSProtocol || 
                             sev === 'CRITICAL' || 
                             sev === 'HIGH' || 
                             !COMMON_WEB_PORTS.includes(m.port) ||
                             findings.length > 0; // Has specific security issues

  if (shouldCreateFinding) {
    // Only create generic finding if no specific issues found
    if (findings.length === 0) {
      findings.push(`Exposed service on port ${m.port}`);
    }

    for (const f of findings) {
      // Use specific finding type for ICS/OT protocols
      const findingType = isICSProtocol ? 'OT_PROTOCOL_EXPOSED' : 'EXPOSED_SERVICE';
      
      await insertFinding(
        artId,
        findingType,
        buildRecommendation(m.port, f, m.product ?? '', m.version ?? ''),
        f,
      );
      inserted += 1;
    }
  }
  return inserted;
}

/* -------------------------------------------------------------------------- */
/*  Main exported function                                                     */
/* -------------------------------------------------------------------------- */

export async function runShodanScan(job: {
  domain: string;
  scanId: string;
  companyName: string;
}): Promise<number> {
  const { domain, scanId } = job;
  log(`[Shodan] Start scan for ${domain}`);

  /* Build target set ------------------------------------------------------ */
  const targets = new Set<string>([domain]);

  const dbRes = await pool.query(
    `SELECT DISTINCT val_text
     FROM artifacts
     WHERE meta->>'scan_id' = $1
       AND type IN ('subdomain','hostname','ip')
     LIMIT $2`,
    [scanId, TARGET_LIMIT],
  );
  dbRes.rows.forEach((r) => targets.add(r.val_text.trim()));

  log(`[Shodan] Querying ${targets.size} targets (PAGE_LIMIT=${PAGE_LIMIT})`);

  let totalItems = 0;
  const seenServices = new Set<string>(); // Deduplication for similar services

  for (const tgt of targets) {
    let fetched = 0;
    for (let page = 1; page <= PAGE_LIMIT; page += 1) {
      const q = encodeURIComponent(`hostname:${tgt}`);
      const url = `${SEARCH_BASE}?key=${API_KEY}&query=${q}&page=${page}`;

      try {
        // eslint-disable-next-line no-await-in-loop
        const data = await rlFetch<ShodanResponse>(url);
        if (data.matches.length === 0) break;

        for (const m of data.matches) {
          // Deduplicate similar services to prevent spam
          const serviceKey = `${m.ip_str}:${m.port}:${m.product || 'unknown'}`;
          if (seenServices.has(serviceKey)) {
            continue; // Skip duplicate service
          }
          seenServices.add(serviceKey);

          // eslint-disable-next-line no-await-in-loop
          totalItems += await persistMatch(m, scanId, tgt);
        }

        fetched += data.matches.length;
        if (fetched >= data.total) break;
      } catch (err) {
        log(`[Shodan] ERROR for ${tgt} (page ${page}): ${(err as Error).message}`);
        break; // next target
      }
    }
  }

  await insertArtifact({
    type: 'scan_summary',
    val_text: `Shodan scan: ${totalItems} services found, ${seenServices.size} unique after deduplication`,
    severity: 'INFO',
    meta: { 
      scan_id: scanId, 
      total_items: totalItems, 
      unique_services: seenServices.size,
      api_calls_used: apiCallsCount,
      targets_queried: targets.size,
      timestamp: new Date().toISOString() 
    },
  });

  log(`[Shodan] Done — ${totalItems} services found, ${seenServices.size} unique after deduplication, ${apiCallsCount} API calls for ${targets.size} targets`);
  return totalItems;
}

export default runShodanScan;
</file>

<file path="spfDmarc.ts">
/*
 * =============================================================================
 * MODULE: spfDmarc.ts (Refactored)
 * =============================================================================
 * This module performs deep analysis of a domain's email security posture by
 * checking DMARC, SPF, and DKIM configurations.
 *
 * Key Improvements from previous version:
 * 1.  **Recursive SPF Validation:** The SPF check now recursively resolves `include`
 * and `redirect` mechanisms to accurately count DNS lookups.
 * 2.  **Comprehensive DKIM Probing:** Probes for a much wider array of common and
 * provider-specific DKIM selectors.
 * 3.  **BIMI Record Check:** Adds validation for Brand Indicators for Message
 * Identification (BIMI) for enhanced brand trust in email clients.
 * =============================================================================
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { log } from '../core/logger.js';

const exec = promisify(execFile);

interface SpfResult {
  record: string;
  lookups: number;
  error?: 'TOO_MANY_LOOKUPS' | 'REDIRECT_LOOP' | 'MULTIPLE_RECORDS' | 'NONE_FOUND';
  allMechanism: '~all' | '-all' | '?all' | 'none';
}

/**
 * REFACTOR: A new recursive function to fully resolve an SPF record.
 * It follows includes and redirects to accurately count DNS lookups.
 */
async function resolveSpfRecord(domain: string, lookups: number = 0, redirectChain: string[] = []): Promise<SpfResult> {
  const MAX_LOOKUPS = 10;

  if (lookups > MAX_LOOKUPS) {
    return { record: '', lookups, error: 'TOO_MANY_LOOKUPS', allMechanism: 'none' };
  }
  if (redirectChain.includes(domain)) {
    return { record: '', lookups, error: 'REDIRECT_LOOP', allMechanism: 'none' };
  }

  try {
    const { stdout } = await exec('dig', ['TXT', domain, '+short'], { timeout: 10000 });
    const records = stdout.trim().split('\n').map(s => s.replace(/"/g, '')).filter(r => r.startsWith('v=spf1'));

    if (records.length === 0) return { record: '', lookups, error: 'NONE_FOUND', allMechanism: 'none' };
    if (records.length > 1) return { record: records.join(' | '), lookups, error: 'MULTIPLE_RECORDS', allMechanism: 'none' };

    const record = records[0];
    const mechanisms = record.split(' ').slice(1);
    let currentLookups = lookups;
    let finalResult: SpfResult = { record, lookups, allMechanism: 'none' };

    for (const mech of mechanisms) {
      if (mech.startsWith('include:')) {
        currentLookups++;
        const includeDomain = mech.split(':')[1];
        const result = await resolveSpfRecord(includeDomain, currentLookups, [...redirectChain, domain]);
        currentLookups = result.lookups;
        if (result.error) return { ...finalResult, error: result.error, lookups: currentLookups };
      } else if (mech.startsWith('redirect=')) {
        currentLookups++;
        const redirectDomain = mech.split('=')[1];
        return resolveSpfRecord(redirectDomain, currentLookups, [...redirectChain, domain]);
      } else if (mech.startsWith('a') || mech.startsWith('mx') || mech.startsWith('exists:')) {
        currentLookups++;
      }
    }

    finalResult.lookups = currentLookups;
    if (record.includes('-all')) finalResult.allMechanism = '-all';
    else if (record.includes('~all')) finalResult.allMechanism = '~all';
    else if (record.includes('?all')) finalResult.allMechanism = '?all';

    if (currentLookups > MAX_LOOKUPS) {
        finalResult.error = 'TOO_MANY_LOOKUPS';
    }

    return finalResult;
  } catch (error) {
    return { record: '', lookups, error: 'NONE_FOUND', allMechanism: 'none' };
  }
}

export async function runSpfDmarc(job: { domain: string; scanId?: string }): Promise<number> {
  log('[spfDmarc] Starting email security scan for', job.domain);
  let findingsCount = 0;

  // --- 1. DMARC Check (Existing logic is good) ---
  log('[spfDmarc] Checking DMARC record...');
  try {
    const { stdout: dmarcOut } = await exec('dig', ['txt', `_dmarc.${job.domain}`, '+short']);
    if (!dmarcOut.trim()) {
        const artifactId = await insertArtifact({ type: 'dmarc_missing', val_text: `DMARC record missing`, severity: 'MEDIUM', meta: { scan_id: job.scanId, scan_module: 'spfDmarc' } });
        await insertFinding(artifactId, 'EMAIL_SECURITY_GAP', 'Implement a DMARC policy (start with p=none) to gain visibility into email channels and begin protecting against spoofing.', 'No DMARC record found.');
        findingsCount++;
    } else if (/p=none/i.test(dmarcOut)) {
        const artifactId = await insertArtifact({ type: 'dmarc_weak', val_text: `DMARC policy is not enforcing`, severity: 'LOW', meta: { record: dmarcOut.trim(), scan_id: job.scanId, scan_module: 'spfDmarc' } });
        await insertFinding(artifactId, 'EMAIL_SECURITY_WEAKNESS', 'Strengthen DMARC policy from p=none to p=quarantine or p=reject to actively prevent email spoofing.', 'DMARC policy is in monitoring mode (p=none) and provides no active protection.');
        findingsCount++;
    }
  } catch (e) {
      log('[spfDmarc] DMARC check failed or no record found.');
  }

  // --- 2. Recursive SPF Check ---
  log('[spfDmarc] Performing recursive SPF check...');
  const spfResult = await resolveSpfRecord(job.domain);
  
  if (spfResult.error === 'NONE_FOUND') {
      const artifactId = await insertArtifact({ type: 'spf_missing', val_text: `SPF record missing`, severity: 'MEDIUM', meta: { scan_id: job.scanId, scan_module: 'spfDmarc' } });
      await insertFinding(artifactId, 'EMAIL_SECURITY_GAP', 'Implement an SPF record to specify all authorized mail servers. This is a foundational step for DMARC.', 'No SPF record found.');
      findingsCount++;
  } else if (spfResult.error) {
      const artifactId = await insertArtifact({ type: 'spf_invalid', val_text: `SPF record is invalid: ${spfResult.error}`, severity: 'HIGH', meta: { record: spfResult.record, lookups: spfResult.lookups, error: spfResult.error, scan_id: job.scanId, scan_module: 'spfDmarc' } });
      await insertFinding(artifactId, 'EMAIL_SECURITY_MISCONFIGURATION', `Correct the invalid SPF record. The error '${spfResult.error}' can cause email delivery failures for legitimate mail.`, `SPF record validation failed with error: ${spfResult.error}.`);
      findingsCount++;
  } else {
    if (spfResult.allMechanism === '~all' || spfResult.allMechanism === '?all') {
        const artifactId = await insertArtifact({ type: 'spf_weak', val_text: `SPF policy is too permissive (${spfResult.allMechanism})`, severity: 'LOW', meta: { record: spfResult.record, scan_id: job.scanId, scan_module: 'spfDmarc' } });
        await insertFinding(artifactId, 'EMAIL_SECURITY_WEAKNESS', 'Strengthen SPF policy by using "-all" (hard fail) instead of "~all" (soft fail) or "?all" (neutral).', 'The SPF record does not instruct receivers to reject unauthorized mail.');
        findingsCount++;
    }
  }
  
  // --- 3. Comprehensive DKIM Check ---
  log('[spfDmarc] Probing for common DKIM selectors...');
  // REFACTOR: Expanded list of provider-specific DKIM selectors.
  const currentYear = new Date().getFullYear();
  const commonSelectors = [
      'default', 'selector1', 'selector2', 'google', 'k1', 'k2', 'mandrill', 
      'sendgrid', 'mailgun', 'zoho', 'amazonses', 'dkim', 'm1', 'pm', 'o365',
      'mailchimp', 'constantcontact', 'hubspot', 'salesforce', // Added providers
      `s${currentYear}`, `s${currentYear - 1}`
  ];
  let dkimFound = false;
  
  for (const selector of commonSelectors) {
    try {
      const { stdout: dkimOut } = await exec('dig', ['txt', `${selector}._domainkey.${job.domain}`, '+short']);
      if (dkimOut.trim().includes('k=rsa')) {
        dkimFound = true;
        log(`[spfDmarc] Found DKIM record with selector: ${selector}`);
        break;
      }
    } catch (dkimError) { /* Selector does not exist */ }
  }
  
  if (!dkimFound) {
    const artifactId = await insertArtifact({ type: 'dkim_missing', val_text: `DKIM record not detected for common selectors`, severity: 'LOW', meta: { selectors_checked: commonSelectors, scan_id: job.scanId, scan_module: 'spfDmarc' } });
    await insertFinding(artifactId, 'EMAIL_SECURITY_GAP', 'Implement DKIM signing for outbound email to cryptographically verify message integrity. This is a critical component for DMARC alignment.', 'Could not find a valid DKIM record using a wide range of common selectors.');
    findingsCount++;
  }

  // REFACTOR: --- 4. BIMI Check (Optional Enhancement) ---
  log('[spfDmarc] Checking for BIMI record...');
  try {
      const { stdout: bimiOut } = await exec('dig', ['txt', `default._bimi.${job.domain}`, '+short']);
      if (bimiOut.trim().startsWith('v=BIMI1')) {
          log(`[spfDmarc] Found BIMI record: ${bimiOut.trim()}`);
          await insertArtifact({
              type: 'bimi_found',
              val_text: 'BIMI record is properly configured',
              severity: 'INFO',
              meta: { record: bimiOut.trim(), scan_id: job.scanId, scan_module: 'spfDmarc' }
          });
      } else {
          // A missing BIMI record is not a security failure, but an opportunity.
          await insertArtifact({
              type: 'bimi_missing',
              val_text: 'BIMI record not found',
              severity: 'INFO',
              meta: { scan_id: job.scanId, scan_module: 'spfDmarc' }
          });
      }
  } catch (bimiError) {
      log('[spfDmarc] BIMI check failed or no record found.');
  }
  
  log('[spfDmarc] Completed email security scan, found', findingsCount, 'issues');
  return findingsCount;
}
</file>

<file path="spiderFoot.ts">
/*
 * =============================================================================
 * MODULE: spiderFoot.ts (Refactored)
 * =============================================================================
 * This module is a robust wrapper for the SpiderFoot OSINT tool.
 *
 * Key Improvements from previous version:
 * 1.  **Advanced Protocol Probing:** When an INTERNET_NAME (domain) is found,
 * this module now actively probes for both http:// and https:// and performs
 * an advanced health check, verifying a `200 OK` status before creating a
 * URL artifact. This improves the accuracy of downstream tools.
 * 2.  **API Key Dependency Warnings:** The module now checks for critical API
 * keys at startup. If keys are missing, it creates a `scan_warning` artifact
 * to make the potentially incomplete results visible in the scan output.
 * =============================================================================
 */

import { execFile, exec as execRaw } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs/promises';
import axios from 'axios';
import { insertArtifact } from '../core/artifactStore.js';
import { log } from '../core/logger.js';

const execFileAsync = promisify(execFile);
const execAsync = promisify(execRaw);

const ALLOW_SET = new Set<string>([
  'DOMAIN_NAME', 'INTERNET_DOMAIN', 'SUBDOMAIN', 'INTERNET_NAME', 'CO_HOSTED_SITE',
  'NETBLOCK_OWNER', 'RAW_RIR_DATA', 'AFFILIATE_INTERNET_NAME', 'IP_ADDRESS',
  'EMAILADDR', 'VULNERABILITY_CVE', 'MALICIOUS_IPADDR', 'MALICIOUS_INTERNET_NAME',
  'LEAKSITE_CONTENT', 'PASTESITE_CONTENT',
  // HIBP-specific result types
  'EMAILADDR_COMPROMISED', 'BREACH_DATA', 'ACCOUNT_EXTERNAL_COMPROMISED'
]);
const DENY_SET = new Set<string>();

function shouldPersist(rowType: string): boolean {
  const mode = (process.env.SPIDERFOOT_FILTER_MODE || 'allow').toLowerCase();
  switch (mode) {
    case 'off': return true;
    case 'deny': return !DENY_SET.has(rowType);
    case 'allow': default: return ALLOW_SET.has(rowType);
  }
}

/**
 * REFACTOR: Implemented advanced health checks. Now uses a GET request and
 * verifies a 200 OK status for more reliable endpoint validation.
 */
async function probeAndCreateUrlArtifacts(domain: string, baseArtifact: any): Promise<number> {
    const protocols = ['https', 'http'];
    let urlsCreated = 0;
    for (const proto of protocols) {
        const url = `${proto}://${domain}`;
        try {
            const response = await axios.get(url, { 
                timeout: 8000,
                headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36' }
            });

            // Check for a definitive "OK" status. This is more reliable than just not erroring.
            if (response.status === 200) {
                await insertArtifact({ ...baseArtifact, type: 'url', val_text: url });
                urlsCreated++;
            }
        } catch (error) {
            // Ignore connection errors, 404s, 5xx, etc.
        }
    }
    return urlsCreated;
}

const TARGET_MODULES = [
  'sfp_crtsh', 'sfp_sublist3r', 'sfp_chaos',
  'sfp_r7_dns', 'sfp_haveibeenpwnd', 'sfp_psbdmp', 'sfp_skymem',
  'sfp_sslcert', 'sfp_nuclei', 'sfp_whois', 'sfp_dnsresolve',
].join(',');

async function resolveSpiderFootCommand(): Promise<string | null> {
    if (process.env.SPIDERFOOT_CMD) return process.env.SPIDERFOOT_CMD;
    const candidates = [
        '/opt/spiderfoot/sf.py', '/usr/local/bin/sf', 'sf', 'spiderfoot.py',
    ];
    for (const cand of candidates) {
        try {
            if (cand.startsWith('/')) {
                await fs.access(cand, fs.constants.X_OK);
                return cand.includes('.py') ? `python3 ${cand}` : cand;
            }
            await execFileAsync('which', [cand]);
            return cand;
        } catch { /* next */ }
    }
    return null;
}

export async function runSpiderFoot(job: { domain: string; scanId: string }): Promise<number> {
    const { domain, scanId } = job;
    log(`[SpiderFoot] Starting scan for ${domain} (scanId=${scanId})`);

    const spiderFootCmd = await resolveSpiderFootCommand();
    if (!spiderFootCmd) {
        log('[SpiderFoot] [CRITICAL] Binary not found – module skipped');
        await insertArtifact({
            type: 'scan_error',
            val_text: 'SpiderFoot binary not found in container',
            severity: 'HIGH',
            meta: { scan_id: scanId, module: 'spiderfoot' },
        });
        return 0;
    }

    const confDir = `/tmp/spiderfoot-${scanId}`;
    await fs.mkdir(confDir, { recursive: true });

    const config = {
        haveibeenpwnd_api_key: process.env.HIBP_API_KEY ?? '',
        chaos_api_key: process.env.CHAOS_API_KEY ?? '',
        dbconnectstr: `sqlite:////tmp/spiderfoot-${scanId}.db`,
        webport: '5001',
        webhost: '127.0.0.1',
    };
    
    const missingKeys = Object.entries(config)
        .filter(([key, value]) => key.endsWith('_api_key') && !value)
        .map(([key]) => key);
    
    if (missingKeys.length > 0) {
        const warningText = `SpiderFoot scan may be incomplete. Missing API keys: ${missingKeys.join(', ')}`;
        log(`[SpiderFoot] [WARNING] ${warningText}`);
        await insertArtifact({
            type: 'scan_warning',
            val_text: warningText,
            severity: 'LOW',
            meta: { scan_id: scanId, module: 'spiderfoot', missing_keys: missingKeys }
        });
    }

    const mask = (v: string) => (v ? '✅' : '❌');
    log(`[SpiderFoot] API keys: HIBP ${mask(config.haveibeenpwnd_api_key)}, Chaos ${mask(config.chaos_api_key)} (Shodan/Censys handled by dedicated modules)`);
    await fs.writeFile(`${confDir}/spiderfoot.conf`, Object.entries(config).map(([k, v]) => `${k}=${v}`).join('\n'));
    
    const cmd = `${spiderFootCmd} -q -s ${domain} -m ${TARGET_MODULES} -o json`;
    log('[SpiderFoot] Command:', cmd);
    
    const env = { ...process.env, SF_CONFDIR: confDir };
    const TIMEOUT_MS = parseInt(process.env.SPIDERFOOT_TIMEOUT_MS || '300000', 10);
    
    try {
        const start = Date.now();
        const { stdout, stderr } = await execAsync(cmd, { env, timeout: TIMEOUT_MS, shell: '/bin/sh', maxBuffer: 20 * 1024 * 1024 });
        if (stderr) log('[SpiderFoot-stderr]', stderr.slice(0, 400));
        log(`[SpiderFoot] Raw output size: ${stdout.length} bytes`);

        const results = stdout.trim() ? JSON.parse(stdout) : [];
        let artifacts = 0;
        const linkUrls: string[] = []; // Collect URLs for TruffleHog
        
        for (const row of results) {
            if (!shouldPersist(row.type)) continue;

            const base = {
                severity: /VULNERABILITY|MALICIOUS/.test(row.type) ? 'HIGH' : 'INFO',
                src_url: row.sourceUrl ?? domain,
                meta: { scan_id: scanId, spiderfoot_type: row.type, source_module: row.module },
            } as const;
            
            let created = false;
            switch (row.type) {
                // Network Infrastructure
                case 'IP_ADDRESS':
                    await insertArtifact({ ...base, type: 'ip', val_text: row.data });
                    created = true;
                    break;
                    
                case 'INTERNET_NAME':
                case 'AFFILIATE_INTERNET_NAME':
                case 'CO_HOSTED_SITE':
                    await insertArtifact({ ...base, type: 'hostname', val_text: row.data });
                    const urlsCreated = await probeAndCreateUrlArtifacts(row.data, base);
                    artifacts += (1 + urlsCreated);
                    continue;
                    
                case 'SUBDOMAIN':
                    await insertArtifact({ ...base, type: 'subdomain', val_text: row.data });
                    created = true;
                    break;
                    
                // Personal Information
                case 'EMAILADDR':
                    await insertArtifact({ ...base, type: 'email', val_text: row.data });
                    created = true;
                    break;
                    
                case 'PHONE_NUMBER':
                    await insertArtifact({ ...base, type: 'phone_number', val_text: row.data });
                    created = true;
                    break;
                    
                case 'USERNAME':
                    await insertArtifact({ ...base, type: 'username', val_text: row.data });
                    created = true;
                    break;
                    
                case 'GEOINFO':
                    await insertArtifact({ ...base, type: 'geolocation', val_text: row.data });
                    created = true;
                    break;
                    
                // Vulnerabilities
                case 'VULNERABILITY_CVE_CRITICAL':
                case 'VULNERABILITY_CVE_HIGH':
                case 'VULNERABILITY':
                    await insertArtifact({ ...base, type: 'vuln', val_text: row.data, severity: 'HIGH' });
                    created = true;
                    break;
                    
                // Malicious Indicators
                case 'MALICIOUS_IPADDR':
                case 'MALICIOUS_SUBDOMAIN':
                case 'MALICIOUS_INTERNET_NAME':
                    await insertArtifact({ ...base, type: 'malicious_indicator', val_text: row.data, severity: 'HIGH' });
                    created = true;
                    break;
                    
                // Data Leaks
                case 'LEAKSITE_CONTENT':
                case 'DARKWEB_MENTION':
                case 'PASTESITE_CONTENT':
                    await insertArtifact({ ...base, type: 'data_leak', val_text: row.data, severity: 'MEDIUM' });
                    created = true;
                    break;
                    
                // URLs for TruffleHog
                case 'CODE_REPOSITORY':
                case 'LINKED_URL_EXTERNAL':
                case 'LINKED_URL_INTERNAL':
                    // Check if URL looks like a Git repo or paste site
                    const url = row.data.toLowerCase();
                    if (url.includes('github.com') || url.includes('gitlab.com') || 
                        url.includes('bitbucket.org') || url.includes('pastebin.com') ||
                        url.includes('paste.') || url.includes('.git') || 
                        url.includes('gist.github.com')) {
                        linkUrls.push(row.data);
                        log(`[SpiderFoot] Added to TruffleHog queue: ${row.data}`);
                    }
                    await insertArtifact({ ...base, type: 'linked_url', val_text: row.data });
                    created = true;
                    break;
                    
                // Default case for less common types
                default:
                    await insertArtifact({ ...base, type: 'intel', val_text: row.data });
                    created = true;
                    break;
            }
            if (created) artifacts++;
        }
        
        // Save collected URLs for TruffleHog
        if (linkUrls.length > 0) {
            log(`[SpiderFoot] Collected linkUrls for TruffleHog:`, linkUrls);
            await fs.writeFile(`/tmp/spiderfoot-links-${scanId}.json`, JSON.stringify(linkUrls, null, 2));
            log(`[SpiderFoot] Saved ${linkUrls.length} URLs to /tmp/spiderfoot-links-${scanId}.json for TruffleHog`);
        }
        
        await insertArtifact({
            type: 'scan_summary',
            val_text: `SpiderFoot scan completed: ${artifacts} artifacts`,
            severity: 'INFO',
            meta: { scan_id: scanId, duration_ms: Date.now() - start, results_processed: results.length, artifacts_created: artifacts, timestamp: new Date().toISOString() },
        });
        
        log(`[SpiderFoot] ✔️ Completed – ${artifacts} artifacts`);
        return artifacts;
    } catch (err: any) {
        log('[SpiderFoot] ❌ Scan failed:', err.message);
        await insertArtifact({
            type: 'scan_error',
            val_text: `SpiderFoot scan failed: ${err.message}`,
            severity: 'HIGH',
            meta: { scan_id: scanId, module: 'spiderfoot' },
        });
        return 0;
    }
}
</file>

<file path="targetDiscovery.ts">
/* =============================================================================
 * MODULE: targetDiscovery.ts
 * =============================================================================
 * Target discovery and classification for security scanning.
 * Handles URL discovery, asset type classification, and third-party origin detection.
 * =============================================================================
 */

import { pool } from '../core/artifactStore.js';
import { log as rootLog } from '../core/logger.js';
import { withPage } from '../util/dynamicBrowser.js';
// Removed import for deleted module

const log = (...m: unknown[]) => rootLog('[targetDiscovery]', ...m);

// Configuration
const CONFIG = {
  PAGE_TIMEOUT_MS: 25_000,
  MAX_THIRD_PARTY_REQUESTS: 200,
  MAX_DISCOVERED_ENDPOINTS: 100,
} as const;

// Types
export interface ClassifiedTarget {
  url: string;
  assetType: 'html' | 'nonHtml';
}

export interface TargetDiscoveryConfig {
  maxThirdPartyRequests?: number;
  pageTimeout?: number;
  maxDiscoveredEndpoints?: number;
  enablePuppeteer?: boolean;
}

export interface TargetDiscoveryResult {
  primary: ClassifiedTarget[];
  thirdParty: ClassifiedTarget[];
  total: number;
  metrics: {
    htmlCount: number;
    nonHtmlCount: number;
    discoveredCount: number;
    thirdPartySkipped: boolean;
  };
}

export class TargetDiscovery {
  constructor(private config: TargetDiscoveryConfig = {}) {}

  /* Filter out problematic domains that cause issues with scanners */
  private isProblematicDomain(hostname: string): boolean {
    const problematicDomains = [
      // CDNs and large platforms that scanners struggle with
      'google.com', 'www.google.com', 'gstatic.com', 'www.gstatic.com',
      'googleapis.com', 'fonts.googleapis.com', 'fonts.gstatic.com',
      'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
      'cloudflare.com', 'amazonaws.com', 'azure.com',
      // Content delivery networks
      'cdn.', 'cdnjs.', 'jsdelivr.', 'unpkg.com',
      'contentful.com', 'ctfassets.net'
    ];
    
    return problematicDomains.some(domain => 
      hostname === domain || hostname.endsWith('.' + domain) || hostname.startsWith(domain)
    );
  }

  /* Build enhanced target list with asset type classification */
  async buildTargets(scanId: string, domain: string): Promise<ClassifiedTarget[]> {
    const baseTargets = [`https://${domain}`, `https://www.${domain}`];
    const targets = new Map<string, ClassifiedTarget>();
    
    // Add base domain targets (always HTML)
    baseTargets.forEach(url => {
      targets.set(url, { url, assetType: 'html' });
    });
    
    try {
      const { rows } = await pool.query(
        `SELECT jsonb_path_query_array(meta, '$.endpoints[*].url') AS urls
         FROM artifacts
         WHERE type='discovered_endpoints' AND meta->>'scan_id'=$1
         LIMIT 1`,
        [scanId]
      );
      
      // Add discovered endpoints with classification (limit for performance)
      const maxEndpoints = this.config.maxDiscoveredEndpoints || CONFIG.MAX_DISCOVERED_ENDPOINTS;
      const discoveredCount = rows[0]?.urls?.length || 0;
      
      rows[0]?.urls?.slice(0, maxEndpoints).forEach((url: string) => {
        if (url && typeof url === 'string' && url !== 'null' && url.startsWith('http')) {
          // Additional validation to prevent problematic URLs
          try {
            const urlObj = new URL(url);
            // Skip if URL is valid and not problematic
            if (urlObj.hostname && !this.isProblematicDomain(urlObj.hostname)) {
              const assetType = 'html';
              targets.set(url, { url, assetType });
            }
          } catch {
            // Skip invalid URLs
          }
        }
      });
      
      const htmlCount = Array.from(targets.values()).filter(t => t.assetType === 'html').length;
      const nonHtmlCount = Array.from(targets.values()).filter(t => t.assetType === 'nonHtml').length;
      log(`buildTargets discovered=${discoveredCount} total=${targets.size} (html=${htmlCount}, nonHtml=${nonHtmlCount})`);
      
    } catch (error) {
      log(`buildTargets error: ${(error as Error).message}`);
    }
    
    return Array.from(targets.values());
  }

  /* Third-party sub-resource discovery using shared Puppeteer */
  async discoverThirdPartyOrigins(domain: string): Promise<ClassifiedTarget[]> {
    // Check if Puppeteer is enabled
    const puppeteerEnabled = this.config.enablePuppeteer !== false && process.env.ENABLE_PUPPETEER !== '0';
    if (!puppeteerEnabled) {
      log(`thirdParty=skipped domain=${domain} reason="puppeteer_disabled"`);
      return [];
    }
    
    try {
      return await withPage(async (page) => {
        const origins = new Set<string>();
        
        // Track network requests
        await page.setRequestInterception(true);
        page.on('request', (request) => {
          const url = request.url();
          try {
            const urlObj = new URL(url);
            const origin = urlObj.origin;
            
            // Filter to third-party origins (different eTLD+1) and exclude problematic domains
            if (!origin.includes(domain) && 
                !origin.includes('localhost') && 
                !origin.includes('127.0.0.1') &&
                !this.isProblematicDomain(urlObj.hostname)) {
              origins.add(origin);
            }
          } catch {
            // Invalid URL, ignore
          }
          
          // Continue the request
          request.continue();
        });
        
        // Navigate and wait for resources with fallback
        const pageTimeout = this.config.pageTimeout || CONFIG.PAGE_TIMEOUT_MS;
        try {
          await page.goto(`https://${domain}`, { 
            timeout: pageTimeout,
            waitUntil: 'networkidle2' 
          });
        } catch (navError) {
          // Fallback: try with less strict wait condition
          log(`thirdParty=navigation_fallback domain=${domain} error="${(navError as Error).message}"`);
          await page.goto(`https://${domain}`, { 
            timeout: pageTimeout,
            waitUntil: 'domcontentloaded' 
          });
        }
        
        // Limit results to prevent excessive discovery and classify each one
        const maxRequests = this.config.maxThirdPartyRequests || CONFIG.MAX_THIRD_PARTY_REQUESTS;
        const limitedOrigins = Array.from(origins).slice(0, maxRequests);
        const classifiedTargets = limitedOrigins.map(url => ({
          url,
          assetType: 'html' as const
        }));
        
        const htmlCount = classifiedTargets.length; // All third-party origins are treated as HTML
        const nonHtmlCount = 0; // No non-HTML origins in this discovery method
        log(`thirdParty=discovered domain=${domain} total=${limitedOrigins.length} (html=${htmlCount}, nonHtml=${nonHtmlCount})`);
        
        return classifiedTargets;
      });
      
    } catch (error) {
      log(`thirdParty=error domain=${domain} error="${(error as Error).message}"`);
      return [];
    }
  }

  /* Main target discovery orchestrator */
  async discoverTargets(scanId: string, domain: string, providedTargets?: string[]): Promise<TargetDiscoveryResult> {
    let primary: ClassifiedTarget[] = [];
    let thirdParty: ClassifiedTarget[] = [];
    let thirdPartySkipped = false;

    if (providedTargets) {
      // Convert provided targets to classified format (assume HTML for compatibility)
      primary = providedTargets.map(url => ({ url, assetType: 'html' as const }));
      thirdPartySkipped = true;
    } else {
      // Discover targets from various sources
      const [primaryTargets, thirdPartyTargets] = await Promise.all([
        this.buildTargets(scanId, domain),
        this.discoverThirdPartyOrigins(domain)
      ]);
      
      primary = primaryTargets;
      thirdParty = thirdPartyTargets;
    }

    const allTargets = [...primary, ...thirdParty];
    const htmlCount = allTargets.filter(t => t.assetType === 'html').length;
    const nonHtmlCount = allTargets.filter(t => t.assetType === 'nonHtml').length;

    return {
      primary,
      thirdParty,
      total: allTargets.length,
      metrics: {
        htmlCount,
        nonHtmlCount,
        discoveredCount: primary.length + thirdParty.length,
        thirdPartySkipped
      }
    };
  }

  /* Extract just HTML targets for scanner compatibility */
  getHtmlTargets(targets: ClassifiedTarget[]): string[] {
    return targets
      .filter(t => t.assetType === 'html')
      .map(t => t.url);
  }

  /* Extract non-HTML targets (typically bypassed by most scanners) */
  getNonHtmlTargets(targets: ClassifiedTarget[]): ClassifiedTarget[] {
    return targets.filter(t => t.assetType === 'nonHtml');
  }
}

// Create default target discovery instance
export function createTargetDiscovery(config?: TargetDiscoveryConfig) {
  return new TargetDiscovery(config);
}
</file>

<file path="techStackScan.ts">
/* =============================================================================
 * MODULE: techStackScan.ts (Monolithic v4 – Pre-Refactor)
 * =============================================================================
 * This module performs technology fingerprinting with integrated vulnerability
 * intelligence, SBOM generation, and supply-chain risk scoring.
 * =============================================================================
 */
import {
  insertArtifact,
  insertFinding,
  pool,
} from '../core/artifactStore.js';
import { log as rootLog } from '../core/logger.js';
import {
  detectTechnologiesWithWebTech,
  detectTechnologiesWithWhatWeb,
  detectFromHeaders,
} from '../util/fastTechDetection.js';
import { detectTechnologyByFavicon } from '../util/faviconDetection.js';
import { UnifiedCache } from './techCache/index.js';

// Configuration
const CONFIG = {
  MAX_CONCURRENCY: 6,
  TECH_CIRCUIT_BREAKER: 20,
  PAGE_TIMEOUT_MS: 25_000,
  MAX_VULN_IDS_PER_FINDING: 12,
} as const;

type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
const RISK_TO_SEVERITY: Record<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', Severity> = {
  LOW: 'INFO',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL'
};

// Types
interface TechResult {
  name: string;
  slug: string;
  version?: string;
  confidence: number;
  cpe?: string;
  purl?: string;
  vendor?: string;
  ecosystem?: string;
  categories: string[];
}

interface VulnRecord {
  id: string;
  source: 'OSV' | 'GITHUB';
  cvss?: number;
  epss?: number;
  cisaKev?: boolean;
  summary?: string;
  publishedDate?: Date;
  affectedVersionRange?: string;
  activelyTested?: boolean;
  exploitable?: boolean;
  verificationDetails?: any;
}

interface EnhancedSecAnalysis {
  eol: boolean;
  vulns: VulnRecord[];
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  advice: string[];
  versionAccuracy?: number;
  supplyChainScore: number;
  activeVerification?: {
    tested: number;
    exploitable: number;
    notExploitable: number;
  };
}

interface ScanMetrics {
  totalTargets: number;
  thirdPartyOrigins: number;
  uniqueTechs: number;
  supplyFindings: number;
  runMs: number;
  circuitBreakerTripped: boolean;
  cacheHitRate: number;
  dynamic_browser_skipped?: boolean;
}

// Cache removed for simplicity

const log = (...m: unknown[]) => rootLog('[techStackScan]', ...m);

// Helper function
function summarizeVulnIds(v: VulnRecord[], max: number): string {
  const ids = v.slice(0, max).map(r => r.id);
  return v.length > max ? ids.join(', ') + ', …' : ids.join(', ');
}

function detectEcosystem(tech: TechResult): string {
  const name = tech.name.toLowerCase();
  if (name.includes('node') || name.includes('npm')) return 'npm';
  if (name.includes('python') || name.includes('pip')) return 'pypi';
  if (name.includes('java') || name.includes('maven')) return 'maven';
  if (name.includes('ruby') || name.includes('gem')) return 'rubygems';
  if (name.includes('php') || name.includes('composer')) return 'packagist';
  if (name.includes('docker')) return 'docker';
  return 'unknown';
}

// Simplified target discovery
async function discoverTargets(scanId: string, domain: string, providedTargets?: string[]) {
  // Get discovered endpoints from endpointDiscovery if available
  const endpointQuery = await pool.query(
    `SELECT meta FROM artifacts WHERE type = 'discovered_endpoints' AND meta->>'scan_id' = $1 LIMIT 1`,
    [scanId]
  );
  
  const targets = new Set<string>();
  
  // Add primary domain targets
  targets.add(`https://${domain}`);
  targets.add(`https://www.${domain}`);
  
  // Add provided targets
  if (providedTargets) {
    providedTargets.forEach(t => targets.add(t));
  }
  
  // Add discovered endpoints if available
  if (endpointQuery.rows.length > 0 && endpointQuery.rows[0].meta.endpoints) {
    const endpoints = endpointQuery.rows[0].meta.endpoints;
    endpoints.slice(0, 10).forEach((ep: any) => {
      if (ep.url) targets.add(ep.url);
    });
  }
  
  return {
    primary: Array.from(targets).slice(0, 5),
    thirdParty: [],
    total: targets.size,
    metrics: {
      htmlCount: targets.size,
      nonHtmlCount: 0,
      thirdPartySkipped: false
    }
  };
}

// Simplified security analysis
async function analyzeSecurityEnhanced(tech: TechResult): Promise<EnhancedSecAnalysis> {
  return {
    eol: false,
    vulns: [],
    risk: 'LOW',
    advice: [`${tech.name} detected with confidence ${tech.confidence}%`],
    versionAccuracy: tech.confidence,
    supplyChainScore: 3.0,
    activeVerification: {
      tested: 0,
      exploitable: 0,
      notExploitable: 0
    }
  };
}

// Main function
export async function runTechStackScan(job: { 
  domain: string; 
  scanId: string;
  targets?: string[];
}): Promise<number> {
  const { domain, scanId, targets: providedTargets } = job;
  const start = Date.now();
  log(`techstack=start domain=${domain}`);

  try {
    // 1. TARGET DISCOVERY
    const targetResult = await discoverTargets(scanId, domain, providedTargets);
    const allTargets = targetResult.primary;
    
    log(`techstack=targets total=${targetResult.total} html=${allTargets.length}`);
    
    // 2. TECHNOLOGY DETECTION
    let allDetections: TechResult[] = [];
    let circuitBreakerTripped = false;
    
    for (const url of allTargets.slice(0, 5)) {
      try {
        const webtech = await detectTechnologiesWithWebTech(url);
        allDetections.push(...webtech.technologies);
        
        if (webtech.technologies.length === 0) {
          const whatweb = await detectTechnologiesWithWhatWeb(url);
          allDetections.push(...whatweb.technologies);
        }
        
        if (allDetections.length === 0) {
          const headers = await detectFromHeaders(url);
          allDetections.push(...headers);
        }

        const favicon = await detectTechnologyByFavicon(url);
        if (favicon.length > 0) {
          allDetections.push(...favicon);
        }
      } catch (err) {
        log(`Error detecting tech for ${url}:`, (err as Error).message);
      }
    }

    const techMap = new Map<string, TechResult>();
    for (const tech of allDetections) {
      if (!techMap.has(tech.slug) || (techMap.get(tech.slug)!.confidence < tech.confidence)) {
        techMap.set(tech.slug, tech);
      }
    }
    
    log(`techstack=tech_detection_complete techs=${techMap.size}`);
    
    // 3. SECURITY ANALYSIS
    const analysisMap = new Map<string, EnhancedSecAnalysis>();
    for (const [slug, tech] of techMap) {
      analysisMap.set(slug, await analyzeSecurityEnhanced(tech));
    }
    
    // 4. ARTIFACT GENERATION
    let artCount = 0;
    let supplyFindings = 0;
    
    for (const [slug, tech] of techMap) {
      const analysis = analysisMap.get(slug)!;
      const artId = await insertArtifact({
        type: 'technology',
        val_text: `${tech.name}${tech.version ? ' v' + tech.version : ''}`,
        severity: RISK_TO_SEVERITY[analysis.risk],
        meta: { 
          scan_id: scanId, 
          scan_module: 'techStackScan', 
          technology: tech, 
          security: analysis, 
          ecosystem: detectEcosystem(tech), 
          supply_chain_score: analysis.supplyChainScore, 
          version_accuracy: analysis.versionAccuracy, 
          active_verification: analysis.activeVerification 
        }
      });
      artCount++;
      
      if (analysis.vulns.length) {
        await insertFinding(
          artId,
          'EXPOSED_SERVICE',
          `${analysis.vulns.length} vulnerabilities detected: ${summarizeVulnIds(analysis.vulns, CONFIG.MAX_VULN_IDS_PER_FINDING)}`,
          analysis.advice.join(' ')
        );
      } else if (analysis.advice.length) {
        await insertFinding(
          artId,
          'TECHNOLOGY_RISK',
          analysis.advice.join(' '),
          `Analysis for ${tech.name}${tech.version ? ' v'+tech.version : ''}. Supply chain score: ${analysis.supplyChainScore.toFixed(1)}/10.`
        );
      }
      
      if (analysis.supplyChainScore >= 7.0) {
        supplyFindings++;
      }
    }

    // Generate discovered_endpoints artifact for dependent modules
    const endpointsForDeps = allTargets.map(url => ({
      url,
      method: 'GET',
      status: 200,
      title: 'Discovered endpoint',
      contentType: 'text/html',
      contentLength: 0,
      requiresAuth: false,
      isStaticContent: false,
      allowsStateChanging: false
    }));

    await insertArtifact({
      type: 'discovered_endpoints',
      val_text: `${endpointsForDeps.length} endpoints discovered for tech scanning`,
      severity: 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'techStackScan',
        endpoints: endpointsForDeps,
        total_count: endpointsForDeps.length
      }
    });

    // Generate discovered_web_assets artifact for dependent modules  
    await insertArtifact({
      type: 'discovered_web_assets',
      val_text: `${allTargets.length} web assets discovered for tech scanning`,
      severity: 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'techStackScan',
        assets: allTargets.map(url => ({ url, type: 'html' })),
        total_count: allTargets.length
      }
    });

    // 5. METRICS AND SUMMARY
    const runMs = Date.now() - start;
    const metrics: ScanMetrics = {
      totalTargets: targetResult.total,
      thirdPartyOrigins: 0,
      uniqueTechs: techMap.size,
      supplyFindings,
      runMs,
      circuitBreakerTripped,
      cacheHitRate: 0,
      dynamic_browser_skipped: false
    };

    await insertArtifact({
      type: 'scan_summary',
      val_text: `Tech scan: ${metrics.uniqueTechs} techs, ${supplyFindings} supply chain risks`,
      severity: 'INFO',
      meta: { 
        scan_id: scanId, 
        scan_module: 'techStackScan', 
        metrics, 
        scan_duration_ms: runMs 
      }
    });
    
    log(`techstack=complete domain=${domain} artifacts=${artCount} runtime=${runMs}ms`);
    return artCount;

  } catch (error) {
    log(`techstack=error domain=${domain} error="${(error as Error).message}"`);
    await insertArtifact({
      type: 'scan_error',
      val_text: `Tech stack scan failed: ${(error as Error).message}`,
      severity: 'HIGH',
      meta: { 
        scan_id: scanId, 
        scan_module: 'techStackScan', 
        error: (error as Error).message, 
        stack: (error as Error).stack 
      }
    });
    return 0;
  }
}
</file>

<file path="tierConfig.ts">
/*
 * =============================================================================
 * MODULE: tierConfig.ts
 * =============================================================================
 * Configuration for two-tier scanning system:
 * - Tier 1: Quick scan (3-5 minutes) for immediate security assessment
 * - Tier 2: Deep dive (10-15 minutes) for comprehensive analysis
 * =============================================================================
 */

export interface ScanTier {
    name: 'tier1' | 'tier2';
    description: string;
    targetTime: string;
}

export const SCAN_TIERS: Record<'tier1' | 'tier2', ScanTier> = {
    tier1: {
        name: 'tier1',
        description: 'Quick security assessment',
        targetTime: '3-5 minutes'
    },
    tier2: {
        name: 'tier2', 
        description: 'Comprehensive deep analysis',
        targetTime: '10-15 minutes'
    }
};

// Endpoint Discovery Configuration
export const ENDPOINT_DISCOVERY_CONFIG = {
    tier1: {
        maxCrawlDepth: 2,
        maxConcurrentRequests: 12,      // Reduced from 20 to 12 for stability
        requestTimeout: 3000,           // Reduced from 8000
        maxJsFileSize: 2 * 1024 * 1024, // 2MB max
        maxFilesPerCrawl: 25,           // Reduced from 35
        maxTotalCrawlSize: 20 * 1024 * 1024, // 20MB total
        maxPages: 50,                   // Reduced from 75
        highValuePathsOnly: true        // Focus on likely targets
    },
    tier2: {
        maxCrawlDepth: 3,               // Deeper crawling
        maxConcurrentRequests: 10,      // Reduced from 15 for stability  
        requestTimeout: 8000,           // Full timeout
        maxJsFileSize: 5 * 1024 * 1024, // 5MB max
        maxFilesPerCrawl: 75,           // Full coverage
        maxTotalCrawlSize: 50 * 1024 * 1024, // 50MB total
        maxPages: 150,                  // Comprehensive crawling
        highValuePathsOnly: false       // Scan everything
    }
};

// TruffleHog Configuration
export const TRUFFLEHOG_CONFIG = {
    tier1: {
        maxContentSize: 2 * 1024 * 1024,    // 2MB per file
        maxFilesToScan: 20,                  // Top 20 files only
        skipLargeFiles: true,
        prioritizeJavaScript: true
    },
    tier2: {
        maxContentSize: 10 * 1024 * 1024,   // 10MB per file
        maxFilesToScan: 100,                 // More comprehensive
        skipLargeFiles: false,
        prioritizeJavaScript: false
    }
};

// Database Port Scan Configuration
export const DB_PORT_SCAN_CONFIG = {
    tier1: {
        maxConcurrentScans: 8,              // Reduced from 12 to 8 for stability
        nmapTimeout: 30000,                 // Reduced from 60000
        nucleiTimeout: 60000,               // Reduced from 300000
        skipSlowScripts: true
    },
    tier2: {
        maxConcurrentScans: 6,              // Reduced from 8 to 6 for stability
        nmapTimeout: 120000,                // Full timeout
        nucleiTimeout: 300000,              // Full timeout
        skipSlowScripts: false
    }
};

// Web Archive Scanner Configuration
export const WEB_ARCHIVE_CONFIG = {
    tier1: {
        maxArchiveUrls: 20,                 // Quick scan: 20 URLs
        maxYearsBack: 1,                    // Recent year only
        maxConcurrentFetches: 8,            // Reduced from 12 to 8 for stability
        archiveTimeout: 5000,               // Quick timeout
        skipGau: false                      // Keep gau for speed
    },
    tier2: {
        maxArchiveUrls: 200,                // Deep dive: 200 URLs  
        maxYearsBack: 3,                    // 3 years back
        maxConcurrentFetches: 6,            // Reduced from 8 to 6 for stability
        archiveTimeout: 15000,              // Full timeout
        skipGau: false
    }
};

// AI Path Finder Configuration
export const AI_PATH_FINDER_CONFIG = {
    tier1: {
        maxPathsToGenerate: 25,             // Reduced from 50
        maxConcurrentProbes: 10,            // Reduced from 15 to 10 for stability
        probeTimeout: 4000,                 // Reduced from 8000
        aiTimeout: 15000,                   // Quick AI response
        fallbackOnly: false                 // Use AI for better results
    },
    tier2: {
        maxPathsToGenerate: 75,             // More comprehensive
        maxConcurrentProbes: 8,             // Reduced from 10 to 8 for stability
        probeTimeout: 8000,                 // Full timeout
        aiTimeout: 30000,                   // Full AI timeout
        fallbackOnly: false
    }
};

// Module execution order and parallelization
export const MODULE_EXECUTION_PLAN = {
    tier1: {
        // Phase 1: Independent discovery (parallel)
        phase1: [
            'endpointDiscovery',
            'aiPathFinder'
            // Skip webArchiveScanner for speed in tier1
        ],
        // Phase 2: Dependent scanning (parallel) 
        phase2: [
            'trufflehog',       // Depends on endpointDiscovery
            'dbPortScan'        // Can run in parallel with trufflehog
        ],
        estimatedTime: '3-5 minutes'
    },
    tier2: {
        // Phase 1: Independent discovery (parallel)
        phase1: [
            'endpointDiscovery',
            'webArchiveScanner', 
            'aiPathFinder'
        ],
        // Phase 2: Dependent scanning (parallel)
        phase2: [
            'trufflehog',       // Depends on discovery modules
            'dbPortScan'        // Depends on trufflehog secrets
        ],
        estimatedTime: '10-15 minutes'
    }
};

/**
 * Get configuration for a specific module and tier
 */
export function getModuleConfig<T>(module: string, tier: 'tier1' | 'tier2'): T {
    const configs: Record<string, any> = {
        endpointDiscovery: ENDPOINT_DISCOVERY_CONFIG,
        trufflehog: TRUFFLEHOG_CONFIG,
        dbPortScan: DB_PORT_SCAN_CONFIG,
        webArchiveScanner: WEB_ARCHIVE_CONFIG,
        aiPathFinder: AI_PATH_FINDER_CONFIG
    };
    
    return configs[module]?.[tier] as T;
}

/**
 * Check if a module should be skipped for a tier
 */
export function shouldSkipModule(module: string, tier: 'tier1' | 'tier2'): boolean {
    // Skip web archive scanner in tier1 for speed
    if (tier === 'tier1' && module === 'webArchiveScanner') {
        return true;
    }
    
    return false;
}
</file>

<file path="tlsScan.ts">
/* =============================================================================
 * MODULE: tlsScan.ts (Rewritten with sslscan v8, 2025-06-22)
 * =============================================================================
 * Performs TLS/SSL configuration assessment using **sslscan** instead of testssl.sh.
 * sslscan is much more reliable, faster, and easier to integrate.
 * =============================================================================
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import axios from 'axios';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { log } from '../core/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const exec = promisify(execFile);

/* ---------- Types --------------------------------------------------------- */

type Severity = 'OK' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INFO';

interface SSLScanResult {
  host: string;
  port: number;
  certificate?: {
    subject: string;
    issuer: string;
    notBefore: string;
    notAfter: string;
    expired: boolean;
    selfSigned: boolean;
  };
  protocols: Array<{
    name: string;
    version: string;
    enabled: boolean;
  }>;
  ciphers: Array<{
    cipher: string;
    protocols: string[];
    keyExchange: string;
    authentication: string;
    encryption: string;
    bits: number;
    status: string;
  }>;
  vulnerabilities: string[];
}

interface ScanOutcome {
  findings: number;
  hadCert: boolean;
}

interface PythonValidationResult {
  host: string;
  port: number;
  valid: boolean;
  error?: string;
  certificate?: {
    subject_cn: string;
    issuer_cn: string;
    not_after: string;
    days_until_expiry: number | null;
    is_expired: boolean;
    self_signed: boolean;
    subject_alt_names: Array<{type: string; value: string}>;
  };
  tls_version?: string;
  cipher_suite?: any;
  sni_supported: boolean;
  validation_method: string;
}

/* ---------- Config -------------------------------------------------------- */

const TLS_SCAN_TIMEOUT_MS = Number.parseInt(process.env.TLS_SCAN_TIMEOUT_MS ?? '120000', 10); // 2 min
const TLS_DERIVATION_PREFIXES = ['www']; // extend with 'app', 'login', etc. if needed

/* ---------- Helpers ------------------------------------------------------- */

/** Validate sslscan is available */
async function validateSSLScan(): Promise<boolean> {
  try {
    const result = await exec('sslscan', ['--version']);
    log(`[tlsScan] sslscan found: ${result.stdout?.trim() || 'version check ok'}`);
    return true;
  } catch (error) {
    log(`[tlsScan] [CRITICAL] sslscan binary not found: ${(error as Error).message}`);
    return false;
  }
}

/** Run Python certificate validator with SNI support */
async function runPythonCertificateValidator(host: string, port: number = 443): Promise<PythonValidationResult | null> {
  try {
    const pythonScript = join(__dirname, '../scripts/tls_verify.py');
    const result = await exec('python3', [pythonScript, host, '--port', port.toString(), '--json'], {
      timeout: 30000 // 30 second timeout
    });
    
    const validationResult = JSON.parse(result.stdout || '{}') as PythonValidationResult;
    log(`[tlsScan] Python validator: ${host} - ${validationResult.valid ? 'VALID' : 'INVALID'}`);
    return validationResult;
    
  } catch (error) {
    log(`[tlsScan] Python validator failed for ${host}: ${(error as Error).message}`);
    return null;
  }
}

/** Parse sslscan XML output */
function parseSSLScanOutput(xmlOutput: string, host: string): SSLScanResult | null {
  try {
    // For now, do basic text parsing. Could use xml2js later if needed.
    const result: SSLScanResult = {
      host,
      port: 443,
      protocols: [],
      ciphers: [],
      vulnerabilities: []
    };

    const lines = xmlOutput.split('\n');
    
    // Extract certificate info
    let certMatch = xmlOutput.match(/Subject:\s+(.+)/);
    if (certMatch) {
      const issuerMatch = xmlOutput.match(/Issuer:\s+(.+)/);
      const notBeforeMatch = xmlOutput.match(/Not valid before:\s+(.+)/);
      const notAfterMatch = xmlOutput.match(/Not valid after:\s+(.+)/);
      
      result.certificate = {
        subject: certMatch[1]?.trim() || '',
        issuer: issuerMatch?.[1]?.trim() || '',
        notBefore: notBeforeMatch?.[1]?.trim() || '',
        notAfter: notAfterMatch?.[1]?.trim() || '',
        expired: false, // Will calculate below
        selfSigned: xmlOutput.includes('self signed')
      };

      // Check if certificate is expired
      if (result.certificate.notAfter) {
        const expiryDate = new Date(result.certificate.notAfter);
        result.certificate.expired = expiryDate < new Date();
      }
    }

    // Extract protocol support
    if (xmlOutput.includes('SSLv2') && xmlOutput.match(/SSLv2\s+enabled/)) {
      result.vulnerabilities.push('SSLv2 enabled (deprecated)');
    }
    if (xmlOutput.includes('SSLv3') && xmlOutput.match(/SSLv3\s+enabled/)) {
      result.vulnerabilities.push('SSLv3 enabled (deprecated)');
    }
    if (xmlOutput.includes('TLSv1.0') && xmlOutput.match(/TLSv1\.0\s+enabled/)) {
      result.vulnerabilities.push('TLSv1.0 enabled (deprecated)');
    }

    // Extract weak ciphers
    if (xmlOutput.includes('RC4')) {
      result.vulnerabilities.push('RC4 cipher support detected');
    }
    if (xmlOutput.includes('DES') || xmlOutput.includes('3DES')) {
      result.vulnerabilities.push('Weak DES/3DES cipher support detected');
    }
    if (xmlOutput.includes('NULL')) {
      result.vulnerabilities.push('NULL cipher support detected');
    }

    // Check for missing certificate - but this will be cross-validated with Python
    if (!result.certificate && !xmlOutput.includes('Certificate information')) {
      result.vulnerabilities.push('No SSL certificate presented');
    }

    return result;
    
  } catch (error) {
    log(`[tlsScan] Failed to parse sslscan output: ${(error as Error).message}`);
    return null;
  }
}

/** Check if domain is behind CDN/proxy that terminates SSL */
async function isCloudFlareProtected(hostname: string): Promise<boolean> {
  try {
    // Check DNS for known CDN IP ranges
    const { stdout } = await exec('dig', ['+short', hostname]);
    const ips = stdout.trim().split('\n').filter(ip => ip.includes('.'));
    
    // Comprehensive CDN IP ranges
    const cdnRanges = {
      cloudflare: [
        '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.',
        '104.24.', '104.25.', '104.26.', '104.27.', '104.28.', '104.29.', '104.30.', '104.31.',
        '172.64.', '172.65.', '172.66.', '172.67.', '108.162.', '141.101.', '162.158.', '162.159.',
        '173.245.', '188.114.', '190.93.', '197.234.', '198.41.', '103.21.', '103.22.', '103.31.'
      ],
      fastly: [
        '23.235.32.', '23.235.33.', '23.235.34.', '23.235.35.', '23.235.36.', '23.235.37.',
        '23.235.38.', '23.235.39.', '23.235.40.', '23.235.41.', '23.235.42.', '23.235.43.',
        '23.235.44.', '23.235.45.', '23.235.46.', '23.235.47.', '185.31.16.', '185.31.17.',
        '185.31.18.', '185.31.19.', '151.101.'
      ],
      bunnycdn: [
        '89.187.162.', '89.187.163.', '89.187.164.', '89.187.165.', '89.187.166.', '89.187.167.',
        '89.187.168.', '89.187.169.', '89.187.170.', '89.187.171.', '89.187.172.', '89.187.173.'
      ],
      keycdn: [
        '167.114.', '192.254.', '178.32.', '176.31.', '87.98.', '94.23.', '5.196.'
      ]
    };
    
    // Check if any IP matches known CDN ranges
    for (const [cdn, ranges] of Object.entries(cdnRanges)) {
      const matchesCDN = ips.some(ip => ranges.some(range => ip.startsWith(range)));
      if (matchesCDN) {
        log(`[tlsScan] ${hostname} detected behind ${cdn.toUpperCase()} CDN`);
        return true;
      }
    }
    
    // Check HTTP headers for comprehensive CDN detection
    try {
      const response = await axios.head(`https://${hostname}`, { 
        timeout: 5000,
        headers: { 'User-Agent': 'DealBrief-TLS-Scanner/1.0' }
      });
      
      const headers = response.headers;
      const headerStr = JSON.stringify(headers).toLowerCase();
      
      // Comprehensive CDN/Proxy header detection
      const cdnIndicators = {
        cloudflare: ['cf-ray', 'cf-cache-status', 'cloudflare', 'cf-edge', 'cf-worker'],
        aws_cloudfront: ['x-amz-cf-id', 'x-amzn-trace-id', 'x-amz-cf-pop', 'cloudfront'],
        fastly: ['x-served-by', 'x-fastly-request-id', 'fastly-debug-digest', 'x-timer'],
        akamai: ['x-akamai-', 'akamai', 'x-cache-key', 'x-check-cacheable'],
        maxcdn_stackpath: ['x-pull', 'x-cache', 'maxcdn', 'stackpath'],
        keycdn: ['x-edge-location', 'keycdn'],
        bunnycdn: ['bunnycdn', 'x-bunny'],
        jsdelivr: ['x-served-by', 'jsdelivr'],
        sucuri: ['x-sucuri-id', 'sucuri', 'x-sucuri-cache'],
        incapsula: ['x-iinfo', 'incap-ses', 'x-cdn', 'imperva'],
        // Security services that terminate SSL
        ddos_guard: ['x-ddos-protection', 'ddos-guard'],
        stormwall: ['x-stormwall', 'stormwall'],
        qrator: ['x-qrator', 'qrator']
      };
      
      // Check for any CDN/proxy indicators
      for (const [service, indicators] of Object.entries(cdnIndicators)) {
        const matchesService = indicators.some(indicator => 
          headerStr.includes(indicator) || 
          Object.keys(headers).some(header => header.toLowerCase().includes(indicator))
        );
        
        if (matchesService) {
          log(`[tlsScan] ${hostname} detected behind ${service.replace('_', ' ').toUpperCase()} via headers`);
          return true;
        }
      }
      
      // Check server headers for common CDN signatures
      const serverHeader = headers.server?.toLowerCase() || '';
      const cdnServerSigs = ['cloudflare', 'fastly', 'akamaighost', 'keycdn', 'bunnycdn'];
      if (cdnServerSigs.some(sig => serverHeader.includes(sig))) {
        log(`[tlsScan] ${hostname} detected CDN via Server header: ${serverHeader}`);
        return true;
      }
      
    } catch (httpError) {
      // HTTP check failed, but that doesn't mean it's not behind a CDN
    }
    
    return false;
    
  } catch (error) {
    log(`[tlsScan] CDN detection failed for ${hostname}: ${(error as Error).message}`);
    return false;
  }
}

/** Get remediation advice for TLS issues */
function getTlsRecommendation(vulnerability: string): string {
  const recommendations: Record<string, string> = {
    'SSLv2 enabled': 'Disable SSLv2 completely - it has known security vulnerabilities',
    'SSLv3 enabled': 'Disable SSLv3 completely - vulnerable to POODLE attack',
    'TLSv1.0 enabled': 'Disable TLSv1.0 - use TLS 1.2 or higher only',
    'RC4 cipher': 'Disable RC4 ciphers - they are cryptographically weak',
    'DES/3DES cipher': 'Disable DES and 3DES ciphers - use AES instead',
    'NULL cipher': 'Disable NULL ciphers - they provide no encryption',
    'No SSL certificate': 'Install a valid SSL/TLS certificate from a trusted CA',
    'expired': 'Renew the SSL certificate immediately',
    'self signed': 'Replace self-signed certificate with one from a trusted CA'
  };

  for (const [key, recommendation] of Object.entries(recommendations)) {
    if (vulnerability.toLowerCase().includes(key.toLowerCase())) {
      return recommendation;
    }
  }
  
  return 'Review and update TLS configuration according to current security best practices';
}

/** Cross-validate sslscan and Python certificate validator results */
async function performCrossValidation(
  host: string, 
  sslscanResult: SSLScanResult, 
  pythonResult: PythonValidationResult,
  scanId?: string
): Promise<{additionalFindings: number}> {
  let additionalFindings = 0;

  // 1. Check for validation mismatches - Trust Python validator over sslscan
  const sslscanHasCert = !!sslscanResult.certificate;
  const pythonHasCert = pythonResult.valid && !!pythonResult.certificate;
  
  // Only report a mismatch if Python says INVALID but sslscan says valid
  // If Python says valid but sslscan says invalid, trust Python (common with SNI/cloud certs)
  if (sslscanHasCert && !pythonHasCert) {
    additionalFindings++;
    const artId = await insertArtifact({
      type: 'tls_validation_mismatch',
      val_text: `${host} - Certificate validation mismatch: sslscan found cert but Python validation failed`,
      severity: 'MEDIUM',
      meta: {
        host,
        sslscan_has_cert: sslscanHasCert,
        python_has_cert: pythonHasCert,
        python_error: pythonResult.error,
        sni_supported: pythonResult.sni_supported,
        scan_id: scanId,
        scan_module: 'tlsScan_hybrid'
      }
    });
    
    await insertFinding(
      artId,
      'TLS_VALIDATION_INCONSISTENCY',
      'Certificate found by sslscan but Python validation failed - investigate certificate validity',
      `sslscan: found cert, Python validator: ${pythonResult.error || 'validation failed'}`
    );
  }
  // REMOVED: Don't report when Python says valid but sslscan says invalid (trust Python)

  // 2. SNI-specific issues
  if (!pythonResult.sni_supported && sslscanResult.certificate) {
    additionalFindings++;
    const artId = await insertArtifact({
      type: 'tls_sni_issue',
      val_text: `${host} - SNI configuration issue detected`,
      severity: 'HIGH',
      meta: {
        host,
        python_error: pythonResult.error,
        scan_id: scanId,
        scan_module: 'tlsScan_hybrid'
      }
    });
    
    await insertFinding(
      artId,
      'SNI_CONFIGURATION_ISSUE',
      'Configure proper SNI support for cloud-hosted certificates',
      `Certificate found by sslscan but Python validator failed: ${pythonResult.error}`
    );
  }

  // 3. Enhanced certificate expiry validation (Python is more accurate)
  if (pythonResult.certificate?.is_expired && sslscanResult.certificate && !sslscanResult.certificate.expired) {
    additionalFindings++;
    const artId = await insertArtifact({
      type: 'tls_certificate_expired_python',
      val_text: `${host} - Certificate expired (Python validator)`,
      severity: 'CRITICAL',
      meta: {
        host,
        python_certificate: pythonResult.certificate,
        validation_discrepancy: true,
        scan_id: scanId,
        scan_module: 'tlsScan_hybrid'
      }
    });
    
    await insertFinding(
      artId,
      'CERTIFICATE_EXPIRY_VERIFIED',
      'Certificate expiry confirmed by Python validator - renew immediately',
      `Python validator confirms certificate expired: ${pythonResult.certificate.not_after}`
    );
  }

  // 4. Modern TLS version detection (Python provides actual negotiated version)
  if (pythonResult.tls_version) {
    const tlsVersion = pythonResult.tls_version;
    if (tlsVersion.includes('1.0') || tlsVersion.includes('1.1')) {
      additionalFindings++;
      const artId = await insertArtifact({
        type: 'tls_weak_version_negotiated',
        val_text: `${host} - Weak TLS version negotiated: ${tlsVersion}`,
        severity: 'MEDIUM',
        meta: {
          host,
          negotiated_version: tlsVersion,
          cipher_suite: pythonResult.cipher_suite,
          scan_id: scanId,
          scan_module: 'tlsScan_hybrid'
        }
      });
      
      await insertFinding(
        artId,
        'WEAK_TLS_VERSION_NEGOTIATED',
        'Disable TLS 1.0 and 1.1 - use TLS 1.2+ only',
        `Negotiated TLS version: ${tlsVersion}`
      );
    }
  }

  log(`[tlsScan] Cross-validation complete for ${host}: ${additionalFindings} additional findings`);
  return { additionalFindings };
}

/* ---------- Core host-scan routine ---------------------------------------- */

async function scanHost(host: string, scanId?: string): Promise<ScanOutcome> {
  let findingsCount = 0;
  let certificateSeen = false;

  try {
    log(`[tlsScan] Scanning ${host} with hybrid validation (sslscan + Python)...`);
    
    // Run both sslscan and Python validator concurrently
    const [sslscanResult, pythonResult] = await Promise.allSettled([
      exec('sslscan', [
        '--xml=-',  // Output XML to stdout
        '--no-colour',
        '--timeout=30',
        host
      ], { timeout: TLS_SCAN_TIMEOUT_MS }),
      runPythonCertificateValidator(host)
    ]);

    // Process sslscan results
    let sslscanData: { stdout: string; stderr: string } | null = null;
    if (sslscanResult.status === 'fulfilled') {
      sslscanData = sslscanResult.value;
      if (sslscanData.stderr) {
        // Filter out common ECDHE key generation warnings that don't affect functionality
        const filteredStderr = sslscanData.stderr
          .split('\n')
          .filter(line => !line.includes('Failed to generate ECDHE key for nid'))
          .join('\n')
          .trim();
        
        if (filteredStderr) {
          log(`[tlsScan] sslscan stderr for ${host}: ${filteredStderr}`);
        }
      }
    } else {
      log(`[tlsScan] sslscan failed for ${host}: ${sslscanResult.reason}`);
    }

    // Process Python validation results
    let pythonData: PythonValidationResult | null = null;
    if (pythonResult.status === 'fulfilled') {
      pythonData = pythonResult.value;
    } else {
      log(`[tlsScan] Python validator failed for ${host}: ${pythonResult.reason}`);
    }

    // Parse sslscan output
    const result = sslscanData ? parseSSLScanOutput(sslscanData.stdout, host) : null;
    if (!result) {
      log(`[tlsScan] Failed to parse results for ${host}`);
      return { findings: 0, hadCert: false };
    }

    certificateSeen = !!result.certificate;

    // Check certificate expiry
    if (result.certificate) {
      const cert = result.certificate;
      
      if (cert.expired) {
        findingsCount++;
        const artId = await insertArtifact({
          type: 'tls_certificate_expired',
          val_text: `${host} - SSL certificate expired`,
          severity: 'CRITICAL',
          meta: {
            host,
            certificate: cert,
            scan_id: scanId,
            scan_module: 'tlsScan'
          }
        });
        await insertFinding(
          artId,
          'CERTIFICATE_EXPIRY',
          'SSL certificate has expired - renew immediately',
          `Certificate for ${host} expired on ${cert.notAfter}`
        );
      } else if (cert.notAfter) {
        // Check if expiring soon
        const expiryDate = new Date(cert.notAfter);
        const daysUntilExpiry = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        
        let severity: Severity | null = null;
        if (daysUntilExpiry <= 14) {
          severity = 'HIGH';
        } else if (daysUntilExpiry <= 30) {
          severity = 'MEDIUM';
        } else if (daysUntilExpiry <= 90) {
          severity = 'LOW';
        }

        if (severity) {
          findingsCount++;
          const artId = await insertArtifact({
            type: 'tls_certificate_expiry',
            val_text: `${host} - SSL certificate expires in ${daysUntilExpiry} days`,
            severity,
            meta: {
              host,
              certificate: cert,
              days_remaining: daysUntilExpiry,
              scan_id: scanId,
              scan_module: 'tlsScan'
            }
          });
          await insertFinding(
            artId,
            'CERTIFICATE_EXPIRY',
            `Certificate expires in ${daysUntilExpiry} days - plan renewal`,
            `Certificate for ${host} expires on ${cert.notAfter}`
          );
        }
      }

      // Check for self-signed certificate
      if (cert.selfSigned) {
        findingsCount++;
        const artId = await insertArtifact({
          type: 'tls_self_signed',
          val_text: `${host} - Self-signed SSL certificate detected`,
          severity: 'MEDIUM',
          meta: {
            host,
            certificate: cert,
            scan_id: scanId,
            scan_module: 'tlsScan'
          }
        });
        await insertFinding(
          artId,
          'SELF_SIGNED_CERTIFICATE',
          'Replace self-signed certificate with one from a trusted CA',
          `Self-signed certificate detected for ${host}`
        );
      }
    }

    // Cross-validate with Python certificate validator
    if (pythonData && result) {
      const crossValidation = await performCrossValidation(host, result, pythonData, scanId);
      findingsCount += crossValidation.additionalFindings;
      
      // Update certificate seen status with Python validation
      certificateSeen = certificateSeen || (pythonData.valid && !!pythonData.certificate);
    }

    // Process vulnerabilities - filter out false positives when Python says certificate is valid
    for (const vulnerability of result.vulnerabilities) {
      // Skip "No SSL certificate presented" if Python validator confirmed a valid certificate
      if (vulnerability.includes('No SSL certificate') && pythonData && pythonData.valid && pythonData.certificate) {
        log(`[tlsScan] Skipping false positive: "${vulnerability}" - Python validator confirmed valid certificate`);
        continue;
      }

      // Check if site is behind CDN/proxy that terminates SSL - skip origin cert issues
      if (vulnerability.includes('No SSL certificate') && await isCloudFlareProtected(host)) {
        log(`[tlsScan] Skipping origin cert issue for ${host} - behind CDN/proxy (not user-facing risk)`);
        continue;
      }

      // Enhanced certificate issue analysis with Python validation context
      if (vulnerability.includes('No SSL certificate')) {
        // If Python validator shows certificate chain issues vs no certificate at all
        if (pythonData && pythonData.error?.includes('unable to get local issuer certificate')) {
          log(`[tlsScan] Converting "No SSL certificate" to "Incomplete certificate chain" based on Python validation`);
          // This is a configuration issue, not a security vulnerability
          const artId = await insertArtifact({
            type: 'tls_configuration',
            val_text: `${host} - Incomplete SSL certificate chain (missing intermediates)`,
            severity: 'INFO',
            meta: {
              host,
              issue_type: 'incomplete_certificate_chain',
              python_error: pythonData.error,
              scan_id: scanId,
              scan_module: 'tlsScan'
            }
          });

          await insertFinding(
            artId,
            'TLS_CONFIGURATION_ISSUE',
            'Configure server to present complete certificate chain including intermediate certificates',
            `Python validation: ${pythonData.error}`
          );
          
          findingsCount++;
          continue; // Skip the generic "No SSL certificate" processing
        }
      }
      
      findingsCount++;
      
      let severity: Severity = 'MEDIUM';
      if (vulnerability.includes('SSLv2') || vulnerability.includes('SSLv3')) {
        severity = 'HIGH'; // Removed "No SSL certificate" from HIGH severity
      } else if (vulnerability.includes('No SSL certificate')) {
        severity = 'HIGH'; // Only for actual missing certificates
      } else if (vulnerability.includes('NULL') || vulnerability.includes('RC4')) {
        severity = 'HIGH';
      } else if (vulnerability.includes('TLSv1.0') || vulnerability.includes('DES')) {
        severity = 'MEDIUM';
      }

      const artId = await insertArtifact({
        type: 'tls_weakness',
        val_text: `${host} - ${vulnerability}`,
        severity,
        meta: {
          host,
          vulnerability,
          scan_id: scanId,
          scan_module: 'tlsScan'
        }
      });

      await insertFinding(
        artId,
        'TLS_CONFIGURATION_ISSUE',
        getTlsRecommendation(vulnerability),
        vulnerability
      );
    }

  } catch (error) {
    log(`[tlsScan] Scan failed for ${host}: ${(error as Error).message}`);
  }

  return { findings: findingsCount, hadCert: certificateSeen };
}

/* ---------- Public entry-point ------------------------------------------- */

export async function runTlsScan(job: { domain: string; scanId?: string }): Promise<number> {
  const input = job.domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*/, '');

  // Validate sslscan is available
  if (!(await validateSSLScan())) {
    await insertArtifact({
      type: 'scan_error',
      val_text: 'sslscan binary not found, TLS scan aborted',
      severity: 'HIGH',
      meta: { scan_id: job.scanId, scan_module: 'tlsScan' }
    });
    return 0;
  }

  // Derive base domain & host list
  const isWww = input.startsWith('www.');
  const baseDomain = isWww ? input.slice(4) : input;

  const candidates = new Set<string>();
  
  // Always scan the original host
  candidates.add(input);

  // Forward derivations (apex → prefixes)
  if (!isWww) {
    TLS_DERIVATION_PREFIXES.forEach((prefix) => candidates.add(`${prefix}.${baseDomain}`));
  }

  // Reverse derivation (www → apex)
  if (isWww) {
    candidates.add(baseDomain);
  }

  let totalFindings = 0;
  let anyCert = false;

  for (const host of candidates) {
    const { findings, hadCert } = await scanHost(host, job.scanId);
    totalFindings += findings;
    anyCert ||= hadCert;
  }

  /* Consolidated "no TLS at all" finding (only if *all* hosts lack cert) */
  if (!anyCert) {
    const artId = await insertArtifact({
      type: 'tls_no_certificate',
      val_text: `${baseDomain} - no valid SSL/TLS certificate on any host`,
      severity: 'HIGH',
      meta: {
        domain: baseDomain,
        scan_id: job.scanId,
        scan_module: 'tlsScan'
      }
    });
    await insertFinding(
      artId,
      'MISSING_TLS_CERTIFICATE',
      'Configure SSL/TLS certificates for all public hosts',
      'No valid SSL/TLS certificate found on any tested host variant'
    );
    totalFindings += 1;
  }

  /* Final summary artifact */
  await insertArtifact({
    type: 'scan_summary',
    val_text: `TLS scan complete - ${totalFindings} issue(s) found`,
    severity: 'INFO',
    meta: {
      domain: baseDomain,
      scan_id: job.scanId,
      scan_module: 'tlsScan',
      total_findings: totalFindings,
      hosts_scanned: Array.from(candidates),
      timestamp: new Date().toISOString()
    }
  });

  log(`[tlsScan] Scan complete. Hosts: ${[...candidates].join(', ')}. Findings: ${totalFindings}`);
  return totalFindings;
}
</file>

<file path="trufflehog.ts">
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs/promises';
import { insertArtifact, insertFinding, pool } from '../core/artifactStore.js';
import { log } from '../core/logger.js';
import { scanGitRepos } from './scanGitRepos.js';

const exec = promisify(execFile);
const EXPECTED_TRUFFLEHOG_VER = '3.83.7';
const GITHUB_RE = /^https:\/\/github\.com\/([\w.-]+\/[\w.-]+)(\.git)?$/i;
const GITLAB_RE = /^https:\/\/gitlab\.com\/([\w.-]+\/[\w.-]+)(\.git)?$/i;
const BITBUCKET_RE = /^https:\/\/bitbucket\.org\/([\w.-]+\/[\w.-]+)(\.git)?$/i;
const MAX_GIT_REPOS = 10;

type SourceType = 'git' | 'file' | 'http';

async function guardTrufflehog(): Promise<void> {
  try {
    const { stdout } = await exec('trufflehog', ['--version'], { timeout: 5000 });
    const version = stdout.match(/(\d+\.\d+\.\d+)/)?.[1];
    if (version !== EXPECTED_TRUFFLEHOG_VER) {
      log(`[trufflehog] Version mismatch: expected ${EXPECTED_TRUFFLEHOG_VER}, found ${version}`);
    }
  } catch (error) {
    throw new Error(`TruffleHog binary not available: ${(error as Error).message}`);
  }
}

/** Process TruffleHog JSON-lines output and emit findings */
function processTruffleHogOutput(output: string): { DetectorName: string; Raw: string; Verified: boolean; SourceMetadata: any }[] {
  if (!output || !output.trim()) {
    log('[trufflehog] TruffleHog returned empty output');
    return [];
  }
  
  const results: { DetectorName: string; Raw: string; Verified: boolean; SourceMetadata: any }[] = [];
  
  for (const line of output.split(/\r?\n/).filter(Boolean)) {
    try {
      const obj = JSON.parse(line);
      if (obj.DetectorName && obj.Raw) {
        results.push(obj);
      }
    } catch (e) {
      log('[trufflehog] Failed to parse TruffleHog JSON line:', (e as Error).message);
      log('[trufflehog] Raw line:', line.slice(0, 200));
    }
  }
  
  return results;
}

async function emitFindings(results: { DetectorName: string; Raw: string; Verified: boolean; SourceMetadata: any }[], src: SourceType, url: string) {
  let count = 0;
  for (const obj of results) {
    count++;
    const aid = await insertArtifact({
      type: 'secret',
      val_text: `${obj.DetectorName}: ${obj.Raw.slice(0, 40)}…`,
      severity: obj.Verified ? 'CRITICAL' : 'HIGH',
      src_url: url,
      meta: { detector: obj.DetectorName, source_type: src }
    });
    await insertFinding(
      aid,
      obj.Verified ? 'VERIFIED_SECRET' : 'POTENTIAL_SECRET',
      'Rotate/ revoke immediately.',
      obj.Raw
    );
  }
  return count;
}

// Get Git repositories from discovered web assets and endpoint discovery artifacts
async function getGitRepos(scanId: string): Promise<string[]> {
  try {
    const gitUrls = new Set<string>();
    
    // 1. Check discovered web assets for Git repository URLs
    const webAssetsResult = await pool.query(`
      SELECT meta 
      FROM artifacts 
      WHERE meta->>'scan_id' = $1 
        AND type = 'discovered_web_assets'
      ORDER BY created_at DESC 
      LIMIT 1
    `, [scanId]);
    
    if (webAssetsResult.rows.length > 0) {
      const assets = webAssetsResult.rows[0].meta?.assets || [];
      for (const asset of assets) {
        if (asset.url && (
          GITHUB_RE.test(asset.url) || 
          GITLAB_RE.test(asset.url) || 
          BITBUCKET_RE.test(asset.url) ||
          asset.url.includes('.git')
        )) {
          gitUrls.add(asset.url);
          log(`[trufflehog] Found Git repo in web assets: ${asset.url}`);
        }
      }
    }
    
    // 2. Check discovered endpoints for Git-related paths
    const endpointsResult = await pool.query(`
      SELECT meta 
      FROM artifacts 
      WHERE meta->>'scan_id' = $1 
        AND type = 'discovered_endpoints'
      ORDER BY created_at DESC 
      LIMIT 1
    `, [scanId]);
    
    if (endpointsResult.rows.length > 0) {
      const endpoints = endpointsResult.rows[0].meta?.endpoints || [];
      for (const endpoint of endpoints) {
        if (endpoint.path && (
          endpoint.path.includes('.git') ||
          endpoint.path.includes('/git/') ||
          endpoint.path.includes('/.git/')
        )) {
          // Construct full URL from endpoint
          const baseUrl = endpoint.baseUrl || `https://${scanId.split('-')[0]}.com`; // fallback
          const fullUrl = new URL(endpoint.path, baseUrl).toString();
          gitUrls.add(fullUrl);
          log(`[trufflehog] Found Git repo in endpoints: ${fullUrl}`);
        }
      }
    }
    
    // 3. Check for any linked_url artifacts that might contain Git repos
    const linkedUrlsResult = await pool.query(`
      SELECT val_text 
      FROM artifacts 
      WHERE meta->>'scan_id' = $1 
        AND type = 'linked_url'
        AND (
          val_text ~ 'github\.com' OR 
          val_text ~ 'gitlab\.com' OR 
          val_text ~ 'bitbucket\.org' OR
          val_text ~ '\.git'
        )
      LIMIT 20
    `, [scanId]);
    
    for (const row of linkedUrlsResult.rows) {
      const url = row.val_text;
      if (GITHUB_RE.test(url) || GITLAB_RE.test(url) || BITBUCKET_RE.test(url)) {
        gitUrls.add(url);
        log(`[trufflehog] Found Git repo in linked URLs: ${url}`);
      }
    }
    
    const repos = Array.from(gitUrls).slice(0, MAX_GIT_REPOS);
    log(`[trufflehog] Discovered ${repos.length} Git repositories from artifacts`);
    return repos;
    
  } catch (error) {
    log(`[trufflehog] Error retrieving Git repositories from artifacts: ${(error as Error).message}`);
    return [];
  }
}

export async function runTrufflehog(job: { domain: string; scanId: string }) {
  await guardTrufflehog();

  let findings = 0;
  
  // Get Git repositories from discovered artifacts instead of spiderfoot file
  const repos = await getGitRepos(job.scanId);
  if (repos.length) {
    log(`[trufflehog] Scanning ${repos.length} Git repositories for secrets`);
    findings += await scanGitRepos(repos, job.scanId, async (output: string, src: SourceType, url: string) => {
      const secrets = processTruffleHogOutput(output);
      return await emitFindings(secrets, src, url);
    });
  } else {
    log('[trufflehog] No Git repositories found to scan from discovered artifacts');
    
    // Create an informational artifact about the lack of Git repositories
    await insertArtifact({
      type: 'scan_summary',
      val_text: `TruffleHog scan completed but no Git repositories were discovered for ${job.domain}`,
      severity: 'INFO',
      meta: { 
        scan_id: job.scanId, 
        total_findings: 0, 
        scope: 'git_discovery_failed',
        note: 'No Git repositories found in web assets, endpoints, or linked URLs'
      }
    });
  }

  await insertArtifact({
    type: 'scan_summary',
    val_text: `TruffleHog Git scan finished – ${findings} secret(s) found across ${repos.length} repositories`,
    severity: findings > 0 ? 'MEDIUM' : 'INFO',
    meta: { 
      scan_id: job.scanId, 
      total_findings: findings, 
      scope: 'git_only',
      repositories_scanned: repos.length,
      repositories_found: repos
    }
  });
  log(`[trufflehog] finished Git scan – findings=${findings}, repos=${repos.length}`);
  return findings;
}
</file>

<file path="webArchiveScanner.ts">
/*
 * =============================================================================
 * MODULE: webArchiveScanner.ts
 * =============================================================================
 * Web archive discovery using Wayback Machine and other archive services.
 * Discovers historical URLs that might have exposed secrets or sensitive files.
 * =============================================================================
 */

import axios from 'axios';
import * as https from 'node:https';
import { insertArtifact } from '../core/artifactStore.js';
import { log } from '../core/logger.js';

// Configuration - Tier-based scanning
const TIER1_MAX_ARCHIVE_URLS = 20;      // Quick scan: 20 URLs
const TIER2_MAX_ARCHIVE_URLS = 200;     // Deep dive: 200 URLs
const TIER1_MAX_YEARS_BACK = 1;         // Quick scan: 1 year
const TIER2_MAX_YEARS_BACK = 3;         // Deep dive: 3 years
const MAX_CONCURRENT_FETCHES = 8;      // Reduced from 12 for stability
const ARCHIVE_TIMEOUT = 8000;           // Reduced timeout
const WAYBACK_API_URL = 'https://web.archive.org/cdx/search/cdx';

interface ArchiveUrl {
    url: string;
    timestamp: string;
    statusCode: string;
    mimeType: string;
    digest: string;
    originalUrl: string;
    confidence: 'high' | 'medium' | 'low';
    reason: string;
}

interface ArchiveResult {
    url: string;
    content: string;
    size: number;
    accessible: boolean;
    archiveTimestamp: string;
    archiveUrl?: string;
    confidence?: 'high' | 'medium' | 'low';
    reason?: string;
}

const USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15'
];

/**
 * Get historical URLs from Wayback Machine
 */
async function getWaybackUrls(domain: string, tier: 'tier1' | 'tier2' = 'tier1'): Promise<ArchiveUrl[]> {
    const archiveUrls: ArchiveUrl[] = [];
    
    try {
        const currentYear = new Date().getFullYear();
        const maxYearsBack = tier === 'tier1' ? TIER1_MAX_YEARS_BACK : TIER2_MAX_YEARS_BACK;
        const maxUrls = tier === 'tier1' ? TIER1_MAX_ARCHIVE_URLS : TIER2_MAX_ARCHIVE_URLS;
        const startYear = currentYear - maxYearsBack;
        
        log(`[webArchiveScanner] ${tier.toUpperCase()} scan: Querying Wayback Machine for ${domain} (${startYear}-${currentYear})`);
        
        // Query Wayback Machine CDX API
        const response = await axios.get(WAYBACK_API_URL, {
            params: {
                url: `*.${domain}/*`,
                output: 'json',
                collapse: 'digest',
                from: startYear.toString(),
                to: currentYear.toString(),
                limit: maxUrls * 2, // Get more to filter down
                filter: 'statuscode:200'
            },
            timeout: ARCHIVE_TIMEOUT
        });
        
        if (!Array.isArray(response.data) || response.data.length < 2) {
            log('[webArchiveScanner] No archive data found');
            return archiveUrls;
        }
        
        // Skip header row and process results
        const results = response.data.slice(1);
        log(`[webArchiveScanner] Found ${results.length} archived URLs`);
        
        for (const row of results) {
            if (archiveUrls.length >= maxUrls) break;
            
            const [urlkey, timestamp, originalUrl, mimeType, statusCode, digest] = row;
            
            if (!originalUrl || !timestamp) continue;
            
            // Filter for interesting URLs
            const confidence = categorizeUrl(originalUrl);
            if (confidence === 'low') continue;
            
            archiveUrls.push({
                url: `https://web.archive.org/web/${timestamp}/${originalUrl}`,
                timestamp,
                statusCode,
                mimeType: mimeType || 'unknown',
                digest,
                originalUrl,
                confidence,
                reason: getUrlReason(originalUrl)
            });
        }
        
        // Sort by confidence and recency
        archiveUrls.sort((a, b) => {
            const confidenceScore = { high: 3, medium: 2, low: 1 };
            const aScore = confidenceScore[a.confidence];
            const bScore = confidenceScore[b.confidence];
            
            if (aScore !== bScore) return bScore - aScore;
            return b.timestamp.localeCompare(a.timestamp);
        });
        
        log(`[webArchiveScanner] Filtered to ${archiveUrls.length} high-interest archived URLs`);
        
    } catch (error) {
        log('[webArchiveScanner] Error querying Wayback Machine:', (error as Error).message);
    }
    
    const maxUrls = tier === 'tier1' ? TIER1_MAX_ARCHIVE_URLS : TIER2_MAX_ARCHIVE_URLS;
    return archiveUrls.slice(0, maxUrls);
}

/**
 * Categorize URLs by likelihood of containing secrets
 */
function categorizeUrl(url: string): 'high' | 'medium' | 'low' {
    const urlLower = url.toLowerCase();
    
    // High-value patterns
    const highPatterns = [
        /\.env/i,
        /config\.(json|js|php|yaml|yml)/i,
        /settings\.(json|js|php|yaml|yml)/i,
        /\.git\//i,
        /\.svn\//i,
        /backup/i,
        /\.sql$/i,
        /\.zip$/i,
        /\.tar\.gz$/i,
        /admin/i,
        /debug/i,
        /test/i,
        /staging/i,
        /dev/i,
        /api.*config/i,
        /swagger\.(json|yaml|yml)/i,
        /openapi\.(json|yaml|yml)/i,
        /\.map$/i, // Source maps
        /package\.json$/i,
        /composer\.json$/i,
        /requirements\.txt$/i,
        /Gemfile/i,
        /pom\.xml$/i,
        /web\.config$/i,
        /\.htaccess$/i,
        /wp-config\.php$/i,
        /database\.(php|json|yml|yaml)/i
    ];
    
    // Medium-value patterns
    const mediumPatterns = [
        /\.(js|css)$/i,
        /\/api\//i,
        /\/docs?\//i,
        /\/help/i,
        /\/info/i,
        /\.(php|asp|aspx|jsp)$/i,
        /robots\.txt$/i,
        /sitemap\.xml$/i,
        /\.well-known\//i
    ];
    
    for (const pattern of highPatterns) {
        if (pattern.test(urlLower)) return 'high';
    }
    
    for (const pattern of mediumPatterns) {
        if (pattern.test(urlLower)) return 'medium';
    }
    
    return 'low';
}

/**
 * Get reason why URL is interesting
 */
function getUrlReason(url: string): string {
    const urlLower = url.toLowerCase();
    
    if (/\.env/i.test(url)) return 'Environment configuration file';
    if (/config\./i.test(url)) return 'Configuration file';
    if (/settings\./i.test(url)) return 'Settings file';
    if (/\.git\//i.test(url)) return 'Git repository exposure';
    if (/backup/i.test(url)) return 'Backup file';
    if (/admin/i.test(url)) return 'Admin interface';
    if (/debug/i.test(url)) return 'Debug endpoint';
    if (/swagger|openapi/i.test(url)) return 'API documentation';
    if (/\.map$/i.test(url)) return 'Source map file';
    if (/package\.json$/i.test(url)) return 'Package manifest';
    if (/wp-config\.php$/i.test(url)) return 'WordPress configuration';
    if (/database\./i.test(url)) return 'Database configuration';
    if (/api/i.test(url)) return 'API endpoint';
    
    return 'Potentially sensitive file';
}

/**
 * Fetch archived content that might contain secrets
 */
async function fetchArchivedContent(archiveUrls: ArchiveUrl[]): Promise<ArchiveResult[]> {
    const results: ArchiveResult[] = [];
    const httpsAgent = new https.Agent({ rejectUnauthorized: false });
    
    // Process URLs in chunks to control concurrency
    for (let i = 0; i < archiveUrls.length; i += MAX_CONCURRENT_FETCHES) {
        const chunk = archiveUrls.slice(i, i + MAX_CONCURRENT_FETCHES);
        
        const chunkResults = await Promise.allSettled(
            chunk.map(async (archiveUrl) => {
                try {
                    log(`[webArchiveScanner] Fetching archived content: ${archiveUrl.originalUrl}`);
                    
                    const response = await axios.get(archiveUrl.url, {
                        timeout: ARCHIVE_TIMEOUT,
                        maxContentLength: 5 * 1024 * 1024, // 5MB max
                        httpsAgent,
                        headers: {
                            'User-Agent': USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)]
                        },
                        validateStatus: () => true
                    });
                    
                    if (response.status === 200 && response.data) {
                        const content = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                        
                        return {
                            url: archiveUrl.originalUrl,
                            content: content.length > 100000 ? content.substring(0, 100000) + '...[truncated]' : content,
                            size: content.length,
                            accessible: true,
                            archiveTimestamp: archiveUrl.timestamp,
                            archiveUrl: archiveUrl.url,
                            confidence: archiveUrl.confidence,
                            reason: archiveUrl.reason
                        };
                    }
                    
                } catch (error) {
                    log(`[webArchiveScanner] Failed to fetch ${archiveUrl.originalUrl}:`, (error as Error).message);
                }
                
                return null;
            })
        );
        
        // Process chunk results
        for (const result of chunkResults) {
            if (result.status === 'fulfilled' && result.value) {
                results.push(result.value);
                log(`[webArchiveScanner] Successfully fetched archived content: ${result.value.url}`);
            }
        }
        
        // Rate limiting delay
        if (i + MAX_CONCURRENT_FETCHES < archiveUrls.length) {
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
    
    return results;
}

/**
 * Check if gau tool is available for alternative archive discovery
 */
async function checkGauAvailability(): Promise<boolean> {
    try {
        const { execFile } = await import('node:child_process');
        const { promisify } = await import('node:util');
        const exec = promisify(execFile);
        
        await exec('gau', ['--version']);
        return true;
    } catch (error) {
        return false;
    }
}

/**
 * Use gau tool for additional archive discovery
 */
async function getGauUrls(domain: string): Promise<string[]> {
    try {
        log('[webArchiveScanner] Using gau for additional archive discovery');
        
        const { execFile } = await import('node:child_process');
        const { promisify } = await import('node:util');
        const exec = promisify(execFile);
        
        const { stdout } = await exec('gau', [
            domain,
            '--threads', '5',
            '--timeout', '30',
            '--retries', '2'
        ], { timeout: 60000 });
        
        const urls = stdout.trim().split('\n').filter(Boolean);
        log(`[webArchiveScanner] gau discovered ${urls.length} URLs`);
        
        // Filter for interesting URLs
        return urls.filter(url => categorizeUrl(url) !== 'low').slice(0, 100);
        
    } catch (error) {
        log('[webArchiveScanner] Error using gau:', (error as Error).message);
        return [];
    }
}

/**
 * Main Web Archive Scanner function
 */
export async function runWebArchiveScanner(job: { domain: string; scanId?: string; tier?: 'tier1' | 'tier2' }): Promise<number> {
    const tier = job.tier || 'tier1';
    log(`[webArchiveScanner] Starting ${tier.toUpperCase()} web archive discovery for ${job.domain}`);
    
    if (!job.scanId) {
        log('[webArchiveScanner] No scanId provided - skipping archive scanning');
        return 0;
    }
    
    try {
        let totalFindings = 0;
        
        // 1. Get historical URLs from Wayback Machine
        const waybackUrls = await getWaybackUrls(job.domain, tier);
        
        // 2. Try gau tool if available (tier2 only for comprehensive scans)
        const gauAvailable = await checkGauAvailability();
        let gauUrls: string[] = [];
        if (gauAvailable && tier === 'tier2') {
            gauUrls = await getGauUrls(job.domain);
        } else if (tier === 'tier1') {
            log('[webArchiveScanner] Skipping gau in tier1 for speed');
        } else {
            log('[webArchiveScanner] gau tool not available - using Wayback Machine only');
        }
        
        // 3. Fetch archived content for high-value URLs
        const archivedContent = await fetchArchivedContent(waybackUrls);
        
        // 4. Save archived content as web assets for secret scanning
        if (archivedContent.length > 0) {
            await insertArtifact({
                type: 'discovered_web_assets',
                val_text: `Discovered ${archivedContent.length} archived web assets for secret scanning on ${job.domain}`,
                severity: 'INFO',
                meta: {
                    scan_id: job.scanId,
                    scan_module: 'webArchiveScanner',
                    assets: archivedContent.map(content => ({
                        url: content.url,
                        type: 'html',
                        size: content.size,
                        confidence: content.confidence,
                        source: 'web_archive',
                        content: content.content,
                        mimeType: 'text/html',
                        archive_timestamp: content.archiveTimestamp,
                        archive_url: content.archiveUrl,
                        reason: content.reason
                    }))
                }
            });
            
            totalFindings += archivedContent.length;
        }
        
        // 5. Save historical URL list for reference
        if (waybackUrls.length > 0 || gauUrls.length > 0) {
            await insertArtifact({
                type: 'historical_urls',
                val_text: `Discovered ${waybackUrls.length + gauUrls.length} historical URLs for ${job.domain}`,
                severity: 'INFO',
                meta: {
                    scan_id: job.scanId,
                    scan_module: 'webArchiveScanner',
                    wayback_urls: waybackUrls,
                    gau_urls: gauUrls,
                    years_scanned: tier === 'tier1' ? TIER1_MAX_YEARS_BACK : TIER2_MAX_YEARS_BACK,
                    total_historical_urls: waybackUrls.length + gauUrls.length,
                    tier: tier
                }
            });
        }
        
        log(`[webArchiveScanner] Completed ${tier} web archive discovery: ${totalFindings} assets found from ${waybackUrls.length + gauUrls.length} historical URLs`);
        return totalFindings;
        
    } catch (error) {
        log('[webArchiveScanner] Error in web archive discovery:', (error as Error).message);
        return 0;
    }
}
</file>

<file path="whoisWrapper.ts">
/**
 * TypeScript wrapper for the Python WHOIS resolver (RDAP + Whoxy)
 * Provides 87% cost savings vs WhoisXML
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { log } from '../core/logger.js';

const exec = promisify(execFile);

interface WhoisRecord {
  domain: string;
  registrant_name?: string;
  registrant_org?: string;
  registrar?: string;
  creation_date?: string;
  source: 'rdap' | 'whoxy';
  fetched_at: string;
}

interface WhoisStats {
  rdap_calls: number;
  whoxy_calls: number;
  estimated_cost: number;
  saved_vs_whoisxml: number;
}

/**
 * Resolve WHOIS data for multiple domains using hybrid RDAP+Whoxy approach
 * Cost: ~$0.002/call (vs $0.015/call for WhoisXML) = 87% savings
 */
export async function resolveWhoisBatch(domains: string[]): Promise<{ records: WhoisRecord[]; stats: WhoisStats }> {
  if (!process.env.WHOXY_API_KEY) {
    log('[whoisWrapper] WHOXY_API_KEY not set - WHOIS resolution disabled');
    return { 
      records: domains.map(d => ({
        domain: d,
        source: 'rdap' as const,
        fetched_at: new Date().toISOString()
      })),
      stats: { rdap_calls: 0, whoxy_calls: 0, estimated_cost: 0, saved_vs_whoisxml: 0 }
    };
  }

  const tempFile = join('/tmp', `whois_domains_${Date.now()}.json`);
  
  try {
    // Write domains to temp file
    await writeFile(tempFile, JSON.stringify(domains));
    
    // Call Python resolver with domains as arguments
    const pythonScript = join(process.cwd(), 'apps/workers/modules/whoisResolver.py');
    const { stdout, stderr } = await exec('python3', [pythonScript, ...domains], { 
        timeout: 60_000,
        env: { 
          ...process.env, 
          WHOXY_API_KEY: process.env.WHOXY_API_KEY || ''
        }
      });

    if (stderr) {
      log('[whoisWrapper] Python stderr:', stderr);
    }

    // Parse line-by-line JSON output from Python script
    const lines = stdout.trim().split('\n').filter(line => line.trim());
    const records: WhoisRecord[] = [];
    
    for (const line of lines) {
      try {
        const record = JSON.parse(line);
        records.push({
          domain: record.domain,
          registrant_name: record.registrant_name,
          registrant_org: record.registrant_org,
          registrar: record.registrar,
          creation_date: record.creation_date,
          source: record.source,
          fetched_at: record.fetched_at
        });
      } catch (parseError) {
        log('[whoisWrapper] Failed to parse WHOIS record line:', line);
      }
    }
    
    // Calculate stats
    const rdapCalls = records.filter(r => r.source === 'rdap').length;
    const whoxyCalls = records.filter(r => r.source === 'whoxy').length;
    const estimatedCost = whoxyCalls * 0.002;
    const savedVsWhoisxml = domains.length * 0.015 - estimatedCost;
    
    const result = {
      records,
      stats: {
        rdap_calls: rdapCalls,
        whoxy_calls: whoxyCalls,
        estimated_cost: estimatedCost,
        saved_vs_whoisxml: savedVsWhoisxml
      }
    };
    
    log(`[whoisWrapper] WHOIS resolution: ${rdapCalls} RDAP (free) + ${whoxyCalls} Whoxy (~$${estimatedCost.toFixed(3)})`);
    log(`[whoisWrapper] Saved $${savedVsWhoisxml.toFixed(3)} vs WhoisXML`);
    
    return result;
    
  } catch (error) {
    log('[whoisWrapper] Error resolving WHOIS data:', (error as Error).message);
    
    // Fallback to empty records
    return {
      records: domains.map(d => ({
        domain: d,
        source: 'rdap' as const,
        fetched_at: new Date().toISOString()
      })),
      stats: { rdap_calls: 0, whoxy_calls: 0, estimated_cost: 0, saved_vs_whoisxml: 0 }
    };
    
  } finally {
    // Cleanup temp file
    await unlink(tempFile).catch(() => {});
  }
}

/**
 * Legacy single domain resolver for backward compatibility
 */
export async function resolveWhoisSingle(domain: string): Promise<WhoisRecord | null> {
  const result = await resolveWhoisBatch([domain]);
  return result.records[0] || null;
}
</file>

<file path="zapScan.ts">
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
import { insertArtifact, insertFinding, pool } from '../core/artifactStore.js';
import { log as rootLog } from '../core/logger.js';
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
    const { rows } = await pool.query(
      `SELECT DISTINCT src_url 
       FROM artifacts 
       WHERE meta->>'scan_id' = $1 
         AND type IN ('discovered_endpoint', 'http_probe')
         AND src_url ILIKE $2
         AND src_url ~ '^https?://'`,
      [scanId, `%${domain}%`]
    );
    
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
    throw new Error(`Failed to create artifacts directory: ${dirResult.error}`);
  }

  log(`Running ZAP baseline scan for ${target}`);
  
  const zapArgs = [
    'run', '--rm',
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
            log(`Failed to cleanup ZAP output file: ${cleanupResult.error}`);
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
      zapProcess.kill('SIGKILL');
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
    throw new Error(`Failed to parse ZAP results: ${result.error}`);
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
</file>

</files>
