/**
 * Accessibility Scan Module
 * 
 * Performs real WCAG 2.1 AA compliance testing to identify accessibility violations
 * that create genuine ADA lawsuit risk for companies.
 */

import { httpClient } from '../net/httpClient.js';
import { createHash } from 'node:crypto';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as rootLog } from '../core/logger.js';
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
        const { data } = await httpClient.get(sitemapUrl, { timeout: 10000 });
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
    // Starting fresh - always run accessibility scan
    log(`accessibility=change_detection domain="${domain}" status="starting_fresh"`);
    return true;
    
    // Note: The code below is unreachable but kept for future implementation
    // when we add persistence for accessibility scan history
    
    // Check if any pages changed
    const currentHashMap = new Map(currentHashes.map(h => [h.url, h]));
    const previousHashMap = new Map<string, PageHashData>(); // TODO: Load from storage
    
    for (const [url, currentHash] of currentHashMap) {
      const previousHash = previousHashMap.get(url);
      
      if (!previousHash) {
        log(`accessibility=change_detected domain="${domain}" url="${url}" reason="new_page"`);
        return true; // New page found
      }
      
      // Check if any component hash changed
      if (currentHash.titleHash !== previousHash?.titleHash ||
          currentHash.headingsHash !== previousHash?.headingsHash ||
          currentHash.linksHash !== previousHash?.linksHash ||
          currentHash.formsHash !== previousHash?.formsHash ||
          currentHash.contentHash !== previousHash?.contentHash) {
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