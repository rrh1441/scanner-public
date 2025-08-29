/**
 * Lightweight Accessibility Scanner
 * 
 * Quick accessibility compliance check without Puppeteer.
 * Detects common ADA/WCAG violations that create lawsuit risk.
 */

import { httpClient } from '../net/httpClient.js';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as rootLog } from '../core/logger.js';
import { executeModule } from '../util/errorHandler.js';

const log = (...args: unknown[]) => rootLog('[accessibilityLightweight]', ...args);

interface AccessibilityIssue {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
  riskLevel: 'HIGH_LAWSUIT_RISK' | 'MEDIUM_LAWSUIT_RISK' | 'LOW_LAWSUIT_RISK';
}

/**
 * Check for basic accessibility violations in HTML content
 */
function checkAccessibilityViolations(html: string, url: string): AccessibilityIssue[] {
  const issues: AccessibilityIssue[] = [];
  
  // Check for missing alt attributes on images
  const imgTagsWithoutAlt = html.match(/<img(?![^>]*alt\s*=)[^>]*>/gi) || [];
  if (imgTagsWithoutAlt.length > 0) {
    issues.push({
      type: 'MISSING_ALT_TEXT',
      severity: 'HIGH',
      description: `${imgTagsWithoutAlt.length} images missing alt text`,
      recommendation: 'Add descriptive alt attributes to all images for screen readers',
      riskLevel: 'HIGH_LAWSUIT_RISK'
    });
  }

  // Check for missing form labels
  const inputsWithoutLabels = html.match(/<input(?![^>]*aria-label)(?![^>]*aria-labelledby)(?![^>]*title)[^>]*>/gi) || [];
  if (inputsWithoutLabels.length > 0) {
    issues.push({
      type: 'MISSING_FORM_LABELS',
      severity: 'HIGH', 
      description: `${inputsWithoutLabels.length} form inputs missing labels`,
      recommendation: 'Add proper labels or aria-labels to all form inputs',
      riskLevel: 'HIGH_LAWSUIT_RISK'
    });
  }

  // Check for missing page title
  if (!html.match(/<title[^>]*>[\s\S]*?<\/title>/i)) {
    issues.push({
      type: 'MISSING_PAGE_TITLE',
      severity: 'MEDIUM',
      description: 'Page missing title element',
      recommendation: 'Add descriptive page title for screen readers and SEO',
      riskLevel: 'MEDIUM_LAWSUIT_RISK'
    });
  }

  // Check for missing language declaration
  if (!html.match(/<html[^>]*lang\s*=/i)) {
    issues.push({
      type: 'MISSING_LANGUAGE',
      severity: 'MEDIUM',
      description: 'HTML missing language declaration',
      recommendation: 'Add lang attribute to html element (e.g., <html lang="en">)',
      riskLevel: 'MEDIUM_LAWSUIT_RISK'
    });
  }

  // Check for insufficient color contrast indicators
  const hasLightColors = html.match(/color\s*:\s*#[f-f]{3,6}|color\s*:\s*rgb\(2[5-9][0-9]|color\s*:\s*white/gi);
  const hasLightBackground = html.match(/background[^:]*:\s*#[f-f]{3,6}|background[^:]*:\s*rgb\(2[5-9][0-9]|background[^:]*:\s*white/gi);
  if (hasLightColors && hasLightBackground) {
    issues.push({
      type: 'POTENTIAL_CONTRAST_ISSUES',
      severity: 'MEDIUM',
      description: 'Potential color contrast issues detected',
      recommendation: 'Ensure 4.5:1 contrast ratio for normal text, 3:1 for large text',
      riskLevel: 'MEDIUM_LAWSUIT_RISK'
    });
  }

  // Check for missing heading structure
  const h1Count = (html.match(/<h1[^>]*>/gi) || []).length;
  if (h1Count === 0) {
    issues.push({
      type: 'MISSING_H1',
      severity: 'MEDIUM',
      description: 'Page missing primary heading (h1)',
      recommendation: 'Add a descriptive h1 heading as the main page title',
      riskLevel: 'MEDIUM_LAWSUIT_RISK'
    });
  } else if (h1Count > 1) {
    issues.push({
      type: 'MULTIPLE_H1',
      severity: 'LOW',
      description: `Page has ${h1Count} h1 headings (should be 1)`,
      recommendation: 'Use only one h1 per page, use h2-h6 for subsections',
      riskLevel: 'LOW_LAWSUIT_RISK'
    });
  }

  // Check for inaccessible links
  const emptyLinks = html.match(/<a[^>]*>[\s]*<\/a>/gi) || [];
  if (emptyLinks.length > 0) {
    issues.push({
      type: 'EMPTY_LINKS',
      severity: 'HIGH',
      description: `${emptyLinks.length} empty or unclear links`,
      recommendation: 'Ensure all links have descriptive text or aria-labels',
      riskLevel: 'HIGH_LAWSUIT_RISK'
    });
  }

  return issues;
}

/**
 * Calculate overall accessibility risk score
 */
function calculateRiskScore(issues: AccessibilityIssue[]): {
  score: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  lawsuitRisk: boolean;
} {
  let score = 0;
  let highRiskIssues = 0;

  issues.forEach(issue => {
    switch (issue.severity) {
      case 'CRITICAL': score += 10; break;
      case 'HIGH': score += 5; break;
      case 'MEDIUM': score += 2; break;
      case 'LOW': score += 1; break;
    }
    
    if (issue.riskLevel === 'HIGH_LAWSUIT_RISK') {
      highRiskIssues++;
    }
  });

  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  if (score >= 20) riskLevel = 'CRITICAL';
  else if (score >= 10) riskLevel = 'HIGH';
  else if (score >= 5) riskLevel = 'MEDIUM';
  else riskLevel = 'LOW';

  const lawsuitRisk = highRiskIssues >= 2 || score >= 15;

  return { score, riskLevel, lawsuitRisk };
}

/**
 * Main lightweight accessibility scan function
 */
export async function runAccessibilityLightweight(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;
  
  return executeModule('accessibilityLightweight', async () => {
    const startTime = Date.now();
    log(`🔍 Starting lightweight accessibility scan for ${domain}`);

    let findingsCount = 0;
    const allIssues: AccessibilityIssue[] = [];

    try {
      // Test main page
      const response = await httpClient.get(`https://${domain}`, {
        timeout: 10000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
      });

      if (response.status === 200 && response.data) {
        const html = response.data as string;
        const issues = checkAccessibilityViolations(html, `https://${domain}`);
        allIssues.push(...issues);
        
        log(`Found ${issues.length} accessibility issues on main page`);
      }

      // Test www subdomain if different
      try {
        const wwwResponse = await httpClient.get(`https://www.${domain}`, {
          timeout: 5000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        });

        if (wwwResponse.status === 200 && wwwResponse.data) {
          const html = wwwResponse.data as string;
          const issues = checkAccessibilityViolations(html, `https://www.${domain}`);
          allIssues.push(...issues);
          
          log(`Found ${issues.length} accessibility issues on www subdomain`);
        }
      } catch (error) {
        // www subdomain might not exist, continue
      }

    } catch (error) {
      log(`Error fetching page: ${(error as Error).message}`);
      return 0;
    }

    if (allIssues.length === 0) {
      log('No accessibility issues found');
      return 0;
    }

    // Calculate risk score
    const riskAssessment = calculateRiskScore(allIssues);
    
    // Group issues by type for better reporting
    const groupedIssues = new Map<string, AccessibilityIssue[]>();
    allIssues.forEach(issue => {
      if (!groupedIssues.has(issue.type)) {
        groupedIssues.set(issue.type, []);
      }
      groupedIssues.get(issue.type)!.push(issue);
    });

    // Create findings for each issue type
    for (const [issueType, issues] of groupedIssues) {
      const representative = issues[0];
      const count = issues.length;
      
      const artifactId = await insertArtifact({
        type: 'accessibility_violation',
        val_text: `${representative.description} (${count} instances)`,
        severity: representative.severity,
        meta: {
          scan_id: scanId,
          scan_module: 'accessibilityLightweight',
          domain,
          issue_type: issueType,
          instance_count: count,
          risk_level: representative.riskLevel,
          scan_duration_ms: Date.now() - startTime
        }
      });

      await insertFinding({
        artifact_id: artifactId,
        finding_type: 'ACCESSIBILITY_VIOLATION',
        recommendation: representative.recommendation,
        description: `${representative.description}${count > 1 ? ` (${count} instances)` : ''}`,
        scan_id: scanId,
        severity: representative.severity,
        type: 'ACCESSIBILITY_VIOLATION'
      });

      findingsCount++;
    }

    // Create overall risk assessment
    const overallSeverity = riskAssessment.lawsuitRisk ? 'HIGH' : 
                           riskAssessment.riskLevel === 'HIGH' ? 'MEDIUM' : 'LOW';

    await insertArtifact({
      type: 'accessibility_summary',
      val_text: `Accessibility scan: ${allIssues.length} issues, risk score ${riskAssessment.score}${riskAssessment.lawsuitRisk ? ' (HIGH LAWSUIT RISK)' : ''}`,
      severity: overallSeverity,
      meta: {
        scan_id: scanId,
        scan_module: 'accessibilityLightweight',
        domain,
        total_issues: allIssues.length,
        risk_score: riskAssessment.score,
        risk_level: riskAssessment.riskLevel,
        lawsuit_risk: riskAssessment.lawsuitRisk,
        scan_duration_ms: Date.now() - startTime
      }
    });

    const duration = Date.now() - startTime;
    log(`Accessibility scan completed: ${findingsCount} findings in ${duration}ms`);
    
    return findingsCount;
    
  }, { scanId, target: domain });
}