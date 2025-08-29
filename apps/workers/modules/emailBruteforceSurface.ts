/**
 * Email Bruteforce Surface Module
 * 
 * Uses Nuclei templates to detect exposed email services that could be targets
 * for bruteforce attacks, including OWA, Exchange, IMAP, and SMTP services.
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
    // Pool query removed for GCP migration - starting fresh
    const urlRows: any[] = [];
    const urlResult = { rows: urlRows };    
    urlRows.forEach((row: any) => {
      targets.add(row.val_text.trim());
    });
    
    // Get hostnames and subdomains
    // Pool query removed for GCP migration - starting fresh
    const hostRows: any[] = [];
    const hostResult = { rows: hostRows };    
    const hosts = new Set([domain]);
    hostRows.forEach((row: any) => {
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