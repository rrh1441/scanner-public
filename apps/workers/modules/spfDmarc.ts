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
import { logLegacy as log } from '../core/logger.js';

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
    const { stdout } = await exec('dig', ['-4', 'TXT', domain, '+short'], { 
      timeout: 10000,
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      killSignal: 'SIGKILL' // Force kill if hangs
    });
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
  console.log(`[spfDmarc] START at ${new Date().toISOString()}`);
  log('[spfDmarc] Starting email security scan for', job.domain);
  let findingsCount = 0;

  // --- 1. DMARC Check (Existing logic is good) ---
  log('[spfDmarc] Checking DMARC record...');
  try {
    const { stdout: dmarcOut } = await exec('dig', ['-4', 'txt', `_dmarc.${job.domain}`, '+short'], {
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      killSignal: 'SIGKILL' // Force kill if hangs
    });
    if (!dmarcOut.trim()) {
        const artifactId = await insertArtifact({ type: 'dmarc_missing', val_text: `DMARC record missing`, severity: 'MEDIUM', meta: { scan_id: job.scanId, scan_module: 'spfDmarc' } });
        await insertFinding({
          scan_id: job.scanId,
          type: 'EMAIL_SECURITY_GAP',
          severity: 'MEDIUM',
          title: 'DMARC policy missing',
          description: 'No DMARC record found.',
          data: { recommendation: 'Implement a DMARC policy (start with p=none) to gain visibility into email channels and begin protecting against spoofing.' }
        });
        findingsCount++;
    } else if (/p=none/i.test(dmarcOut)) {
        const artifactId = await insertArtifact({ type: 'dmarc_weak', val_text: `DMARC policy is not enforcing`, severity: 'LOW', meta: { record: dmarcOut.trim(), scan_id: job.scanId, scan_module: 'spfDmarc' } });
        await insertFinding({
          scan_id: job.scanId,
          type: 'EMAIL_SECURITY_WEAKNESS',
          severity: 'LOW',
          title: 'DMARC policy too weak',
          description: 'DMARC policy is in monitoring mode (p=none) and provides no active protection.',
          data: { recommendation: 'Strengthen DMARC policy from p=none to p=quarantine or p=reject to actively prevent email spoofing.' }
        });
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
      await insertFinding({
        scan_id: job.scanId,
        type: 'EMAIL_SECURITY_GAP',
        severity: 'MEDIUM',
        title: 'SPF record missing',
        description: 'No SPF record found.',
        data: { recommendation: 'Implement an SPF record to specify all authorized mail servers. This is a foundational step for DMARC.' }
      });
      findingsCount++;
  } else if (spfResult.error) {
      const artifactId = await insertArtifact({ type: 'spf_invalid', val_text: `SPF record is invalid: ${spfResult.error}`, severity: 'HIGH', meta: { record: spfResult.record, lookups: spfResult.lookups, error: spfResult.error, scan_id: job.scanId, scan_module: 'spfDmarc' } });
      await insertFinding({
        scan_id: job.scanId,
        type: 'EMAIL_SECURITY_MISCONFIGURATION',
        severity: 'HIGH',
        title: 'SPF record invalid',
        description: `SPF record validation failed with error: ${spfResult.error}.`,
        data: { recommendation: `Correct the invalid SPF record. The error '${spfResult.error}' can cause email delivery failures for legitimate mail.` }
      });
      findingsCount++;
  } else {
    if (spfResult.allMechanism === '~all' || spfResult.allMechanism === '?all') {
        const artifactId = await insertArtifact({ type: 'spf_weak', val_text: `SPF policy is too permissive (${spfResult.allMechanism})`, severity: 'LOW', meta: { record: spfResult.record, scan_id: job.scanId, scan_module: 'spfDmarc' } });
        await insertFinding({
          scan_id: job.scanId,
          type: 'EMAIL_SECURITY_WEAKNESS',
          severity: 'LOW',
          title: 'SPF policy too weak',
          description: 'The SPF record does not instruct receivers to reject unauthorized mail.',
          data: { recommendation: 'Strengthen SPF policy by using "-all" (hard fail) instead of "~all" (soft fail) or "?all" (neutral).' }
        });
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
      const { stdout: dkimOut } = await exec('dig', ['-4', 'txt', `${selector}._domainkey.${job.domain}`, '+short'], {
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
        killSignal: 'SIGKILL' // Force kill if hangs
      });
      if (dkimOut.trim().includes('k=rsa')) {
        dkimFound = true;
        log(`[spfDmarc] Found DKIM record with selector: ${selector}`);
        break;
      }
    } catch (dkimError) { /* Selector does not exist */ }
  }
  
  if (!dkimFound) {
    const artifactId = await insertArtifact({ type: 'dkim_missing', val_text: `DKIM record not detected for common selectors`, severity: 'LOW', meta: { selectors_checked: commonSelectors, scan_id: job.scanId, scan_module: 'spfDmarc' } });
    await insertFinding({
      scan_id: job.scanId,
      type: 'EMAIL_SECURITY_GAP',
      severity: 'LOW',
      title: 'DKIM record missing',
      description: 'Could not find a valid DKIM record using a wide range of common selectors.',
      data: { recommendation: 'Implement DKIM signing for outbound email to cryptographically verify message integrity. This is a critical component for DMARC alignment.' }
    });
    findingsCount++;
  }

  // REFACTOR: --- 4. BIMI Check (Optional Enhancement) ---
  log('[spfDmarc] Checking for BIMI record...');
  try {
      const { stdout: bimiOut } = await exec('dig', ['-4', 'txt', `default._bimi.${job.domain}`, '+short'], {
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
        killSignal: 'SIGKILL' // Force kill if hangs
      });
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
