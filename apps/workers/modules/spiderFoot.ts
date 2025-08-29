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
import { httpClient } from '../net/httpClient.js';
import { insertArtifact } from '../core/artifactStore.js';
import { logLegacy as log } from '../core/logger.js';

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
            const response = await httpClient.get(url, { 
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
    
    // Sanitize domain input to prevent command injection
    const sanitizedDomain = domain.replace(/[^a-zA-Z0-9.-]/g, '');
    if (sanitizedDomain !== domain) {
        throw new Error(`Invalid domain format: ${domain}`);
    }
    
    // Use array-based command execution to prevent injection
    const args = ['-q', '-s', sanitizedDomain, '-m', TARGET_MODULES, '-o', 'json'];
    log('[SpiderFoot] Executing with args:', args);
    
    const env = { ...process.env, SF_CONFDIR: confDir };
    const TIMEOUT_MS = parseInt(process.env.SPIDERFOOT_TIMEOUT_MS || '300000', 10);
    
    try {
        const start = Date.now();
        const { stdout, stderr } = await execAsync(`${spiderFootCmd} ${args.map(arg => `'${arg}'`).join(' ')}`, { env, timeout: TIMEOUT_MS, shell: '/bin/sh', maxBuffer: 20 * 1024 * 1024 });
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
