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

const CENSYS_PAT     = (process.env.CENSYS_PAT || process.env.CENSYS_TOKEN) as string;
const CENSYS_ORG_ID  = process.env.CENSYS_ORG_ID as string;
const DATA_DIR       = process.env.DATA_DIR ?? './data';
const MAX_HOSTS      = Number.parseInt(process.env.CENSYS_MAX_HOSTS ?? '10000', 10);
const BATCH_SIZE     = Number.parseInt(process.env.CENSYS_BATCH_SIZE ?? '5', 10);

const BASE   = 'https://api.platform.censys.io/v3/global';
const SEARCH = `${BASE}/search/query`;
const HOST   = `${BASE}/asset/host`;

const MAX_QPS = 1;
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
        Accept: 'application/vnd.censys.api.v3.host.v1+json',
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
      const services = host.services || [];
      for (const svc of services) {
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
    result: { hits: any[]; next_page_token?: string };
  }

  let cursor: string | undefined;
  const batch: string[] = [];

  do {
    const body: any = {
      query: domain
    };
    // eslint-disable-next-line no-await-in-loop
    const data = await censysFetch<SearchResp>(SEARCH, { method: 'POST', jsonBody: body });

    for (const hit of data.result.hits) {
      // Extract IP from the hit - only use actual IP addresses, not hostnames
      const resource = hit.webproperty_v1?.resource || hit.host_v1?.resource;
      if (resource && resource.ip) {
        // Only add actual IP addresses, skip hostnames
        const ip = resource.ip;
        if (ip && ip.match(/^\d+\.\d+\.\d+\.\d+$/) && hashes.size < MAX_HOSTS) {
          batch.push(ip);
          if (batch.length >= BATCH_SIZE) {
            // eslint-disable-next-line no-await-in-loop
            await processBatch(batch.splice(0));
          }
        }
      }
    }
    cursor = data.result.next_page_token;
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
  if (!(process.env.CENSYS_PAT || process.env.CENSYS_TOKEN) || !process.env.CENSYS_ORG_ID) {
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
