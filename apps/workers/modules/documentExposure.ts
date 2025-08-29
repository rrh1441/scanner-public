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
import { httpRequest, httpGetText } from '../net/httpClient.js';
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
import { logLegacy as log } from '../core/logger.js';

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
    const response = await httpRequest({
      url: SERPER_URL,
      method: 'POST',
      headers: { 'X-API-KEY': process.env.SERPER_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ q: `site:${domain}`, num: 1 }),
      totalTimeoutMs: 10000,
      forceIPv4: true
    });
    const data = JSON.parse(new TextDecoder('utf-8').decode(response.body));
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

    const head = await httpRequest({
      url: urlStr,
      method: 'HEAD',
      totalTimeoutMs: 10000,
      forceIPv4: true
    }).catch(() => null);
    if (parseInt(head?.headers['content-length'] ?? '0', 10) > 15 * 1024 * 1024) return null;

    /* -------------------------------------------------------------------- */
    /* Only proceed if Content-Type OR verified MIME is allowed document     */
    /* -------------------------------------------------------------------- */
    const reported = head?.headers['content-type'] ?? 'application/octet-stream';
    if (!ALLOWED_MIME.has(reported.split(';')[0])) {
      // Quick positive filter: if content-type is not clearly doc, bail early.
      if (!/\.pdf$|\.docx$|\.xlsx$/i.test(urlStr)) return null;
    }

    const res = await httpRequest({
      url: urlStr,
      method: 'GET',
      totalTimeoutMs: 30000,
      forceIPv4: true,
      maxBodyBytes: 10_000_000
    });
    const buf = Buffer.from(res.body);

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
  console.log(`[documentExposure] START at ${new Date().toISOString()}`);
  const start = Date.now();
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

  console.log(`[documentExposure] Calling Serper API for ${domain}...`);
  log(`[documentExposure] Starting ${allQueries.length} parallel Serper queries`);
  
  // Execute all queries in parallel
  const serperStart = Date.now();
  const queryResults = await Promise.allSettled(
    allQueries.map(async ({query, category}, index) => {
      try {
        log(`[documentExposure] Serper API call ${index + 1}: "${query}"`);
        const response = await httpRequest({
          url: SERPER_URL,
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ q: query, num: 20 }),
          totalTimeoutMs: 10000,
          forceIPv4: true
        });
        const data = JSON.parse(new TextDecoder('utf-8').decode(response.body));
        const results = data.organic ?? [];
        console.log(`[documentExposure] Serper query ${index + 1} returned ${results.length} results`);
        log(`[documentExposure] Query ${index + 1} returned ${results.length} results`);
        return { category, query, results, success: true };
      } catch (error) {
        log(`[documentExposure] Query ${index + 1} failed: ${(error as Error).message}`);
        return { category, query, results: [], success: false, error };
      }
    })
  );
  
  console.log(`[documentExposure] Serper returned ${queryResults.filter(r => r.status === 'fulfilled').length} successful results in ${Date.now() - serperStart}ms`);

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
      console.log(`[documentExposure] Found document: ${urlStr} (${platform})`);
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
  console.log(`[documentExposure] COMPLETE: Found ${total} exposed documents in ${Date.now() - start}ms`);
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
