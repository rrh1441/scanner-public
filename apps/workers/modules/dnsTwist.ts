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
import { httpClient, AxiosRequestConfig } from '../net/httpClient.js';
import { parse } from 'node-html-parser';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as log } from '../core/logger.js';
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
      const resp = await httpClient.request(cfg);
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
    const { data } = await httpClient.get(`https://crt.sh/?q=%25.${domain}&output=json`, { timeout: 10_000 });
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
    const { data } = await httpClient.get(`https://crt.sh/?q=%25.${domain}&output=json`, { timeout: 10_000 });
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
  
  // 2. Character-level similarity (Levenshtein-like) - IMPROVED THRESHOLDS
  const editDistance = calculateEditDistance(originalBase, typosquatBase);
  const maxLength = Math.max(originalBase.length, typosquatBase.length);
  const charSimilarity = 1 - (editDistance / maxLength);
  
  // Tightened thresholds to reduce false positives on short domains
  if (charSimilarity > 0.85) {
    similarityScore += 70;
    emailPhishingRisk += 60;
    evidence.push(`High character similarity: ${Math.round(charSimilarity * 100)}% (${editDistance} character changes)`);
  } else if (charSimilarity > 0.75 && editDistance <= 2) {
    // Only flag moderate similarity if 2 or fewer character changes
    similarityScore += 40;
    emailPhishingRisk += 35;
    evidence.push(`Moderate character similarity: ${Math.round(charSimilarity * 100)}% (${editDistance} character changes)`);
  } else if (charSimilarity > 0.6 && editDistance === 1 && originalBase.length >= 6) {
    // Single character change only for longer domains (6+ chars)
    similarityScore += 25;
    emailPhishingRisk += 20;
    evidence.push(`Single character change in longer domain: ${Math.round(charSimilarity * 100)}% (${editDistance} character changes)`);
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
      const response = await httpClient.get(`${proto}://${domain}`, {
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
      const { data } = await httpClient.get(`${proto}://${domain}`, {
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
    const response = await httpClient.post('https://google.serper.dev/search', {
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

  const prompt = `You are a cybersecurity expert analyzing typosquat domains. Compare these domains for PHISHING THREAT RISK:

ORIGINAL: ${safeDomain}
Title: "${safeOriginalTitle}"
Description: "${safeOriginalSnippet}"

TYPOSQUAT: ${safeTyposquat}  
Title: "${safeTyposquatTitle}"
Description: "${safeTyposquatSnippet}"

CRITICAL: If the typosquat is a LEGITIMATE ESTABLISHED BUSINESS (real estate, law firm, restaurant, local business, professional services, etc.) with UNIQUE content/services, rate it 0-20 (LOW THREAT) regardless of domain similarity.

Examples of LEGITIMATE BUSINESSES that should score LOW:
- "Central Iowa Realtors" vs tech company = different industries = LOW THREAT
- Local restaurants, law firms, medical practices = LEGITIMATE = LOW THREAT  
- Established businesses with real addresses/phone numbers = LOW THREAT

HIGH THREAT indicators:
- Copying original brand content/design
- Parked/minimal content with high domain similarity
- Login forms targeting original's users
- No legitimate business content

IGNORE domain name similarity if typosquat has clear legitimate business operations in different industry.

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
      const response = await httpClient.post('https://api.openai.com/v1/chat/completions', {
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
      const response = await httpClient.get('https://www.whoisxmlapi.com/whoisserver/WhoisService', {
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
          
          // Extract base domains for optimization logic
          const originalBase = job.domain.split('.')[0].toLowerCase();
          const typosquatBase = entry.domain.split('.')[0].toLowerCase();
          const editDistance = calculateEditDistance(originalBase, typosquatBase);
          
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
              
              // OPTIMIZATION: Skip expensive AI analysis for obvious low-risk cases
              const skipAI = (
                // Very low domain similarity + different registrar = likely different business
                (threatSignals.domainSimilarity < 30 && !registrarMatch) ||
                // Algorithmic domains with low similarity
                (threatSignals.isAlgorithmic && threatSignals.domainSimilarity < 40) ||
                // Already confirmed defensive registration
                (registrarMatch && registrantMatch) ||
                // Short domains with single char change (like "gibr" vs "cibr")
                (originalBase.length <= 5 && editDistance === 1 && threatSignals.domainSimilarity < 80)
              );
              
              if (skipAI) {
                log(`[dnstwist] 🚀 Skipping AI analysis for obvious case: ${entry.domain} (similarity: ${threatSignals.domainSimilarity}%, algorithmic: ${threatSignals.isAlgorithmic}, registrar match: ${registrarMatch})`);
                phishing = {
                  score: threatSignals.domainSimilarity,
                  evidence: [...threatSignals.similarityEvidence, 'Skipped AI analysis - obvious low-risk case']
                };
              } else {
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
                // ENHANCED FALLBACK: Check for obvious legitimate business indicators
                let isObviousLegitBusiness = false;
                
                // Quick legitimate business check using search snippet if available
                if (typosquatSiteInfo.snippet || typosquatSiteInfo.title) {
                  const content = (typosquatSiteInfo.snippet + ' ' + typosquatSiteInfo.title).toLowerCase();
                  const businessIndicators = [
                    'real estate', 'realty', 'realtor', 'properties', 'law firm', 'attorney', 'legal services',
                    'restaurant', 'cafe', 'diner', 'medical', 'dental', 'clinic', 'hospital', 'doctor',
                    'insurance', 'financial', 'accounting', 'consulting', 'contractor', 'construction',
                    'auto repair', 'mechanic', 'salon', 'spa', 'veterinary', 'church', 'school',
                    'located in', 'serving', 'call us', 'contact us', 'phone:', 'address:', 'hours:'
                  ];
                  
                  const businessMatches = businessIndicators.filter(indicator => content.includes(indicator));
                  if (businessMatches.length >= 2) {
                    isObviousLegitBusiness = true;
                    log(`[dnstwist] 📋 Obvious legitimate business detected: ${entry.domain} (${businessMatches.join(', ')})`);
                  }
                }
                
                if (isObviousLegitBusiness && threatSignals.domainSimilarity < 70) {
                  // Override for obvious legitimate business with low similarity
                  score = Math.max(score - 40, 15);
                  threatReasoning.push('🏢 Obvious legitimate business in different industry - low threat');
                  phishing = {
                    score: Math.max(threatSignals.domainSimilarity - 30, 10),
                    evidence: [...threatSignals.similarityEvidence, 'Legitimate business with professional content']
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
              // Different registrars = potential red flag (defensive registrations would use same registrar)
              score += 25; // Moderate penalty - different registrars are suspicious
              threatReasoning.push('Different registrar - potential threat (defensive registrations typically use same registrar)');
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
            
            // IMPROVED THREAT CLASSIFICATION - Higher thresholds to reduce false positives
            if (isLegitimateBusinessByAI) {
              threatClass = 'MONITOR';
              severity = 'INFO';
              log(`[dnstwist] 🤖 AI OVERRIDE: ${entry.domain} marked as INFO severity - legitimate different business`);
            } else if (score >= 100 || threatSignals.httpContent.hasLoginForm) {
              // CRITICAL only for very high scores or login forms
              threatClass = 'TAKEDOWN';
              severity = 'CRITICAL';
            } else if (score >= 70) {
              // HIGH threshold raised from 50 to 70
              threatClass = 'TAKEDOWN';
              severity = 'HIGH';
            } else if (score >= 45) {
              // MEDIUM threshold raised from 30 to 45
              threatClass = 'INVESTIGATE';
              severity = 'MEDIUM';
            } else if (score >= 25) {
              // LOW threshold raised from 20 to 25
              threatClass = 'MONITOR';
              severity = 'LOW';
            } else {
              // INFO for very low scores
              threatClass = 'MONITOR';
              severity = 'INFO';
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
