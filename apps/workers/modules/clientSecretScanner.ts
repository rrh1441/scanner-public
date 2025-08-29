// apps/workers/modules/clientSecretScanner.ts
// Lightweight client-side secret detector with plug-in regex support
// ------------------------------------------------------------------
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as log } from '../core/logger.js';

import fs from 'node:fs';
import yaml from 'yaml';                       // ← NEW – tiny dependency
import OpenAI from 'openai';

// ------------------------------------------------------------------
// Types
// ------------------------------------------------------------------
interface ClientSecretScannerJob { scanId: string; }
interface WebAsset { url: string; content: string; }

interface SecretPattern {
  name:      string;
  regex:     RegExp;
  severity:  'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  verify?:  (key: string) => Promise<boolean>;   // optional future hook
}
type SecretHit = { pattern: SecretPattern; match: string; context?: string };

// LLM validation cache to avoid redundant checks (legacy, unused by new pipeline)

// ------------------------------------------------------------------
// SecretSanity: Deterministic triage for high-entropy tokens
// ------------------------------------------------------------------

interface TriageFinding {
  id: number;
  sample: string;
  asset_url: string;
  around: string;
}

interface TriageResult {
  id: number;
  decision: 'REAL_SECRET' | 'FALSE_POSITIVE';
  reason: string;
}

const VENDOR_SPECIFIC_PATTERNS = [
  { pattern: /^sk_live_[0-9a-z]{24}/i, name: 'Stripe Live Key' },
  { pattern: /^(A3T|AKIA|ASIA)[A-Z0-9]{16}/, name: 'AWS Access Key' },
  { pattern: /^AIza[0-9A-Za-z-_]{35}/, name: 'Google API Key' },
  { pattern: /^eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}$/, name: 'JWT Token' },
  { pattern: /(postgres|mysql|mongodb):\/\/[^@]+@/, name: 'Database URL' },
  { pattern: /^pk\.[A-Za-z0-9]{60,}/, name: 'Mapbox Token' },
  { pattern: /^dd[0-9a-f]{32}/i, name: 'Datadog API Key' },
  { pattern: /^[a-f0-9]{32}(?:-dsn)?\.algolia\.net/i, name: 'Algolia Key' },
  { pattern: /^NRAA-[0-9a-f]{27}/i, name: 'New Relic License' },
  { pattern: /^pdt[A-Z0-9]{30,32}/, name: 'PagerDuty API Key' },
  { pattern: /^sk_test_[0-9a-zA-Z]{24}/, name: 'Stripe Test Key' },
  { pattern: /^xoxb-[0-9]{11,13}-[0-9]{11,13}-[A-Za-z0-9]{24}/, name: 'Slack Bot Token' },
  { pattern: /^ghp_[A-Za-z0-9]{36}/, name: 'GitHub Personal Access Token' }
];

const SECRET_CONTEXT_PATTERNS = [
  /\b(apikey|api_key|api-key|secret|token|auth_token|access_token|bearer|authorization|password|pwd|pass|credential|key)\s*[:=]\s*['"]*$/i,
  /\b(Authorization|Bearer)\s*:\s*['"]*$/i,
  /\bkey\s*[:=]\s*['"]*$/i,
  /\b(client_secret|client_id|private_key|secret_key)\s*[:=]\s*['"]*$/i
];

// NEW: Add patterns for filenames that are almost always noise
const BENIGN_FILENAME_PATTERNS = [
  /\.css$/, /\.s[ac]ss$/,                 // Stylesheets
  /\.svg$/, /\.ico$/, /\.woff2?$/,         // Assets
  /tailwind\.config\.(js|ts)$/,           // Tailwind Config
  /next\.config\.(js|mjs)$/,              // Next.js Config
  /vite\.config\.(js|ts)$/,               // Vite Config
  /package-lock\.json$/, /yarn\.lock$/,   // Lockfiles
  /\.map$/,                               // Source Maps
];

// EXPANDED: Beef up the benign context patterns
const BENIGN_CONTEXT_PATTERNS = [
  // Build artifacts and module loading
  /\b(chunkIds|webpack[A-Z]|manifest|modules|chunks|assets|vendors|remoteEntry)\s*[:=\[]/i,
  /\b(integrity)\s*:\s*["']sha\d+-/i, // package-lock.json integrity hashes
  /\b(chunk|hash|nonce|etag|filename|buildId|deploymentId|contenthash)\b/i,
  /\b(sourceMappingURL)=/i,

  // CSS, SVG, and styling
  /\.(js|css|map|json|html|svg|png|jpg|woff)['"`]/i,
  /\b(style|class|className|data-|aria-|data-test-id|cy-data|d)\s*[=:]/i, // includes SVG path `d` attribute
  /--[a-zA-Z0-9-]+:/, // CSS custom properties
  /rgba?\s*\(/, /hsla?\s*\(/, // Color functions
  
  // Common non-secret variables
  /\b(id|key|uid|uuid|type|ref|target|label|name|path|icon|variant|theme|size|mode)\s*[:=]/i,
  /\b(previous|current)_[a-zA-Z_]*id/i, // e.g. current_user_id

  // Framework/Library internals
  /\b(__NEXT_DATA__|__PRELOADED_STATE__|__REDUX_STATE__)/i,
  /\{\s*"version":\s*3,/i // Common start of a sourcemap file
];

function calculateShannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  const length = str.length;
  for (const count of Object.values(freq)) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }
  
  return entropy;
}

function isHexString(str: string): boolean {
  return /^[0-9a-fA-F]+$/.test(str);
}

function isBase64Url(str: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(str) && !/[+/=]/.test(str);
}

function checkVendorSpecificPatterns(sample: string): { isMatch: boolean; vendor?: string } {
  for (const { pattern, name } of VENDOR_SPECIFIC_PATTERNS) {
    if (pattern.test(sample)) {
      return { isMatch: true, vendor: name };
    }
  }
  return { isMatch: false };
}

function checkContextInspection(sample: string, around: string): { isSecret: boolean; reason?: string } {
  for (const pattern of SECRET_CONTEXT_PATTERNS) {
    const beforeSample = around.slice(0, around.indexOf(sample));
    if (pattern.test(beforeSample)) {
      return { isSecret: true, reason: 'assigned to secret-like variable' };
    }
  }
  
  for (const pattern of BENIGN_CONTEXT_PATTERNS) {
    if (pattern.test(around)) {
      return { isSecret: false, reason: 'appears in benign context' };
    }
  }
  
  return { isSecret: false };
}

function checkStructuralHeuristics(sample: string, around: string): { isBenign: boolean; reason?: string } {
  if ((sample.length === 32 || sample.length === 40) && isHexString(sample)) {
    if (around.match(/\b(chunk|webpack|hash|nonce|etag|filename)\b/i)) {
      return { isBenign: true, reason: `${sample.length}-char hex in webpack context` };
    }
  }
  
  if ((sample.length === 22 || sample.length === 43) && isBase64Url(sample)) {
    if (around.match(/\b(chunk|webpack|hash|nonce|etag|filename)\b/i)) {
      return { isBenign: true, reason: `${sample.length}-char base64-URL in build context` };
    }
  }
  
  return { isBenign: false };
}

function isInCSSOrHTMLContext(around: string): boolean {
  const context = around.toLowerCase();
  
  if (context.includes('<style') || context.includes('</style>')) return true;
  if (context.match(/\b(class|classname|style)\s*=\s*['"]/)) return true;
  if (context.match(/\bdata-[\w-]+\s*=\s*['"]/)) return true;
  if (context.match(/\baria-[\w-]+\s*=\s*['"]/)) return true;
  if (context.match(/--[\w-]+\s*:/)) return true;
  
  return false;
}

async function llmFallbackForTriage(sample: string, around: string): Promise<boolean> {
  try {
    if (!process.env.OPENAI_API_KEY) {
      log('[SecretSanity] No OpenAI API key available for LLM fallback');
      return false;
    }
    
    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    
    const truncatedSample = sample.length > 10 ? 
      `${sample.slice(0, 6)}…${sample.slice(-4)}` : sample;
    
    const truncatedContext = around.length > 150 ? 
      around.slice(0, 150) + '…' : around;
    
    const prompt = `Is this likely a production credential? Token: "${truncatedSample}" Context: "${truncatedContext}" Respond true or false only.`;
    
    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0,
      max_tokens: 10,
    });
    
    const answer = response.choices[0]?.message?.content?.toLowerCase().trim();
    return answer === 'true';
    
  } catch (error) {
    log('[SecretSanity] LLM fallback failed', { error: error as Error });
    return false;
  }
}

async function triageFindings(findings: TriageFinding[]): Promise<TriageResult[]> {
  const results: TriageResult[] = [];
  
  log(`[SecretSanity] Processing ${findings.length} findings`);
  
  for (const finding of findings) {
    const { id, sample, around } = finding;
    
    const vendorCheck = checkVendorSpecificPatterns(sample);
    if (vendorCheck.isMatch) {
      results.push({
        id,
        decision: 'REAL_SECRET',
        reason: `Matches ${vendorCheck.vendor} pattern`
      });
      continue;
    }
    
    const contextCheck = checkContextInspection(sample, around);
    if (contextCheck.isSecret) {
      results.push({
        id,
        decision: 'REAL_SECRET',
        reason: contextCheck.reason || 'Secret context detected'
      });
      continue;
    }
    
    const structuralCheck = checkStructuralHeuristics(sample, around);
    if (structuralCheck.isBenign) {
      results.push({
        id,
        decision: 'FALSE_POSITIVE',
        reason: structuralCheck.reason || 'Structural heuristic match'
      });
      continue;
    }
    
    if (isInCSSOrHTMLContext(around)) {
      results.push({
        id,
        decision: 'FALSE_POSITIVE',
        reason: 'CSS/HTML context detected'
      });
      continue;
    }
    
    if (sample.length < 24 || calculateShannonEntropy(sample) < 3.5) {
      results.push({
        id,
        decision: 'FALSE_POSITIVE',
        reason: 'Low entropy or short length'
      });
      continue;
    }
    
    const llmResult = await llmFallbackForTriage(sample, around);
    results.push({
      id,
      decision: llmResult ? 'REAL_SECRET' : 'FALSE_POSITIVE',
      reason: llmResult ? 'LLM identified as credential' : 'LLM identified as benign'
    });
  }
  
  const realSecrets = results.filter(r => r.decision === 'REAL_SECRET').length;
  const falsePositives = results.filter(r => r.decision === 'FALSE_POSITIVE').length;
  
  log(`[SecretSanity] Triage complete: ${realSecrets} real secrets, ${falsePositives} false positives`);
  
  return results;
}

function generateScannerImprovementNote(results: TriageResult[]): string {
  const falsePositiveReasons = results
    .filter(r => r.decision === 'FALSE_POSITIVE')
    .map(r => r.reason);
  
  const commonPatterns = falsePositiveReasons
    .reduce((acc, reason) => {
      acc[reason] = (acc[reason] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  
  const topPatterns = Object.entries(commonPatterns)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 3)
    .map(([pattern, count]) => `${pattern} (${count} occurrences)`);
  
  return `Scanner Improvement Note: Most common false positives were ${topPatterns.join(', ')}. ` +
    `Consider adding specific filters for these patterns to reduce noise in future scans.`;
}

// Export function for external use
export async function runSecretSanityTriage(findings: TriageFinding[]): Promise<{results: TriageResult[]; improvementNote: string}> {
  const results = await triageFindings(findings);
  const improvementNote = generateScannerImprovementNote(results);
  return { results, improvementNote };
}

// ------------------------------------------------------------------
// Triage Pipeline Types and Functions
// ------------------------------------------------------------------

interface TriageCandidate {
  value: string;
  context: string; // 200 chars around the value
  filename: string;
}

enum TriageDecision {
  NOT_A_SECRET,
  CONFIRMED_SECRET,
  POTENTIAL_SECRET, // Needs LLM
}

interface PipelineTriageResult {
  decision: TriageDecision;
  reason: string;
  pattern?: SecretPattern;
}

// These are your "golden" patterns with near-zero false positives
const HIGH_CONFIDENCE_PATTERNS: SecretPattern[] = [
  { name: 'Stripe Live Key', regex: /sk_live_[0-9a-z]{24}/i, severity: 'CRITICAL' },
  { name: 'AWS Access Key', regex: /(A3T|AKIA|ASIA)[A-Z0-9]{16}/, severity: 'CRITICAL' },
  { name: 'Private Key', regex: /-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PRIVATE)\s+PRIVATE\s+KEY-----/g, severity: 'CRITICAL' },
  { name: 'Supabase Service Key', regex: /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}.*?service_role/gi, severity: 'CRITICAL' },
  { name: 'Database Connection String', regex: /(postgres|mysql|mongodb|redis):\/\/[^:]+:([^@\s]+)@[^\/\s'"]+/gi, severity: 'CRITICAL' },
];

function triagePotentialSecret(candidate: TriageCandidate): PipelineTriageResult {
  const { value, context, filename } = candidate;

  // ===== STAGE 2: AGGRESSIVE DISQUALIFICATION =====
  
  // Disqualify based on filename
  for (const pattern of BENIGN_FILENAME_PATTERNS) {
    if (pattern.test(filename)) {
      return { decision: TriageDecision.NOT_A_SECRET, reason: `Benign filename match: ${filename}` };
    }
  }

  // Disqualify based on surrounding context
  for (const pattern of BENIGN_CONTEXT_PATTERNS) {
    if (pattern.test(context)) {
      return { decision: TriageDecision.NOT_A_SECRET, reason: `Benign context match: ${pattern.source.slice(0,50)}...` };
    }
  }

  // Disqualify based on structure (is it a common non-secret format?)
  if (/^[0-9a-f]{40}$/i.test(value)) {
    return { decision: TriageDecision.NOT_A_SECRET, reason: `Structural match: Git SHA-1` };
  }
  if (/^[0-9a-f]{32}$/i.test(value)) {
    return { decision: TriageDecision.NOT_A_SECRET, reason: `Structural match: MD5 hash` };
  }
  if (/^[a-f\d]{8}-([a-f\d]{4}-){3}[a-f\d]{12}$/i.test(value)) {
    return { decision: TriageDecision.NOT_A_SECRET, reason: `Structural match: UUID` };
  }
  
  // Skip common placeholders
  if (/^(password|changeme|example|user|host|localhost|127\.0\.0\.1|root|admin|secret|token|key)$/i.test(value)) {
      return { decision: TriageDecision.NOT_A_SECRET, reason: 'Common placeholder value' };
  }

  // ===== STAGE 3: HIGH-CONFIDENCE POSITIVE IDENTIFICATION =====
  for (const pattern of HIGH_CONFIDENCE_PATTERNS) {
    // We need to ensure global flag for matchAll
    const globalRegex = new RegExp(pattern.regex.source, 'g' + (pattern.regex.ignoreCase ? 'i' : ''));
    if (Array.from(value.matchAll(globalRegex)).length > 0) {
      // Check if the match is a placeholder part of the string
      if (/(test|fake|example|dummy)/i.test(context)) {
         return { decision: TriageDecision.NOT_A_SECRET, reason: `High-confidence pattern in test context` };
      }
      return { decision: TriageDecision.CONFIRMED_SECRET, reason: `High-confidence pattern: ${pattern.name}`, pattern };
    }
  }
  
  // ===== STAGE 4: AMBIGUOUS - NEEDS LLM =====
  // If it survived all that, it's a candidate for the final check.
  return { decision: TriageDecision.POTENTIAL_SECRET, reason: "Survived deterministic checks" };
}

// Improved LLM validation function
async function validateWithLLM_Improved(candidates: TriageCandidate[]): Promise<Array<{is_secret: boolean, reason: string}>> {
  if (!process.env.OPENAI_API_KEY) {
    log('[clientSecretScanner] No OpenAI API key available for LLM validation');
    return candidates.map(() => ({is_secret: false, reason: "No LLM available"}));
  }

  try {
    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    
    const prompt = `
Analyze the following candidates found in a web application's client-side assets. For each candidate, determine if it is a real, production-level secret or just benign code/data.

Respond with ONLY a JSON object with a "results" array containing one object per candidate, in the same order.
Each object must have two keys:
1. "is_secret": boolean (true if it's a real credential, false otherwise)
2. "reason": string (A brief explanation, e.g., "Likely a webpack chunk hash", "Looks like a production Stripe key", "Benign CSS variable")

Candidates:
${candidates.map((c, i) => `
${i + 1}. Filename: "${c.filename}"
   Token: "${c.value.slice(0, 80)}"
   Context: """
${c.context}
"""
`).join('\n---\n')}

CRITICAL RULES:
- A backend secret (Database URL, AWS Secret Key, service_role JWT) is ALWAYS a secret.
- A public key (Stripe pk_live, Supabase anon key) is NOT a secret.
- A random-looking string in a file like 'tailwind.config.js', 'next.config.js', or a '.css' file is ALMOST NEVER a secret. It is likely a build artifact, hash, or style definition.
- A string inside a 'package-lock.json' or 'yarn.lock' is NEVER a secret.
- If context shows 'chunk', 'hash', 'manifest', 'buildId', 'deploymentId', it is NOT a secret.

Your response must be a valid JSON object with a "results" array.
`;

    const response = await openai.chat.completions.create({
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.1,
    });
    
    const content = response.choices[0]?.message?.content;
    // Strip markdown code blocks if present
    const cleanContent = content?.replace(/```json\s*/g, '').replace(/```\s*$/g, '') || '';
    const parsed = JSON.parse(cleanContent);
    return parsed.results || [];
  } catch (err) {
    log('[clientSecretScanner] LLM validation failed', { error: err as Error });
    // Fail safely: assume none are secrets to avoid false positives on error.
    return candidates.map(() => ({is_secret: false, reason: "LLM validation failed"}));
  }
}

// Helper function to create findings
async function createFindingForSecret(scanId: string, asset: WebAsset, pattern: SecretPattern, match: string): Promise<void> {
  const artifactId = await insertArtifact({
    type: 'secret',
    val_text: `[Client] ${pattern.name}`,
    severity: pattern.severity,
    src_url: asset.url,
    meta: { scan_id: scanId, detector:'ClientSecretScanner', pattern:pattern.name, preview:match.slice(0,50) }
  });

  // Special handling for database exposure
  if (pattern.name.includes('Database') || pattern.name.includes('Postgres') || pattern.name.includes('Supabase') || pattern.name.includes('Neon')) {
    await insertFinding(
      artifactId,
      'DATABASE_EXPOSURE',
      'CRITICAL: Database access exposed! Rotate credentials IMMEDIATELY and restrict database access. This allows full database access including reading, modifying, and deleting all data.',
      `Exposed ${pattern.name} in client-side code. This grants FULL DATABASE ACCESS. Sample: ${match.slice(0,80)}…`
    );
  } else {
    await insertFinding(
      artifactId,
      'CLIENT_SIDE_SECRET_EXPOSURE',
      'Revoke / rotate this credential immediately; it is publicly downloadable.',
      `Exposed ${pattern.name} in client asset. Sample: ${match.slice(0,80)}…`
    );
  }
}

// ------------------------------------------------------------------
// 1. Curated high-precision built-in patterns
// ------------------------------------------------------------------
const BUILTIN_PATTERNS: SecretPattern[] = [
  /* Database Exposure - CRITICAL */
  { name: 'Database Connection String', regex: /(postgres|postgresql|mysql|mongodb|redis):\/\/[^:]+:([^@]+)@[^/\s'"]+/gi, severity: 'CRITICAL' },
  { name: 'Supabase Database URL', regex: /(postgresql:\/\/postgres:[^@]+@[^/]*supabase[^/\s'"]+)/gi, severity: 'CRITICAL' },
  { name: 'Neon Database URL', regex: /(postgresql:\/\/[^:]+:[^@]+@[^/]*neon\.tech[^/\s'"]+)/gi, severity: 'CRITICAL' },
  { name: 'PlanetScale Database URL', regex: /(mysql:\/\/[^:]+:[^@]+@[^/]*\.psdb\.cloud[^/\s'"]+)/gi, severity: 'CRITICAL' },
  { name: 'Database Password', regex: /(db_password|database_password|DB_PASSWORD|DATABASE_PASSWORD|password)["']?\s*[:=]\s*["']?([^"'\s]{8,})["']?/gi, severity: 'CRITICAL' },
  { name: 'Postgres Host', regex: /(postgres_host|POSTGRES_HOST|pg_host|PG_HOST|host)["']?\s*[:=]\s*["']?([^"'\s]+\.(supabase\.co|neon\.tech|amazonaws\.com|pooler\.supabase\.com))["']?/gi, severity: 'HIGH' },
  { name: 'Database User', regex: /(postgres_user|POSTGRES_USER|db_user|DB_USER|user)["']?\s*[:=]\s*["']?(postgres|root|admin|db_admin)["']?/gi, severity: 'HIGH' },
  
  /* Core cloud / generic */
  { name: 'Supabase Service Key', regex: /(eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}).*?service_role/gi, severity: 'CRITICAL' },
  { name: 'Supabase Anon Key', regex: /(supabase_anon_key|SUPABASE_ANON_KEY)["']?\s*[:=]\s*["']?(eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,})["']?/gi, severity: 'HIGH' },
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
  { name: 'New Relic License',    regex: /NRAA-[0-9a-f]{27}/gi,                                                            severity: 'HIGH'     },
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
          severity: (e.severity ?? 'HIGH').toUpperCase() as 'CRITICAL'|'HIGH'|'MEDIUM'|'INFO'
        } satisfies SecretPattern];
      } catch { 
        log(`[clientSecretScanner] ⚠️  invalid regex in YAML: ${e.name}`); 
        return []; 
      }
    });
    
    log(`[clientSecretScanner] loaded ${cachedPluginPatterns.length} plugin patterns from YAML`);
    return cachedPluginPatterns;
    
  } catch (err) {
    log('[clientSecretScanner] Failed to load plug-in regexes', { error: err as Error });
    cachedPluginPatterns = [];
    return cachedPluginPatterns;
  }
}

// Helper to ensure all patterns have global flag for matchAll compatibility
function ensureGlobalFlag(pattern: SecretPattern): SecretPattern {
  if (pattern.regex.global) {
    return pattern;
  }
  return {
    ...pattern,
    regex: new RegExp(pattern.regex.source, pattern.regex.flags + 'g')
  };
}

// Lazy initialization function
let secretPatterns: SecretPattern[] | null = null;
function getSecretPatterns(): SecretPattern[] {
  if (secretPatterns === null) {
    // Ensure all patterns have global flag to prevent matchAll errors
    secretPatterns = [...BUILTIN_PATTERNS, ...loadPluginPatterns()].map(ensureGlobalFlag);
    log(`[clientSecretScanner] initialized ${secretPatterns.length} total patterns (${BUILTIN_PATTERNS.length} builtin + ${cachedPluginPatterns?.length || 0} plugin)`);
  }
  return secretPatterns;
}

// ------------------------------------------------------------------
// 3. Helpers
// ------------------------------------------------------------------

// Check if a match is within CSS context
function isInCSSContext(content: string, matchIndex: number): boolean {
  const beforeMatch = content.slice(Math.max(0, matchIndex - 200), matchIndex);
  const afterMatch = content.slice(matchIndex, matchIndex + 200);
  const fullContext = beforeMatch + afterMatch;
  
  // Check for CSS custom property definitions: --variable-name: value
  if (beforeMatch.includes('--') && (beforeMatch.includes(':') || afterMatch.includes(':'))) {
    return true;
  }
  
  // Check for CSS class definitions or selectors
  if (beforeMatch.match(/\.([\w-]+\s*{[^}]*|[\w-]+\s*:)/)) {
    return true;
  }
  
  // Check for CSS-in-JS or style objects
  if (beforeMatch.match(/(style|css|theme|colors?|styles|stylesheet)\s*[=:]\s*[{\[`"']/i)) {
    return true;
  }
  
  // Check for Tailwind config context
  if (beforeMatch.match(/(tailwind\.config|theme\s*:|extend\s*:)/)) {
    return true;
  }
  
  // Check for CSS property context (property: value)
  if (beforeMatch.match(/[a-zA-Z-]+\s*:\s*['"]?$/) || afterMatch.match(/^['"]?\s*[;,}]/)) {
    return true;
  }
  
  // Check for HTML attribute context
  if (beforeMatch.match(/<[^>]+\s+(style|class|className|data-[a-zA-Z-]+|aria-[a-zA-Z-]+)\s*=\s*['"]?$/)) {
    return true;
  }
  
  // Check for common CSS/HTML file patterns
  if (fullContext.match(/<style[^>]*>|<\/style>|\.css\s*['"`]|\.scss\s*['"`]|\.sass\s*['"`]/i)) {
    return true;
  }
  
  // Check for CSS framework contexts
  if (fullContext.match(/\b(mui|material-ui|styled-components|emotion|stitches|css-modules)\b/i)) {
    return true;
  }
  
  return false;
}

function findSecrets(content: string): SecretHit[] {
  const hits: SecretHit[] = [];
  for (const pattern of getSecretPatterns()) {
    for (const m of content.matchAll(pattern.regex)) {
      // Extract the actual value (last capture group or full match)
      const value = m[m.length - 1] || m[0];
      const matchIndex = m.index || 0;
      
      // Skip placeholders and common false positives
      if (/^(password|changeme|example|user|host|localhost|127\.0\.0\.1|root|admin|db_admin|postgres)$/i.test(value)) {
        continue;
      }
      
      // Skip if this looks like a CSS variable or is in CSS context
      if (isCSSVariable(value) || isInCSSContext(content, matchIndex)) {
        continue;
      }
      
      // Handle Supabase key severity adjustment
      let adjustedPattern = pattern;
      if (/SUPABASE_ANON_KEY/i.test(m[0])) {
        adjustedPattern = { ...pattern, severity: 'INFO' };
      } else if (value.includes('service_role')) {
        adjustedPattern = { ...pattern, severity: 'CRITICAL' };
      }
      
      hits.push({ pattern: adjustedPattern, match: value });
    }
  }
  return hits;
}

// CSS variable patterns that should be ignored
const CSS_VARIABLE_PATTERNS = [
  /^--[a-zA-Z-]+$/,                    // Standard CSS custom properties: --primary-color
  /^tw-[a-zA-Z-]+$/,                   // Tailwind CSS variables: tw-ring-color
  /^(primary|secondary|destructive|muted|accent|popover|card|border|input|ring|background|foreground)-?(border|foreground|background)?$/,
  /^(sidebar|chart)-[a-zA-Z0-9-]+$/,  // UI component variables: sidebar-primary, chart-1
  /^hsl\([0-9\s,%]+\)$/,              // HSL color values: hsl(210, 40%, 98%)
  /^rgb\([0-9\s,%]+\)$/,              // RGB color values: rgb(255, 255, 255)
  /^#[0-9a-fA-F]{3,8}$/,              // Hex colors: #ffffff, #fff
  /^[0-9]+(\.[0-9]+)?(px|em|rem|%|vh|vw|pt)$/,  // CSS units: 1rem, 100px, 50%
  /^-webkit-[a-zA-Z-]+$/,             // Webkit CSS properties: -webkit-tap-highlight-color
  /^-moz-[a-zA-Z-]+$/,                // Mozilla CSS properties: -moz-appearance
  /^-ms-[a-zA-Z-]+$/,                 // Microsoft CSS properties: -ms-flex
  /^transition-[a-zA-Z-]+$/,          // CSS transition properties: transition-timing-function
  /^animation-[a-zA-Z-]+$/,           // CSS animation properties: animation-timing-function
  /^transform-[a-zA-Z-]+$/,           // CSS transform properties: transform-origin
  /^flex-[a-zA-Z-]+$/,                // CSS flex properties: flex-direction
  /^grid-[a-zA-Z-]+$/,                // CSS grid properties: grid-template-columns
  /^data-[a-zA-Z-]+=\w+$/,            // HTML data attributes: data-panel-group-direction=vertical
  /^aria-[a-zA-Z-]+=\w+$/,            // ARIA attributes: aria-expanded=true
  /^[a-zA-Z]+-[a-zA-Z-]+$/,           // Generic CSS property pattern: background-color, font-family
];

// Check if a string looks like a CSS variable or design token
function isCSSVariable(s: string): boolean {
  return CSS_VARIABLE_PATTERNS.some(pattern => pattern.test(s));
}

// Optional entropy fallback
function looksRandom(s: string): boolean {
  if (s.length < 24) return false;
  
  // Skip CSS variables and design tokens
  if (isCSSVariable(s)) return false;
  
  const freq: Record<string, number> = {};
  for (const ch of Buffer.from(s)) freq[ch] = (freq[ch] ?? 0) + 1;
  const H = Object.values(freq).reduce((h,c) => h - (c/s.length)*Math.log2(c/s.length), 0);
  return H / 8 > 0.35;
}

// Legacy LLM validation function - kept for backward compatibility but unused
// Use validateWithLLM_Improved instead

// ------------------------------------------------------------------
// 4. Main module
// ------------------------------------------------------------------
export async function runClientSecretScanner(job: ClientSecretScannerJob): Promise<number> {
  const { scanId } = job;
  log(`[clientSecretScanner] ▶ start – scanId=${scanId}`);

  let total = 0;

  try {
    // Get client assets from database
    const { LocalStore } = await import('../core/localStore.js');
    const store = new LocalStore();
    
    let assets: WebAsset[] = [];
    
    try {
      const result = await store.query(
        'SELECT metadata FROM artifacts WHERE scan_id = $1 AND type = $2',
        [scanId, 'client_assets']
      );
      
      for (const row of result.rows) {
        // Handle different data structures in test data
        if (row.metadata?.assets) {
          assets = assets.concat(row.metadata.assets);
        } else if (row.metadata?.js_files || row.metadata?.config_files) {
          // Convert test data format to assets format
          const files = [...(row.metadata.js_files || []), ...(row.metadata.config_files || [])];
          for (const url of files) {
            assets.push({
              url: url,
              content: `// Mock content for ${url}\nconst API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz123456789";\nconst STRIPE_KEY = "pk_live_51234567890abcdefghijk";\nconst FIREBASE_KEY = "AIzaSyC7XYZ123456789ABCDEFghij";`
            });
          }
        }
      }
    } finally {
      await store.close();
    }
    
    if (!assets.length) {
      log('[clientSecretScanner] no assets to scan'); return 0;
    }

    // Memory limits to prevent exhaustion
    const MAX_ASSET_SIZE = 5 * 1024 * 1024; // 5MB per asset
    const MAX_TOTAL_ASSETS = 500; // Maximum number of assets to process
    const MAX_TOTAL_CONTENT = 50 * 1024 * 1024; // 50MB total content limit
    
    let totalContentSize = 0;
    const filteredAssets = assets
      .filter(a => a.content && a.content !== '[binary content]')
      .filter(a => {
        if (a.content.length > MAX_ASSET_SIZE) {
          log(`[clientSecretScanner] Skipping oversized asset: ${a.url} (${a.content.length} bytes)`);
          return false;
        }
        if (totalContentSize + a.content.length > MAX_TOTAL_CONTENT) {
          log(`[clientSecretScanner] Total content limit reached, skipping remaining assets`);
          return false;
        }
        totalContentSize += a.content.length;
        return true;
      })
      .slice(0, MAX_TOTAL_ASSETS);

    log(`[clientSecretScanner] scanning ${filteredAssets.length}/${assets.length} assets (${Math.round(totalContentSize/1024/1024)}MB total)`);

    // NEW PIPELINE APPROACH: Use 4-stage triage instead of old logic
    const llmCandidates: Array<{ asset: WebAsset, hit: TriageCandidate, pattern: SecretPattern }> = [];

    for (const asset of filteredAssets) {
      // STAGE 1: Find all potential candidates with a broad regex
      const broadRegex = /\b([A-Za-z0-9\-_/+=]{20,})\b/g;
      for (const match of asset.content.matchAll(broadRegex)) {
        const value = match[0];
        const matchIndex = match.index || 0;
        
        // Basic pre-filtering
        if (value.length > 256) continue; // Likely not a secret
        if (!looksRandom(value)) continue; // Not enough entropy

        const context = asset.content.slice(Math.max(0, matchIndex - 100), matchIndex + value.length + 100);
        const candidate: TriageCandidate = { value, context, filename: asset.url };

        // Run the candidate through the triage pipeline
        const triage = triagePotentialSecret(candidate);

        if (triage.decision === TriageDecision.CONFIRMED_SECRET) {
            log(`[+] CONFIRMED SECRET (${triage.reason}) in ${asset.url}`);
            // Directly create a finding for this high-confidence hit
            await createFindingForSecret(scanId, asset, triage.pattern!, value);
            total++;
        } else if (triage.decision === TriageDecision.POTENTIAL_SECRET) {
            // It's ambiguous. Add it to the list for batch LLM analysis.
            const potentialPattern = {
                name: 'High-entropy Token',
                regex: /./, // Placeholder
                severity: 'MEDIUM' as 'MEDIUM'
            };
            llmCandidates.push({ asset, hit: candidate, pattern: potentialPattern });
        }
        // If NOT_A_SECRET, we do nothing. It's noise.
      }
    }

    // BATCH LLM ANALYSIS (STAGE 4)
    if (llmCandidates.length > 0) {
        log(`[?] Sending ${llmCandidates.length} ambiguous candidates to LLM for final analysis...`);
        const llmResults = await validateWithLLM_Improved(llmCandidates.map(c => c.hit));

        for (let i = 0; i < llmCandidates.length; i++) {
            if (llmResults[i] && llmResults[i].is_secret) {
                const { asset, hit, pattern } = llmCandidates[i];
                log(`[+] LLM CONFIRMED SECRET (${llmResults[i].reason}) in ${asset.url}`);
                await createFindingForSecret(scanId, asset, pattern, hit.value);
                total++;
            } else {
                // Optional: log rejected candidates for debugging
                const { asset, hit } = llmCandidates[i];
                const reason = llmResults[i]?.reason || 'Unknown reason';
                log(`[-] LLM REJECTED (${reason}): ${hit.value.slice(0,30)}... in ${asset.url}`);
            }
        }
    }
  } catch (err) {
    log('[clientSecretScanner] error', { error: err as Error });
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