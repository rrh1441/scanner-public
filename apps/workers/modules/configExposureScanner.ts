/* =============================================================================
 * MODULE: configExposureScanner.ts
 * =============================================================================
 * Direct configuration file and secret exposure scanner.
 * Probes for common exposed configuration files and analyzes their contents.
 * =============================================================================
 */

import { httpClient } from '../net/httpClient.js';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as log } from '../core/logger.js';

// Common configuration file paths to probe
const CONFIG_PATHS = [
  // Environment files
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.env.development',
  '/.env.staging',
  
  // Configuration files
  '/config.json',
  '/config.js',
  '/app.config.json',
  '/settings.json',
  '/appsettings.json',
  '/configuration.json',
  
  // Database files
  '/database.json',
  '/db.json',
  '/backup.sql',
  '/dump.sql',
  '/data.sql',
  
  // Framework configs
  '/wp-config.php',
  '/configuration.php',
  '/settings.php',
  '/config.php',
  '/parameters.yml',
  
  // Build/Deploy files
  '/.env.example',
  '/docker-compose.yml',
  '/.dockerenv',
  '/Dockerfile',
  
  // Cloud configs
  '/.aws/credentials',
  '/.aws/config',
  '/firebase.json',
  '/.firebaserc',
  
  // Package files
  '/package.json',
  '/composer.json',
  '/requirements.txt',
  
  // Documentation
  '/swagger.json',
  '/openapi.json',
  '/api-docs.json',
  
  // Logs and debug
  '/debug.log',
  '/error.log',
  '/access.log',
  '/logs/error.log',
  '/logs/debug.log',
  
  // Admin/User files
  '/admin/users.txt',
  '/users.txt',
  '/passwords.txt',
  '/credentials.txt',
  
  // Backup files
  '/.env.backup',
  '/config.json.backup',
  '/database.backup',
  
  // Git files
  '/.git/config',
  '/.gitconfig'
];

// Entropy calculation for secret validation
function calculateSecretEntropy(str: string): number {
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

// Secret patterns to look for in files
const SECRET_PATTERNS = [
  // API Keys
  { name: 'Generic API Key', regex: /(api[_-]?key|apikey|api_secret)["']?\s*[:=]\s*["']?([A-Za-z0-9\-_.]{20,})["']?/gi, severity: 'HIGH' },
  { name: 'AWS Access Key', regex: /(aws_access_key_id|aws_secret_access_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{20,})["']?/gi, severity: 'CRITICAL' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z-_]{35}/g, severity: 'HIGH' },
  
  // Database
  { name: 'Database Password', regex: /(db_password|database_password|password|pwd)["']?\s*[:=]\s*["']?([^"'\s]{8,})["']?/gi, severity: 'CRITICAL' },
  { name: 'Database URL', regex: /(postgres|mysql|mongodb|redis):\/\/[^:]+:([^@]+)@[^/]+/gi, severity: 'CRITICAL' },
  
  // Tokens
  { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}/g, severity: 'HIGH' },
  { name: 'Bearer Token', regex: /bearer\s+[A-Za-z0-9\-_.]{20,}/gi, severity: 'HIGH' },
  
  // Service-specific
  { name: 'Supabase Key', regex: /(supabase_url|supabase_anon_key|supabase_service_key)["']?\s*[:=]\s*["']?([^"'\s]+)["']?/gi, severity: 'CRITICAL' },
  { name: 'Stripe Key', regex: /(sk_live_|pk_live_)[0-9a-zA-Z]{24,}/g, severity: 'CRITICAL' },
  { name: 'Slack Token', regex: /xox[baprs]-[0-9a-zA-Z]{10,}/g, severity: 'HIGH' },
  
  // Secrets
  { name: 'Private Key', regex: /-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PRIVATE)\s+PRIVATE\s+KEY-----/g, severity: 'CRITICAL' },
  { name: 'Generic Secret', regex: /(secret|client_secret|app_secret)["']?\s*[:=]\s*["']?([A-Za-z0-9\-_.]{16,})["']?/gi, severity: 'HIGH' }
];

interface ConfigFile {
  path: string;
  status: number;
  content: string;
  size: number;
  secrets: Array<{
    type: string;
    value: string;
    severity: string;
  }>;
}

async function probeConfigFile(baseUrl: string, path: string): Promise<ConfigFile | null> {
  const probeStart = Date.now();
  try {
    // Validate path to prevent traversal attacks
    if (!path.startsWith('/') || path.includes('../') || path.includes('..\\') || path.includes('%2e%2e')) {
      throw new Error(`Invalid path: ${path}`);
    }
    
    // Normalize path
    const normalizedPath = path.replace(/\/+/g, '/');
    const url = `${baseUrl}${normalizedPath}`;
    
    const response = await httpClient.get(url, {
      timeout: 10000,
      maxContentLength: 5 * 1024 * 1024, // 5MB max
      validateStatus: () => true
    });

    if (response.status === 200 && response.data) {
      const content = typeof response.data === 'string' 
        ? response.data 
        : JSON.stringify(response.data, null, 2);
      
      // Find secrets in content
      const secrets: ConfigFile['secrets'] = [];
      
      for (const pattern of SECRET_PATTERNS) {
        const matches = content.matchAll(pattern.regex);
        for (const match of matches) {
          // Extract the actual value (last capture group or full match)
          const value = match[match.length - 1] || match[0];
          
          // Skip placeholders and common false positives
          if (/^(password|changeme|example|user|host|localhost|127\.0\.0\.1|root|admin|db_admin|postgres|secret|key|apikey|test|demo|your_key_here|your_secret_here|\[REDACTED\])$/i.test(value)) {
            continue;
          }
          
          // Skip if value is too short or lacks entropy for secrets
          if (value.length < 8 || calculateSecretEntropy(value) < 2.5) {
            continue;
          }
          
          // Handle Supabase key severity adjustment
          let adjustedSeverity = pattern.severity;
          if (pattern.name.includes('Supabase') && /SUPABASE_ANON_KEY/i.test(match[0])) {
            adjustedSeverity = 'INFO';
          } else if (value.includes('service_role')) {
            adjustedSeverity = 'CRITICAL';
          }
          
          // Truncate value for security
          const truncatedValue = value.length > 20 
            ? value.substring(0, 10) + '...' + value.substring(value.length - 5)
            : value;
          
          secrets.push({
            type: pattern.name,
            value: truncatedValue,
            severity: adjustedSeverity
          });
        }
      }

      console.log(`[configExposureScanner] Found exposed file at ${path} (${content.length} bytes, ${secrets.length} secrets) in ${Date.now() - probeStart}ms`);
      return {
        path,
        status: response.status,
        content: content.substring(0, 5000), // Limit content size
        size: content.length,
        secrets
      };
    }
  } catch (error) {
    // Most paths will 404 - only log actual errors
    if (error && (error as any).code !== 'ENOTFOUND' && (error as any).response?.status !== 404) {
      console.log(`[configExposureScanner] Error checking ${path}: ${(error as Error).message}`);
    }
  }
  
  return null;
}

export async function runConfigExposureScanner(job: {
  domain: string;
  scanId?: string;
}): Promise<number> {
  console.log(`[configExposureScanner] START at ${new Date().toISOString()}`);
  const start = Date.now();
  const { domain, scanId } = job;
  const baseUrl = `https://${domain}`;
  
  log(`[configExposureScanner] Starting scan for ${domain}`);
  console.log(`[configExposureScanner] Checking ${CONFIG_PATHS.length} config paths...`);
  
  const exposedFiles: ConfigFile[] = [];
  let totalSecrets = 0;
  
  // Add module-level timeout protection
  const MODULE_TIMEOUT_MS = 60 * 1000; // 1 minute timeout for this module
  const moduleTimeoutPromise = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('configExposureScanner timeout - exceeded 1 minute')), MODULE_TIMEOUT_MS)
  );

  try {
    // Wrap the scanning logic with timeout protection
    await Promise.race([
      (async () => {
        // Probe all config paths - but in parallel chunks to avoid hanging on one request
        const CHUNK_SIZE = 10;
        for (let i = 0; i < CONFIG_PATHS.length; i += CHUNK_SIZE) {
          const chunk = CONFIG_PATHS.slice(i, i + CHUNK_SIZE);
          console.log(`[configExposureScanner] Processing chunk ${Math.floor(i/CHUNK_SIZE) + 1}/${Math.ceil(CONFIG_PATHS.length/CHUNK_SIZE)} (${chunk.length} paths)`);
          
          // Process chunk in parallel with individual timeouts
          const chunkResults = await Promise.allSettled(
            chunk.map(async (path) => {
              console.log(`[configExposureScanner] Checking path: ${path}`);
              const result = await probeConfigFile(baseUrl, path);
              if (result) {
                console.log(`[configExposureScanner] Path ${path} returned status ${result.status}`);
                log(`[configExposureScanner] Found exposed file: ${path} (${result.secrets.length} secrets)`);
              }
              return { path, result };
            })
          );
          
          // Collect successful results
          chunkResults.forEach((settled) => {
            if (settled.status === 'fulfilled' && settled.value.result) {
              exposedFiles.push(settled.value.result);
              totalSecrets += settled.value.result.secrets.length;
            } else if (settled.status === 'rejected') {
              console.log(`[configExposureScanner] Path check failed:`, settled.reason?.message);
            }
          });
        }
      })(),
      moduleTimeoutPromise
    ]);
    
    console.log(`[configExposureScanner] Scanning completed - found ${exposedFiles.length} files`);
  } catch (error) {
    console.log(`[configExposureScanner] Module timed out or failed:`, error instanceof Error ? error.message : String(error));
    log(`[configExposureScanner] Scan failed or timed out: ${error instanceof Error ? error.message : String(error)}`);
    // Continue to store whatever results we have
  }
  
  // Store findings
  for (const file of exposedFiles) {
    const severity = file.secrets.some(s => s.severity === 'CRITICAL') 
      ? 'CRITICAL' 
      : file.secrets.some(s => s.severity === 'HIGH')
      ? 'HIGH'
      : 'MEDIUM';
    
    const artifactId = await insertArtifact({
      type: 'exposed_config',
      val_text: `Exposed configuration file: ${file.path}`,
      severity,
      src_url: `${baseUrl}${file.path}`,
      meta: {
        scan_id: scanId,
        scan_module: 'configExposureScanner',
        path: file.path,
        size: file.size,
        secret_count: file.secrets.length,
        secret_types: [...new Set(file.secrets.map(s => s.type))],
        content_preview: file.content.substring(0, 500)
      }
    });
    
    // Create finding for each unique secret type
    const secretTypes = new Map<string, { count: number; severity: string }>();
    for (const secret of file.secrets) {
      const existing = secretTypes.get(secret.type) || { count: 0, severity: secret.severity };
      existing.count++;
      secretTypes.set(secret.type, existing);
    }
    
    for (const [type, info] of secretTypes) {
      await insertFinding(
        artifactId,
        'EXPOSED_SECRETS',
        `Remove ${file.path} from public access immediately. Move sensitive configuration to environment variables.`,
        `Found ${info.count} ${type}(s) in ${file.path}`
      );
    }
  }
  
  // Summary artifact
  await insertArtifact({
    type: 'scan_summary',
    val_text: `Config exposure scan completed: ${exposedFiles.length} files with ${totalSecrets} secrets`,
    severity: totalSecrets > 0 ? 'HIGH' : 'INFO',
    meta: {
      scan_id: scanId,
      scan_module: 'configExposureScanner',
      files_found: exposedFiles.length,
      total_secrets: totalSecrets,
      file_paths: exposedFiles.map(f => f.path)
    }
  });
  
  console.log(`[configExposureScanner] COMPLETE: Found ${exposedFiles.length} exposures in ${Date.now() - start}ms`);
  log(`[configExposureScanner] Completed: ${exposedFiles.length} exposed files, ${totalSecrets} secrets`);
  return totalSecrets;
}