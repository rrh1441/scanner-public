/* =============================================================================
 * MODULE: tlsScan.ts (Rewritten with sslscan v8, 2025-06-22)
 * =============================================================================
 * Performs TLS/SSL configuration assessment using **sslscan** instead of testssl.sh.
 * sslscan is much more reliable, faster, and easier to integrate.
 * =============================================================================
 */

import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { httpClient } from '../net/httpClient.js';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as log } from '../core/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);


const exec = promisify(execFile);

/**
 * Run sslscan via spawn with streamed IO to avoid maxBuffer dead-locks in execFile.
 * Returns collected stdout/stderr once the process exits or rejects on error/timeout.
 */
function runSslscan(host: string): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    console.log(`[tlsScan] Starting sslscan process for ${host}...`);
    const args = ['--xml=-', '--no-colour', '--timeout=20', host]; // Conservative timeout for reliability
    const proc = spawn('sslscan', args, { 
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        GODEBUG: 'netdns=go+v4', // Force IPv4 for Go binaries (though sslscan is C++)
        RES_OPTIONS: 'inet6off'  // Force IPv4 DNS resolution to prevent hangs
      }
    });

    let stdout = '';
    let stderr = '';
    let bytesReceived = 0;

    proc.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
      bytesReceived += chunk.length;
      console.log(`[tlsScan] Received ${bytesReceived} bytes from sslscan`);
    });
    proc.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    proc.on('error', (err) => reject(err));

    proc.on('close', (code) => {
      if (code === 0 || stdout) {
        resolve({ stdout, stderr });
      } else {
        reject(new Error(`sslscan exited with code ${code}`));
      }
    });

    // Failsafe: kill if over module timeout
    const killer = setTimeout(() => {
      console.log(`[tlsScan] WARNING: sslscan timeout after ${TLS_SCAN_TIMEOUT_MS / 1000}s, killing process`);
      proc.kill('SIGKILL');
      reject(new Error('sslscan timeout'));
    }, TLS_SCAN_TIMEOUT_MS);

    proc.on('exit', (code) => {
      clearTimeout(killer);
      console.log(`[tlsScan] sslscan completed with code ${code}`);
    });
  });
}

/* ---------- Types --------------------------------------------------------- */

type Severity = 'OK' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INFO';

interface SSLScanResult {
  host: string;
  port: number;
  certificate?: {
    subject: string;
    issuer: string;
    notBefore: string;
    notAfter: string;
    expired: boolean;
    selfSigned: boolean;
  };
  protocols: Array<{
    name: string;
    version: string;
    enabled: boolean;
  }>;
  ciphers: Array<{
    cipher: string;
    protocols: string[];
    keyExchange: string;
    authentication: string;
    encryption: string;
    bits: number;
    status: string;
  }>;
  vulnerabilities: string[];
}

interface ScanOutcome {
  findings: number;
  hadCert: boolean;
}

interface PythonValidationResult {
  host: string;
  port: number;
  valid: boolean;
  error?: string;
  certificate?: {
    subject_cn: string;
    issuer_cn: string;
    not_after: string;
    days_until_expiry: number | null;
    is_expired: boolean;
    self_signed: boolean;
    subject_alt_names: Array<{type: string; value: string}>;
  };
  tls_version?: string;
  cipher_suite?: any;
  sni_supported: boolean;
  validation_method: string;
}

/* ---------- Config -------------------------------------------------------- */

const TLS_SCAN_TIMEOUT_MS = Number.parseInt(process.env.TLS_SCAN_TIMEOUT_MS ?? '60000', 10); // 1 min - reduced for faster scans
const TLS_DERIVATION_PREFIXES = ['www']; // extend with 'app', 'login', etc. if needed

/* ---------- Helpers ------------------------------------------------------- */

/** Validate sslscan is available */
async function validateSSLScan(): Promise<boolean> {
  try {
    const result = await exec('sslscan', ['--version'], { maxBuffer: 10 * 1024 * 1024 }); // 10MB buffer
    log(`[tlsScan] sslscan found: ${result.stdout?.trim() || 'version check ok'}`);
    return true;
  } catch (error) {
    log(`[tlsScan] [CRITICAL] sslscan binary not found: ${(error as Error).message}`);
    return false;
  }
}

/** Run Python certificate validator with SNI support */
async function runPythonCertificateValidator(host: string, port: number = 443): Promise<PythonValidationResult | null> {
  try {
    const pythonScript = join(__dirname, '../../scripts/tls_verify.py');
    const result = await exec('python3', [pythonScript, host, '--port', port.toString(), '--json'], {
      timeout: 30000, // 30 second timeout
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer to prevent hanging
      killSignal: 'SIGKILL' // Actually kill the process if it hangs
    });
    
    const validationResult = JSON.parse(result.stdout || '{}') as PythonValidationResult;
    log(`[tlsScan] Python validator: ${host} - ${validationResult.valid ? 'VALID' : 'INVALID'}`);
    return validationResult;
    
  } catch (error) {
    log(`[tlsScan] Python validator failed for ${host}: ${(error as Error).message}`);
    return null;
  }
}

/** Parse sslscan XML output */
function parseSSLScanOutput(xmlOutput: string, host: string): SSLScanResult | null {
  try {
    // For now, do basic text parsing. Could use xml2js later if needed.
    const result: SSLScanResult = {
      host,
      port: 443,
      protocols: [],
      ciphers: [],
      vulnerabilities: []
    };

    const lines = xmlOutput.split('\n');
    
    // Extract certificate info
    let certMatch = xmlOutput.match(/Subject:\s+(.+)/);
    if (certMatch) {
      const issuerMatch = xmlOutput.match(/Issuer:\s+(.+)/);
      const notBeforeMatch = xmlOutput.match(/Not valid before:\s+(.+)/);
      const notAfterMatch = xmlOutput.match(/Not valid after:\s+(.+)/);
      
      result.certificate = {
        subject: certMatch[1]?.trim() || '',
        issuer: issuerMatch?.[1]?.trim() || '',
        notBefore: notBeforeMatch?.[1]?.trim() || '',
        notAfter: notAfterMatch?.[1]?.trim() || '',
        expired: false, // Will calculate below
        selfSigned: xmlOutput.includes('self signed')
      };

      // Check if certificate is expired
      if (result.certificate.notAfter) {
        const expiryDate = new Date(result.certificate.notAfter);
        result.certificate.expired = expiryDate < new Date();
      }
    }

    // Extract protocol support
    if (xmlOutput.includes('SSLv2') && xmlOutput.match(/SSLv2\s+enabled/)) {
      result.vulnerabilities.push('SSLv2 enabled (deprecated)');
    }
    if (xmlOutput.includes('SSLv3') && xmlOutput.match(/SSLv3\s+enabled/)) {
      result.vulnerabilities.push('SSLv3 enabled (deprecated)');
    }
    if (xmlOutput.includes('TLSv1.0') && xmlOutput.match(/TLSv1\.0\s+enabled/)) {
      result.vulnerabilities.push('TLSv1.0 enabled (deprecated)');
    }

    // Extract weak ciphers
    if (xmlOutput.includes('RC4')) {
      result.vulnerabilities.push('RC4 cipher support detected');
    }
    if (xmlOutput.includes('DES') || xmlOutput.includes('3DES')) {
      result.vulnerabilities.push('Weak DES/3DES cipher support detected');
    }
    if (xmlOutput.includes('NULL')) {
      result.vulnerabilities.push('NULL cipher support detected');
    }

    // Check for missing certificate - but this will be cross-validated with Python
    if (!result.certificate && !xmlOutput.includes('Certificate information')) {
      result.vulnerabilities.push('No SSL certificate presented');
    }

    return result;
    
  } catch (error) {
    log(`[tlsScan] Failed to parse sslscan output: ${(error as Error).message}`);
    return null;
  }
}

/** Check if domain is behind CDN/proxy that terminates SSL */
async function isCloudFlareProtected(hostname: string): Promise<boolean> {
  try {
    // Check DNS for known CDN IP ranges
    const { stdout } = await exec('dig', ['+short', hostname], { maxBuffer: 10 * 1024 * 1024 }); // 10MB buffer
    const ips = stdout.trim().split('\n').filter(ip => ip.includes('.'));
    
    // Comprehensive CDN IP ranges
    const cdnRanges = {
      cloudflare: [
        '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.',
        '104.24.', '104.25.', '104.26.', '104.27.', '104.28.', '104.29.', '104.30.', '104.31.',
        '172.64.', '172.65.', '172.66.', '172.67.', '108.162.', '141.101.', '162.158.', '162.159.',
        '173.245.', '188.114.', '190.93.', '197.234.', '198.41.', '103.21.', '103.22.', '103.31.'
      ],
      fastly: [
        '23.235.32.', '23.235.33.', '23.235.34.', '23.235.35.', '23.235.36.', '23.235.37.',
        '23.235.38.', '23.235.39.', '23.235.40.', '23.235.41.', '23.235.42.', '23.235.43.',
        '23.235.44.', '23.235.45.', '23.235.46.', '23.235.47.', '185.31.16.', '185.31.17.',
        '185.31.18.', '185.31.19.', '151.101.'
      ],
      bunnycdn: [
        '89.187.162.', '89.187.163.', '89.187.164.', '89.187.165.', '89.187.166.', '89.187.167.',
        '89.187.168.', '89.187.169.', '89.187.170.', '89.187.171.', '89.187.172.', '89.187.173.'
      ],
      keycdn: [
        '167.114.', '192.254.', '178.32.', '176.31.', '87.98.', '94.23.', '5.196.'
      ]
    };
    
    // Check if any IP matches known CDN ranges
    for (const [cdn, ranges] of Object.entries(cdnRanges)) {
      const matchesCDN = ips.some(ip => ranges.some(range => ip.startsWith(range)));
      if (matchesCDN) {
        log(`[tlsScan] ${hostname} detected behind ${cdn.toUpperCase()} CDN`);
        return true;
      }
    }
    
    // Check HTTP headers for comprehensive CDN detection
    try {
      const response = await httpClient.head(`https://${hostname}`, { 
        timeout: 5000,
        headers: { 'User-Agent': 'DealBrief-TLS-Scanner/1.0' }
      });
      
      const headers = response.headers;
      const headerStr = JSON.stringify(headers).toLowerCase();
      
      // Comprehensive CDN/Proxy header detection
      const cdnIndicators = {
        cloudflare: ['cf-ray', 'cf-cache-status', 'cloudflare', 'cf-edge', 'cf-worker'],
        aws_cloudfront: ['x-amz-cf-id', 'x-amzn-trace-id', 'x-amz-cf-pop', 'cloudfront'],
        fastly: ['x-served-by', 'x-fastly-request-id', 'fastly-debug-digest', 'x-timer'],
        akamai: ['x-akamai-', 'akamai', 'x-cache-key', 'x-check-cacheable'],
        maxcdn_stackpath: ['x-pull', 'x-cache', 'maxcdn', 'stackpath'],
        keycdn: ['x-edge-location', 'keycdn'],
        bunnycdn: ['bunnycdn', 'x-bunny'],
        jsdelivr: ['x-served-by', 'jsdelivr'],
        sucuri: ['x-sucuri-id', 'sucuri', 'x-sucuri-cache'],
        incapsula: ['x-iinfo', 'incap-ses', 'x-cdn', 'imperva'],
        // Security services that terminate SSL
        ddos_guard: ['x-ddos-protection', 'ddos-guard'],
        stormwall: ['x-stormwall', 'stormwall'],
        qrator: ['x-qrator', 'qrator']
      };
      
      // Check for any CDN/proxy indicators
      for (const [service, indicators] of Object.entries(cdnIndicators)) {
        const matchesService = indicators.some(indicator => 
          headerStr.includes(indicator) || 
          Object.keys(headers).some(header => header.toLowerCase().includes(indicator))
        );
        
        if (matchesService) {
          log(`[tlsScan] ${hostname} detected behind ${service.replace('_', ' ').toUpperCase()} via headers`);
          return true;
        }
      }
      
      // Check server headers for common CDN signatures
      const serverHeader = headers.server?.toLowerCase() || '';
      const cdnServerSigs = ['cloudflare', 'fastly', 'akamaighost', 'keycdn', 'bunnycdn'];
      if (cdnServerSigs.some(sig => serverHeader.includes(sig))) {
        log(`[tlsScan] ${hostname} detected CDN via Server header: ${serverHeader}`);
        return true;
      }
      
    } catch (httpError) {
      // HTTP check failed, but that doesn't mean it's not behind a CDN
    }
    
    return false;
    
  } catch (error) {
    log(`[tlsScan] CDN detection failed for ${hostname}: ${(error as Error).message}`);
    return false;
  }
}

/** Get remediation advice for TLS issues */
function getTlsRecommendation(vulnerability: string): string {
  const recommendations: Record<string, string> = {
    'SSLv2 enabled': 'Disable SSLv2 completely - it has known security vulnerabilities',
    'SSLv3 enabled': 'Disable SSLv3 completely - vulnerable to POODLE attack',
    'TLSv1.0 enabled': 'Disable TLSv1.0 - use TLS 1.2 or higher only',
    'RC4 cipher': 'Disable RC4 ciphers - they are cryptographically weak',
    'DES/3DES cipher': 'Disable DES and 3DES ciphers - use AES instead',
    'NULL cipher': 'Disable NULL ciphers - they provide no encryption',
    'No SSL certificate': 'Install a valid SSL/TLS certificate from a trusted CA',
    'expired': 'Renew the SSL certificate immediately',
    'self signed': 'Replace self-signed certificate with one from a trusted CA'
  };

  for (const [key, recommendation] of Object.entries(recommendations)) {
    if (vulnerability.toLowerCase().includes(key.toLowerCase())) {
      return recommendation;
    }
  }
  
  return 'Review and update TLS configuration according to current security best practices';
}

/** Cross-validate sslscan and Python certificate validator results */
async function performCrossValidation(
  host: string, 
  sslscanResult: SSLScanResult, 
  pythonResult: PythonValidationResult,
  scanId?: string
): Promise<{additionalFindings: number}> {
  let additionalFindings = 0;

  // 1. Check for validation mismatches - Trust Python validator over sslscan
  const sslscanHasCert = !!sslscanResult.certificate;
  const pythonHasCert = pythonResult.valid && !!pythonResult.certificate;
  
  // Only report a mismatch if Python says INVALID but sslscan says valid
  // If Python says valid but sslscan says invalid, trust Python (common with SNI/cloud certs)
  if (sslscanHasCert && !pythonHasCert) {
    additionalFindings++;
    const artId = await insertArtifact({
      type: 'tls_validation_mismatch',
      val_text: `${host} - Certificate validation mismatch: sslscan found cert but Python validation failed`,
      severity: 'MEDIUM',
      meta: {
        host,
        sslscan_has_cert: sslscanHasCert,
        python_has_cert: pythonHasCert,
        python_error: pythonResult.error,
        sni_supported: pythonResult.sni_supported,
        scan_id: scanId,
        scan_module: 'tlsScan_hybrid'
      }
    });
    
    await insertFinding(
      artId,
      'TLS_VALIDATION_INCONSISTENCY',
      'Certificate found by sslscan but Python validation failed - investigate certificate validity',
      `sslscan: found cert, Python validator: ${pythonResult.error || 'validation failed'}`
    );
  }
  // REMOVED: Don't report when Python says valid but sslscan says invalid (trust Python)

  // 2. SNI-specific issues
  if (!pythonResult.sni_supported && sslscanResult.certificate) {
    additionalFindings++;
    const artId = await insertArtifact({
      type: 'tls_sni_issue',
      val_text: `${host} - SNI configuration issue detected`,
      severity: 'HIGH',
      meta: {
        host,
        python_error: pythonResult.error,
        scan_id: scanId,
        scan_module: 'tlsScan_hybrid'
      }
    });
    
    await insertFinding(
      artId,
      'SNI_CONFIGURATION_ISSUE',
      'Configure proper SNI support for cloud-hosted certificates',
      `Certificate found by sslscan but Python validator failed: ${pythonResult.error}`
    );
  }

  // 3. Enhanced certificate expiry validation (Python is more accurate)
  if (pythonResult.certificate?.is_expired && sslscanResult.certificate && !sslscanResult.certificate.expired) {
    additionalFindings++;
    const artId = await insertArtifact({
      type: 'tls_certificate_expired_python',
      val_text: `${host} - Certificate expired (Python validator)`,
      severity: 'CRITICAL',
      meta: {
        host,
        python_certificate: pythonResult.certificate,
        validation_discrepancy: true,
        scan_id: scanId,
        scan_module: 'tlsScan_hybrid'
      }
    });
    
    await insertFinding(
      artId,
      'CERTIFICATE_EXPIRY_VERIFIED',
      'Certificate expiry confirmed by Python validator - renew immediately',
      `Python validator confirms certificate expired: ${pythonResult.certificate.not_after}`
    );
  }

  // 4. Modern TLS version detection (Python provides actual negotiated version)
  if (pythonResult.tls_version) {
    const tlsVersion = pythonResult.tls_version;
    if (tlsVersion.includes('1.0') || tlsVersion.includes('1.1')) {
      additionalFindings++;
      const artId = await insertArtifact({
        type: 'tls_weak_version_negotiated',
        val_text: `${host} - Weak TLS version negotiated: ${tlsVersion}`,
        severity: 'MEDIUM',
        meta: {
          host,
          negotiated_version: tlsVersion,
          cipher_suite: pythonResult.cipher_suite,
          scan_id: scanId,
          scan_module: 'tlsScan_hybrid'
        }
      });
      
      await insertFinding(
        artId,
        'WEAK_TLS_VERSION_NEGOTIATED',
        'Disable TLS 1.0 and 1.1 - use TLS 1.2+ only',
        `Negotiated TLS version: ${tlsVersion}`
      );
    }
  }

  log(`[tlsScan] Cross-validation complete for ${host}: ${additionalFindings} additional findings`);
  return { additionalFindings };
}

/* ---------- Core host-scan routine ---------------------------------------- */

async function scanHost(host: string, scanId?: string): Promise<ScanOutcome> {
  const start = Date.now();
  let findingsCount = 0;
  let certificateSeen = false;

  try {
    console.log(`[tlsScan] Starting scan for ${host}...`);
    log(`[tlsScan] Scanning ${host} with hybrid validation (sslscan + Python)...`);
    
    // Run both sslscan and Python validator concurrently
    const [sslscanResult, pythonResult] = await Promise.allSettled([
      runSslscan(host),
      runPythonCertificateValidator(host)
    ]);

    // Process sslscan results
    let sslscanData: { stdout: string; stderr: string } | null = null;
    if (sslscanResult.status === 'fulfilled') {
      sslscanData = sslscanResult.value;
      if (sslscanData.stderr) {
        // Filter out common ECDHE key generation warnings that don't affect functionality
        const filteredStderr = sslscanData.stderr
          .split('\n')
          .filter(line => !line.includes('Failed to generate ECDHE key for nid'))
          .join('\n')
          .trim();
        
        if (filteredStderr) {
          log(`[tlsScan] sslscan stderr for ${host}: ${filteredStderr}`);
        }
      }
    } else {
      log(`[tlsScan] sslscan failed for ${host}: ${sslscanResult.reason}`);
    }

    // Process Python validation results
    let pythonData: PythonValidationResult | null = null;
    if (pythonResult.status === 'fulfilled') {
      pythonData = pythonResult.value;
    } else {
      log(`[tlsScan] Python validator failed for ${host}: ${pythonResult.reason}`);
    }

    // Parse sslscan output
    const result = sslscanData ? parseSSLScanOutput(sslscanData.stdout, host) : null;
    if (!result) {
      log(`[tlsScan] Failed to parse results for ${host}`);
      return { findings: 0, hadCert: false };
    }

    certificateSeen = !!result.certificate;

    // Check certificate expiry
    if (result.certificate) {
      const cert = result.certificate;
      
      if (cert.expired) {
        findingsCount++;
        const artId = await insertArtifact({
          type: 'tls_certificate_expired',
          val_text: `${host} - SSL certificate expired`,
          severity: 'CRITICAL',
          meta: {
            host,
            certificate: cert,
            scan_id: scanId,
            scan_module: 'tlsScan'
          }
        });
        await insertFinding(
          artId,
          'CERTIFICATE_EXPIRY',
          'SSL certificate has expired - renew immediately',
          `Certificate for ${host} expired on ${cert.notAfter}`
        );
      } else if (cert.notAfter) {
        // Check if expiring soon
        const expiryDate = new Date(cert.notAfter);
        const daysUntilExpiry = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        
        let severity: Severity | null = null;
        if (daysUntilExpiry <= 14) {
          severity = 'HIGH';
        } else if (daysUntilExpiry <= 30) {
          severity = 'MEDIUM';
        } else if (daysUntilExpiry <= 90) {
          severity = 'LOW';
        }

        if (severity) {
          findingsCount++;
          const artId = await insertArtifact({
            type: 'tls_certificate_expiry',
            val_text: `${host} - SSL certificate expires in ${daysUntilExpiry} days`,
            severity,
            meta: {
              host,
              certificate: cert,
              days_remaining: daysUntilExpiry,
              scan_id: scanId,
              scan_module: 'tlsScan'
            }
          });
          await insertFinding(
            artId,
            'CERTIFICATE_EXPIRY',
            `Certificate expires in ${daysUntilExpiry} days - plan renewal`,
            `Certificate for ${host} expires on ${cert.notAfter}`
          );
        }
      }

      // Check for self-signed certificate
      if (cert.selfSigned) {
        findingsCount++;
        const artId = await insertArtifact({
          type: 'tls_self_signed',
          val_text: `${host} - Self-signed SSL certificate detected`,
          severity: 'MEDIUM',
          meta: {
            host,
            certificate: cert,
            scan_id: scanId,
            scan_module: 'tlsScan'
          }
        });
        await insertFinding(
          artId,
          'SELF_SIGNED_CERTIFICATE',
          'Replace self-signed certificate with one from a trusted CA',
          `Self-signed certificate detected for ${host}`
        );
      }
    }

    // Cross-validate with Python certificate validator
    if (pythonData && result) {
      const crossValidation = await performCrossValidation(host, result, pythonData, scanId);
      findingsCount += crossValidation.additionalFindings;
      
      // Update certificate seen status with Python validation
      certificateSeen = certificateSeen || (pythonData.valid && !!pythonData.certificate);
    }

    // Process vulnerabilities - filter out false positives when Python says certificate is valid
    for (const vulnerability of result.vulnerabilities) {
      // Skip "No SSL certificate presented" if Python validator confirmed a valid certificate
      if (vulnerability.includes('No SSL certificate') && pythonData && pythonData.valid && pythonData.certificate) {
        log(`[tlsScan] Skipping false positive: "${vulnerability}" - Python validator confirmed valid certificate`);
        continue;
      }

      // Check if site is behind CDN/proxy that terminates SSL - skip origin cert issues
      if (vulnerability.includes('No SSL certificate') && await isCloudFlareProtected(host)) {
        log(`[tlsScan] Skipping origin cert issue for ${host} - behind CDN/proxy (not user-facing risk)`);
        continue;
      }

      // Enhanced certificate issue analysis with Python validation context
      if (vulnerability.includes('No SSL certificate')) {
        // If Python validator shows certificate chain issues vs no certificate at all
        if (pythonData && pythonData.error?.includes('unable to get local issuer certificate')) {
          log(`[tlsScan] Converting "No SSL certificate" to "Incomplete certificate chain" based on Python validation`);
          // This is a configuration issue, not a security vulnerability
          const artId = await insertArtifact({
            type: 'tls_configuration',
            val_text: `${host} - Incomplete SSL certificate chain (missing intermediates)`,
            severity: 'INFO',
            meta: {
              host,
              issue_type: 'incomplete_certificate_chain',
              python_error: pythonData.error,
              scan_id: scanId,
              scan_module: 'tlsScan'
            }
          });

          await insertFinding(
            artId,
            'TLS_CONFIGURATION_ISSUE',
            'Configure server to present complete certificate chain including intermediate certificates',
            `Python validation: ${pythonData.error}`
          );
          
          findingsCount++;
          continue; // Skip the generic "No SSL certificate" processing
        }
      }
      
      findingsCount++;
      
      let severity: Severity = 'MEDIUM';
      if (vulnerability.includes('SSLv2') || vulnerability.includes('SSLv3')) {
        severity = 'HIGH'; // Removed "No SSL certificate" from HIGH severity
      } else if (vulnerability.includes('No SSL certificate')) {
        severity = 'HIGH'; // Only for actual missing certificates
      } else if (vulnerability.includes('NULL') || vulnerability.includes('RC4')) {
        severity = 'HIGH';
      } else if (vulnerability.includes('TLSv1.0') || vulnerability.includes('DES')) {
        severity = 'MEDIUM';
      }

      const artId = await insertArtifact({
        type: 'tls_weakness',
        val_text: `${host} - ${vulnerability}`,
        severity,
        meta: {
          host,
          vulnerability,
          scan_id: scanId,
          scan_module: 'tlsScan'
        }
      });

      await insertFinding(
        artId,
        'TLS_CONFIGURATION_ISSUE',
        getTlsRecommendation(vulnerability),
        vulnerability
      );
    }

  } catch (error) {
    console.log(`[tlsScan] ERROR: Scan failed for ${host}: ${(error as Error).message}`);
    log(`[tlsScan] Scan failed for ${host}: ${(error as Error).message}`);
  }

  console.log(`[tlsScan] Scan for ${host} completed in ${Date.now() - start}ms`);
  return { findings: findingsCount, hadCert: certificateSeen };
}

/* ---------- Public entry-point ------------------------------------------- */

export async function runTlsScan(job: { domain: string; scanId?: string }): Promise<number> {
  console.log(`[tlsScan] START ${job.domain} at ${new Date().toISOString()}`);
  const start = Date.now();
  const input = job.domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*/, '');

  // Validate sslscan is available
  if (!(await validateSSLScan())) {
    await insertArtifact({
      type: 'scan_error',
      val_text: 'sslscan binary not found, TLS scan aborted',
      severity: 'HIGH',
      meta: { scan_id: job.scanId, scan_module: 'tlsScan' }
    });
    return 0;
  }

  // Derive base domain & host list
  const isWww = input.startsWith('www.');
  const baseDomain = isWww ? input.slice(4) : input;

  const candidates = new Set<string>();
  
  // Always scan the original host
  candidates.add(input);

  // Forward derivations (apex → prefixes)
  if (!isWww) {
    TLS_DERIVATION_PREFIXES.forEach((prefix) => candidates.add(`${prefix}.${baseDomain}`));
  }

  // Reverse derivation (www → apex)
  if (isWww) {
    candidates.add(baseDomain);
  }

  let totalFindings = 0;
  let anyCert = false;

  // Process hosts with controlled concurrency to prevent resource exhaustion
  const MAX_CONCURRENT_TLS_SCANS = 3;
  const hostArray = Array.from(candidates);
  
  for (let i = 0; i < hostArray.length; i += MAX_CONCURRENT_TLS_SCANS) {
    const chunk = hostArray.slice(i, i + MAX_CONCURRENT_TLS_SCANS);
    const results = await Promise.allSettled(
      chunk.map(host => scanHost(host, job.scanId))
    );
    
    for (const result of results) {
      if (result.status === 'fulfilled') {
        totalFindings += result.value.findings;
        anyCert ||= result.value.hadCert;
      } else {
        log(`[tlsScan] Host scan failed: ${result.reason}`);
      }
    }
  }

  /* Consolidated "no TLS at all" finding (only if *all* hosts lack cert) */
  if (!anyCert) {
    const artId = await insertArtifact({
      type: 'tls_no_certificate',
      val_text: `${baseDomain} - no valid SSL/TLS certificate on any host`,
      severity: 'HIGH',
      meta: {
        domain: baseDomain,
        scan_id: job.scanId,
        scan_module: 'tlsScan'
      }
    });
    await insertFinding(
      artId,
      'MISSING_TLS_CERTIFICATE',
      'Configure SSL/TLS certificates for all public hosts',
      'No valid SSL/TLS certificate found on any tested host variant'
    );
    totalFindings += 1;
  }

  /* Final summary artifact */
  await insertArtifact({
    type: 'scan_summary',
    val_text: `TLS scan complete - ${totalFindings} issue(s) found`,
    severity: 'INFO',
    meta: {
      domain: baseDomain,
      scan_id: job.scanId,
      scan_module: 'tlsScan',
      total_findings: totalFindings,
      hosts_scanned: Array.from(candidates),
      timestamp: new Date().toISOString()
    }
  });

  console.log(`[tlsScan] COMPLETE: Found ${totalFindings} TLS issues in ${Date.now() - start}ms`);
  log(`[tlsScan] Scan complete. Hosts: ${[...candidates].join(', ')}. Findings: ${totalFindings}`);
  return totalFindings;
}