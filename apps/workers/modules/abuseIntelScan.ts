/**
 * AbuseIntel-GPT Module
 * 
 * Autonomous scanner module for DealBrief's artifact pipeline that checks IP addresses
 * against AbuseIPDB v2 API for reputation and abuse intelligence.
 */

import { httpClient } from '../net/httpClient.js';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as rootLog } from '../core/logger.js';
import { executeModule, apiCall, errorHandler } from '../util/errorHandler.js';

// Configuration constants
const ABUSEIPDB_ENDPOINT = 'https://api.abuseipdb.com/api/v2/check';
const RATE_LIMIT_DELAY_MS = 2000; // 30 requests/minute = 2 second intervals
const JITTER_MS = 200; // ±200ms jitter
const REQUEST_TIMEOUT_MS = 10000;


// Risk assessment thresholds
const SUSPICIOUS_THRESHOLD = 25;
const MALICIOUS_THRESHOLD = 70;

// Enhanced logging
const log = (...args: unknown[]) => rootLog('[abuseIntelScan]', ...args);

interface AbuseIPDBResponse {
  ipAddress: string;
  isPublic: boolean;
  ipVersion: number;
  isWhitelisted: boolean;
  abuseConfidenceScore: number;
  countryCode: string;
  usageType: string;
  isp: string;
  domain: string;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt: string | null;
}

interface RiskAssessment {
  confidence: number;
  findingType: 'SUSPICIOUS_IP' | 'MALICIOUS_IP';
  severity: 'MEDIUM' | 'HIGH';
  description: string;
  evidence: AbuseIPDBResponse;
  recommendation: string;
}

interface IPArtifact {
  id: number;
  val_text: string; // The IP address
  meta: Record<string, any>;
}

interface ScanMetrics {
  totalIPs: number;
  suspicious: number;
  malicious: number;
  errors: number;
  scanTimeMs: number;
}

/**
 * Jittered delay to respect rate limits and avoid thundering herd
 */
async function jitteredDelay(): Promise<void> {
  const delay = RATE_LIMIT_DELAY_MS + (Math.random() * JITTER_MS * 2 - JITTER_MS);
  await new Promise(resolve => setTimeout(resolve, delay));
}

/**
 * Query artifact store for all IP artifacts from the current scan
 */
async function getIPArtifacts(scanId: string): Promise<IPArtifact[]> {
  try {
    const { LocalStore } = await import('../core/localStore.js');
    const store = new LocalStore();
    
    try {
      const result = await store.query(
        'SELECT metadata FROM artifacts WHERE scan_id = $1 AND type = $2',
        [scanId, 'network_discovery']
      );
      
      const ipArtifacts: IPArtifact[] = [];
      
      for (const row of result.rows) {
        if (row.metadata?.ips) {
          // Convert IPs from metadata to artifact format
          for (const ip of row.metadata.ips) {
            ipArtifacts.push({
              id: Date.now() + Math.floor(Math.random() * 1000), // Generate a fake integer ID for compatibility
              val_text: ip.trim(),
              meta: { source: 'network_discovery' }
            });
          }
        }
      }
      
      log(`Found ${ipArtifacts.length} IP artifacts for scan ${scanId}`);
      return ipArtifacts;
      
    } finally {
      await store.close();
    }
  } catch (error) {
    log(`Error querying IP artifacts: ${(error as Error).message}`);
    return [];
  }
}

/**
 * Check if IP address is valid (IPv4 or IPv6)
 */
function isValidIP(ip: string): boolean {
  // Basic IPv4 regex
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  // Basic IPv6 regex (simplified)
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
  
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

/**
 * Check single IP against AbuseIPDB with retries and error handling
 */
async function checkAbuseIPDB(ip: string): Promise<RiskAssessment | null> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    log('ABUSEIPDB_API_KEY not set - skipping AbuseIPDB check');
    return null;
  }

  if (!isValidIP(ip)) {
    log(`Skipping invalid IP: ${ip}`);
    return null;
  }

  // Use standardized API call with retry logic
  const result = await apiCall(async () => {
    log(`Checking IP ${ip} with AbuseIPDB`);
    
    const response = await httpClient.get(ABUSEIPDB_ENDPOINT, {
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
        verbose: ''
      },
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      },
      timeout: REQUEST_TIMEOUT_MS
    });

    return response.data.data as AbuseIPDBResponse;
  }, {
    moduleName: 'abuseIntelScan',
    operation: 'checkAbuseIPDB',
    target: ip
  });
  
  if (!result.success) {
    log(`Failed to check IP ${ip}: ${(result as any).error}`);
    return null;
  }
  
  const data = result.data;
      
      // Only generate findings for IPs with material risk
      if (data.abuseConfidenceScore < SUSPICIOUS_THRESHOLD) {
        log(`IP ${ip} is clean (confidence: ${data.abuseConfidenceScore}%)`);
        return null;
      }

      // Determine risk level and finding type
      const isMalicious = data.abuseConfidenceScore >= MALICIOUS_THRESHOLD;
      const findingType = isMalicious ? 'MALICIOUS_IP' : 'SUSPICIOUS_IP';
      const severity = isMalicious ? 'HIGH' : 'MEDIUM';
      
      // Generate actionable description
      const description = `${ip} has ${data.abuseConfidenceScore}% abuse confidence (${data.totalReports} reports from ${data.numDistinctUsers} users)`;
      
      // Generate specific recommendation
      let recommendation = '';
      if (isMalicious) {
        recommendation = `Block ${ip} immediately. Consider firewall rules and monitoring for related activity.`;
      } else {
        recommendation = `Monitor ${ip} for suspicious activity. Consider rate limiting or enhanced logging.`;
      }

  log(`IP ${ip} flagged as ${findingType} (confidence: ${data.abuseConfidenceScore}%)`);
  
  return {
    confidence: data.abuseConfidenceScore,
    findingType,
    severity,
    description,
    evidence: data,
    recommendation
  };
}

/**
 * Deduplicate IPs within the same scan
 */
function deduplicateIPs(artifacts: IPArtifact[]): IPArtifact[] {
  const seen = new Set<string>();
  return artifacts.filter(artifact => {
    const ip = artifact.val_text.trim();
    if (seen.has(ip)) {
      log(`Skipping duplicate IP: ${ip}`);
      return false;
    }
    seen.add(ip);
    return true;
  });
}

/**
 * Main scan function - processes all IP artifacts for the given scan
 */
export async function runAbuseIntelScan(job: { scanId: string }): Promise<number> {
  const { scanId } = job;
  
  return executeModule('abuseIntelScan', async () => {
    log(`Starting AbuseIPDB scan for scanId=${scanId}`);
    
    // Check for API key first
    if (!process.env.ABUSEIPDB_API_KEY) {
      log('ABUSEIPDB_API_KEY not configured, emitting warning and exiting gracefully');
      
      await insertArtifact({
        type: 'scan_warning',
        val_text: 'AbuseIPDB scan skipped - API key not configured',
        severity: 'LOW',
        meta: {
          scan_id: scanId,
          scan_module: 'abuseIntelScan',
          reason: 'missing_api_key'
        }
      });
      
      return 0;
    }
    // Get all IP artifacts for this scan
    const ipArtifacts = await getIPArtifacts(scanId);
    
    if (ipArtifacts.length === 0) {
      log('No IP artifacts found for this scan');
      return 0;
    }
    
    // Deduplicate IPs
    const uniqueIPs = deduplicateIPs(ipArtifacts);
    log(`Processing ${uniqueIPs.length} unique IPs (${ipArtifacts.length - uniqueIPs.length} duplicates removed)`);
    
    const metrics: ScanMetrics = {
      totalIPs: uniqueIPs.length,
      suspicious: 0,
      malicious: 0,
      errors: 0,
      scanTimeMs: 0
    };
    
    let findingsCount = 0;
    
    // Process each IP sequentially with rate limiting
    for (let i = 0; i < uniqueIPs.length; i++) {
      const artifact = uniqueIPs[i];
      const ip = artifact.val_text.trim();
      
      try {
        // Check IP against AbuseIPDB
        const risk = await checkAbuseIPDB(ip);
        
        if (risk) {
          // Create finding linked to the original artifact
          await insertFinding(
            artifact.id,
            risk.findingType,
            risk.recommendation,
            risk.description
          );
          
          // Update metrics
          if (risk.findingType === 'MALICIOUS_IP') {
            metrics.malicious++;
          } else {
            metrics.suspicious++;
          }
          
          findingsCount++;
          
          log(`Created ${risk.findingType} finding for ${ip} (confidence: ${risk.confidence}%)`);
        }
        
      } catch (error) {
        metrics.errors++;
        log(`Error processing IP ${ip}: ${(error as Error).message}`);
        
        // Continue with remaining IPs
        continue;
      }
      
      // Rate limiting - don't delay after the last IP
      if (i < uniqueIPs.length - 1) {
        await jitteredDelay();
      }
    }
    
    // Calculate final metrics (duration will be handled by executeModule wrapper)
    
    // Create summary artifact
    await insertArtifact({
      type: 'abuse_intel_summary',
      val_text: `AbuseIPDB scan completed: ${metrics.malicious} malicious, ${metrics.suspicious} suspicious IPs found`,
      severity: metrics.malicious > 0 ? 'HIGH' : metrics.suspicious > 0 ? 'MEDIUM' : 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'abuseIntelScan',
        metrics: metrics,
        api_quota_used: metrics.totalIPs - metrics.errors
      }
    });
    
    log(`AbuseIPDB scan completed: ${findingsCount} findings from ${metrics.totalIPs} IPs in ${metrics.scanTimeMs}ms`);
    log(`Summary: ${metrics.malicious} malicious, ${metrics.suspicious} suspicious, ${metrics.errors} errors`);
    
    return findingsCount;
    
  }, { scanId });
}