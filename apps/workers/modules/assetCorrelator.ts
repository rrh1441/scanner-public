/*
 * =============================================================================
 * MODULE: assetCorrelator.ts
 * =============================================================================
 * Correlates disparate security findings into asset-centric intelligence.
 * Transforms flat artifact lists into actionable, prioritized asset groups.
 * 
 * Key optimizations:
 * - Batch DNS resolution with caching
 * - Streaming for large datasets
 * - Service-level correlation (IP:port tuples)
 * - Hostname affinity validation
 * - Finding deduplication
 * =============================================================================
 */

import { pool, insertArtifact } from '../core/artifactStore.js';
import { logLegacy as log } from '../core/logger.js';
import dns from 'node:dns/promises';
import pLimit from 'p-limit';

// Types
interface CorrelatedAsset {
  ip: string;
  port?: number;
  hostnames: string[];
  service?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  findings: Finding[];
  asn?: string;
  org?: string;
  asset_criticality: number;
}

interface Finding {
  artifact_id: number;
  type: string;
  id?: string; // CVE-ID, finding ID
  cvss?: number;
  epss?: number;
  description: string;
}

interface RawArtifact {
  id: number;
  type: string;
  val_text: string;
  severity: string;
  ip?: string;
  host?: string;
  port?: number | string;
  metadata: any;
  hostnames_json?: string;
  product?: string;
  version?: string;
  org?: string;
  asn?: string;
  cve?: string;
  cvss?: string;
  epss?: string;
}

// DNS cache for the scan session
class DNSCache {
  private cache = new Map<string, string[]>();
  private limit = pLimit(10); // Max 10 concurrent DNS lookups

  async resolve(hostname: string): Promise<string[]> {
    if (this.cache.has(hostname)) {
      return this.cache.get(hostname)!;
    }

    try {
      const result = await this.limit(() => 
        Promise.race([
          dns.lookup(hostname, { all: true }),
          new Promise<never>((_, reject) => 
            setTimeout(() => reject(new Error('DNS timeout')), 3000)
          )
        ])
      );
      
      const ips = Array.isArray(result) 
        ? result.map((r: any) => r.address) 
        : [(result as any).address];
      
      this.cache.set(hostname, ips);
      return ips;
    } catch (error) {
      log(`[assetCorrelator] DNS resolution failed for ${hostname}: ${error}`);
      this.cache.set(hostname, []); // Cache failures too
      return [];
    }
  }

  async resolveBatch(hostnames: Set<string>): Promise<Map<string, string[]>> {
    const results = new Map<string, string[]>();
    const promises = Array.from(hostnames).map(async hostname => {
      const ips = await this.resolve(hostname);
      results.set(hostname, ips);
    });
    
    await Promise.allSettled(promises);
    return results;
  }
}

// Main correlation function
export async function runAssetCorrelator(job: { 
  scanId: string; 
  domain: string; 
  tier?: 'tier1' | 'tier2' 
}): Promise<void> {
  console.log(`[assetCorrelator] START at ${new Date().toISOString()}`);
  const { scanId, domain, tier = 'tier1' } = job;
  const startTime = Date.now();
  const TIMEOUT_MS = 30000; // 30 second overall timeout
  
  log(`[assetCorrelator] Starting correlation for scanId: ${scanId}, tier: ${tier}`);

  try {
    // Set up timeout
    const timeoutPromise = new Promise<never>((_, reject) => 
      setTimeout(() => reject(new Error('Correlation timeout')), TIMEOUT_MS)
    );

    await Promise.race([
      correlateAssets(scanId, domain),
      timeoutPromise
    ]);

  } catch (error) {
    const elapsed = Date.now() - startTime;
    console.log(`[assetCorrelator] ERROR: ${(error as Error).message} after ${elapsed}ms`);
    log(`[assetCorrelator] Failed after ${elapsed}ms:`, (error as Error).message);
    
    await insertArtifact({
      type: 'scan_error',
      val_text: `Asset correlation failed: ${(error as Error).message}`,
      severity: 'MEDIUM',
      meta: { 
        scan_id: scanId, 
        scan_module: 'assetCorrelator',
        elapsed_ms: elapsed,
        truncated: (error as Error).message === 'Correlation timeout'
      }
    });
  }
}

async function correlateAssets(scanId: string, domain: string): Promise<void> {
  const startTime = Date.now();
  const dnsCache = new DNSCache();
  const assets = new Map<string, CorrelatedAsset>();
  const correlatedArtifactIds = new Set<number>();
  
  // Query to get all artifacts for this scan
  const query = `SELECT 
      id, 
      type, 
      val_text, 
      severity,
      metadata->>'ip' AS ip,
      metadata->>'host' AS host, 
      metadata->>'port' AS port,
      metadata->>'hostnames' AS hostnames_json,
      metadata->>'product' AS product,
      metadata->>'version' AS version,
      metadata->>'org' AS org,
      metadata->>'asn' AS asn,
      metadata->>'cve' AS cve,
      metadata->>'cvss' AS cvss,
      metadata->>'epss_score' AS epss,
      metadata
    FROM artifacts 
    WHERE scan_id = $1
    ORDER BY created_at`;

  let artifactCount = 0;
  let correlatedCount = 0;

  // Phase 1: Fetch all artifacts and collect hostnames for batch DNS resolution
  const allHostnames = new Set<string>();
  let artifactBuffer: RawArtifact[] = [];
  
  try {
    // Get database connection
    const { LocalStore } = await import('../core/localStore.js');
    const store = new LocalStore();
    
    let result: { rows: RawArtifact[] };
    try {
      result = await store.query(query, [scanId]);
    } finally {
      await store.close();
    }
    
    for (const row of result.rows) {
      artifactBuffer.push(row);
      artifactCount++;
      
      if (row.type === 'hostname' || row.type === 'subdomain') {
        allHostnames.add(row.val_text);
      }
      if (row.hostnames_json) {
        try {
          const hostnames = JSON.parse(row.hostnames_json);
          if (Array.isArray(hostnames)) {
            hostnames.forEach((h: string) => allHostnames.add(h));
          }
        } catch (e) {}
      }
    }
  } catch (error) {
    log(`[assetCorrelator] Query error:`, error);
    throw error;
  }

  console.log(`[assetCorrelator] Available data from: ${artifactCount} artifacts`);
  console.log(`[assetCorrelator] Correlating ${artifactCount} artifacts with ${allHostnames.size} hostnames...`);
  log(`[assetCorrelator] Found ${artifactCount} artifacts, resolving ${allHostnames.size} hostnames`);

  // Phase 2: Batch DNS resolution
  const hostnameToIps = await dnsCache.resolveBatch(allHostnames);

  // Phase 3: Process artifacts and build asset map
  for (const artifact of artifactBuffer) {
    const ips = extractIPs(artifact, hostnameToIps);
    
    if (ips.length === 0) {
      // Non-correlatable artifact
      continue;
    }

    correlatedCount++;
    correlatedArtifactIds.add(artifact.id);

    for (const ip of ips) {
      // Create asset key (IP:port for services, IP for host-level)
      const port = artifact.port ? parseInt(String(artifact.port)) : undefined;
      const assetKey = port ? `${ip}:${port}` : ip;
      
      // Get or create asset
      if (!assets.has(assetKey)) {
        assets.set(assetKey, {
          ip,
          port,
          hostnames: [],
          service: artifact.product || undefined,
          severity: 'INFO',
          findings: [],
          asn: artifact.asn || undefined,
          org: artifact.org || undefined,
          asset_criticality: 1
        });
      }

      const asset = assets.get(assetKey)!;

      // Add hostnames with affinity validation
      const validHostnames = validateHostnameAffinity(artifact, ip, hostnameToIps);
      validHostnames.forEach(h => {
        if (!asset.hostnames.includes(h)) {
          asset.hostnames.push(h);
        }
      });

      // Add finding (with deduplication)
      const finding: Finding = {
        artifact_id: artifact.id,
        type: artifact.type,
        id: artifact.cve || undefined,
        cvss: artifact.cvss ? parseFloat(artifact.cvss) : undefined,
        epss: artifact.epss ? parseFloat(artifact.epss) : undefined,
        description: artifact.val_text
      };

      // Deduplicate by type and description
      const findingKey = `${finding.type}:${finding.description}`;
      const existingFinding = asset.findings.find(f => 
        `${f.type}:${f.description}` === findingKey
      );

      if (!existingFinding) {
        asset.findings.push(finding);
        
        // Update asset severity (max of all findings)
        asset.severity = maxSeverity(asset.severity, artifact.severity as any);
        
        // Update criticality score
        if (artifact.severity === 'CRITICAL') {
          asset.asset_criticality = Math.min(10, asset.asset_criticality + 3);
        } else if (artifact.severity === 'HIGH') {
          asset.asset_criticality = Math.min(10, asset.asset_criticality + 2);
        }
      }
    }
  }

  // Phase 4: Generate correlation summary
  const assetArray = Array.from(assets.values());
  const criticalAssets = assetArray.filter(a => 
    a.severity === 'CRITICAL' || a.asset_criticality >= 8
  );

  if (assetArray.length > 0) {
    const summary = {
      total_artifacts: artifactCount,
      correlated_artifacts: correlatedCount,
      uncorrelated_artifacts: artifactCount - correlatedCount,
      total_assets: assetArray.length,
      critical_assets: criticalAssets.length,
      severity_breakdown: {
        critical: assetArray.filter(a => a.severity === 'CRITICAL').length,
        high: assetArray.filter(a => a.severity === 'HIGH').length,
        medium: assetArray.filter(a => a.severity === 'MEDIUM').length,
        low: assetArray.filter(a => a.severity === 'LOW').length,
        info: assetArray.filter(a => a.severity === 'INFO').length
      },
      assets: assetArray.sort((a, b) => b.asset_criticality - a.asset_criticality)
    };

    await insertArtifact({
      type: 'correlated_asset_summary',
      val_text: `Correlated ${correlatedCount}/${artifactCount} artifacts into ${assetArray.length} assets (${criticalAssets.length} critical)`,
      severity: criticalAssets.length > 0 ? 'HIGH' : 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'assetCorrelator',
        correlation_summary: summary
      }
    });

    console.log(`[assetCorrelator] COMPLETE: Correlated ${assetArray.length} assets in ${Date.now() - startTime}ms`);
    log(`[assetCorrelator] Successfully correlated ${correlatedCount} artifacts into ${assetArray.length} assets`);
  } else {
    console.log(`[assetCorrelator] COMPLETE: No correlatable assets found in ${artifactCount} artifacts`);
    log(`[assetCorrelator] No correlatable assets found in ${artifactCount} artifacts`);
  }
}

// Helper functions
function extractIPs(artifact: RawArtifact, hostnameToIps: Map<string, string[]>): string[] {
  const ips = new Set<string>();
  
  // Direct IP
  if (artifact.ip) ips.add(artifact.ip);
  
  // IPs from meta
  if (artifact.metadata?.ips) {
    artifact.metadata.ips.forEach((ip: string) => ips.add(ip));
  }
  
  // IP artifacts
  if (artifact.type === 'ip') {
    ips.add(artifact.val_text);
  }
  
  // Resolved IPs from hostnames
  if (artifact.host) {
    const resolved = hostnameToIps.get(artifact.host) || [];
    resolved.forEach(ip => ips.add(ip));
  }
  
  if (artifact.type === 'hostname' || artifact.type === 'subdomain') {
    const resolved = hostnameToIps.get(artifact.val_text) || [];
    resolved.forEach(ip => ips.add(ip));
  }
  
  return Array.from(ips);
}

function validateHostnameAffinity(
  artifact: RawArtifact, 
  ip: string, 
  hostnameToIps: Map<string, string[]>
): string[] {
  const validHostnames: string[] = [];
  
  // Check all possible hostnames
  const candidateHostnames = new Set<string>();
  if (artifact.host) candidateHostnames.add(artifact.host);
  if (artifact.type === 'hostname' || artifact.type === 'subdomain') {
    candidateHostnames.add(artifact.val_text);
  }
  if (artifact.hostnames_json) {
    try {
      const hostnames = JSON.parse(artifact.hostnames_json);
      hostnames.forEach((h: string) => candidateHostnames.add(h));
    } catch (e) {}
  }
  
  // Validate each hostname resolves to this IP
  for (const hostname of candidateHostnames) {
    const resolvedIps = hostnameToIps.get(hostname) || [];
    if (resolvedIps.includes(ip)) {
      validHostnames.push(hostname);
    }
  }
  
  // If from TLS cert, trust it even without DNS match
  if (artifact.type === 'tls_scan' && artifact.metadata?.cert_hostnames) {
    artifact.metadata.cert_hostnames.forEach((h: string) => {
      if (!validHostnames.includes(h)) {
        validHostnames.push(h);
      }
    });
  }
  
  return validHostnames;
}

function maxSeverity(a: string, b: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
  const severityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
  const aVal = severityOrder[a as keyof typeof severityOrder] || 0;
  const bVal = severityOrder[b as keyof typeof severityOrder] || 0;
  const maxVal = Math.max(aVal, bVal);
  
  return (Object.keys(severityOrder).find(
    k => severityOrder[k as keyof typeof severityOrder] === maxVal
  ) || 'INFO') as any;
}
