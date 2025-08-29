/* =============================================================================
 * MODULE: techStackScan.ts (Monolithic v4 – Pre-Refactor)
 * =============================================================================
 * This module performs technology fingerprinting with integrated vulnerability
 * intelligence, SBOM generation, and supply-chain risk scoring.
 * =============================================================================
 */
import {
  insertArtifact,
  insertFinding,
} from '../core/artifactStore.js';
import { logLegacy as rootLog } from '../core/logger.js';
import {
  detectTechnologiesWithWebTech,
  detectTechnologiesWithWhatWeb,
  detectFromHeaders,
} from '../util/fastTechDetection.js';
import { detectTechnologyByFavicon } from '../util/faviconDetection.js';

// Configuration - optimized for local 8-core machine
const CONFIG = {
  MAX_CONCURRENCY: 8,  // Increased for 8-core system
  TECH_CIRCUIT_BREAKER: 20,
  PAGE_TIMEOUT_MS: 15_000,  // Reduced timeout for faster scans
  MAX_VULN_IDS_PER_FINDING: 12,
} as const;

type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
const RISK_TO_SEVERITY: Record<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', Severity> = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL'
};

// Types
interface TechResult {
  name: string;
  slug: string;
  version?: string;
  confidence: number;
  cpe?: string;
  purl?: string;
  vendor?: string;
  ecosystem?: string;
  categories: string[];
}

interface VulnRecord {
  id: string;
  source: 'OSV' | 'GITHUB';
  cvss?: number;
  epss?: number;
  cisaKev?: boolean;
  summary?: string;
  publishedDate?: Date;
  affectedVersionRange?: string;
  activelyTested?: boolean;
  exploitable?: boolean;
  verificationDetails?: any;
}

interface EnhancedSecAnalysis {
  eol: boolean;
  vulns: VulnRecord[];
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  advice: string[];
  versionAccuracy?: number;
  supplyChainScore: number;
  activeVerification?: {
    tested: number;
    exploitable: number;
    notExploitable: number;
  };
}

interface ScanMetrics {
  totalTargets: number;
  targetsScanned: number;
  targetsFailed: number;
  uniqueTechs: number;
  supplyFindings: number;
  runMs: number;
  circuitBreakerTripped: boolean;
  detectorsUsed: string[];
}

// Cache removed for simplicity

const log = (...m: unknown[]) => rootLog('[techStackScan]', ...m);

// Helper function
function summarizeVulnIds(v: VulnRecord[], max: number): string {
  const ids = v.slice(0, max).map(r => r.id);
  return v.length > max ? ids.join(', ') + ', …' : ids.join(', ');
}

function detectEcosystem(tech: TechResult): string {
  const name = tech.name.toLowerCase();
  if (name.includes('node') || name.includes('npm')) return 'npm';
  if (name.includes('python') || name.includes('pip')) return 'pypi';
  if (name.includes('java') || name.includes('maven')) return 'maven';
  if (name.includes('ruby') || name.includes('gem')) return 'rubygems';
  if (name.includes('php') || name.includes('composer')) return 'packagist';
  if (name.includes('docker')) return 'docker';
  return 'unknown';
}

// Simple concurrency controller
async function mapConcurrent<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
  const results: R[] = [];
  const executing: Promise<void>[] = [];
  
  for (const item of items) {
    const promise = fn(item).then(result => {
      results.push(result);
    });
    
    executing.push(promise);
    
    if (executing.length >= limit) {
      await Promise.race(executing);
      executing.splice(executing.findIndex(p => p === promise), 1);
    }
  }
  
  await Promise.all(executing);
  return results;
}

// Simplified target discovery
async function discoverTargets(domain: string, providedTargets?: string[]) {
  const targets = new Set<string>();
  
  // Add primary domain targets
  targets.add(`https://${domain}`);
  targets.add(`https://www.${domain}`);
  
  // Add provided targets
  if (providedTargets) {
    providedTargets.forEach(t => targets.add(t));
  }
  
  return {
    primary: Array.from(targets).slice(0, 5),
    total: targets.size
  };
}

// Enhanced security analysis - only flag actual risks
async function analyzeSecurityEnhanced(tech: TechResult): Promise<EnhancedSecAnalysis> {
  const advice: string[] = [];
  let risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  let supplyChainScore = 7.0; // Default to healthy score
  
  // Only flag actual security concerns
  if (tech.version && (tech.version.includes('dev') || tech.version.includes('alpha') || tech.version.includes('beta'))) {
    advice.push(`${tech.name} running development/pre-release version ${tech.version}`);
    risk = 'MEDIUM';
    supplyChainScore = 4.0;
  }
  
  // Flag very old software that's likely EOL
  const name = tech.name.toLowerCase();
  if (name.includes('apache') && tech.version && tech.version.match(/^[01]\./)) {
    advice.push(`${tech.name} version ${tech.version} is end-of-life`);
    risk = 'HIGH';
    supplyChainScore = 2.0;
  }
  if (name.includes('php') && tech.version && tech.version.match(/^[0-6]\./)) {
    advice.push(`PHP version ${tech.version} is end-of-life and unsupported`);
    risk = 'HIGH'; 
    supplyChainScore = 2.0;
  }
  if (name.includes('nginx') && tech.version && tech.version.match(/^0\./)) {
    advice.push(`Nginx version ${tech.version} is end-of-life`);
    risk = 'HIGH';
    supplyChainScore = 2.0;
  }
  
  return {
    eol: risk === 'HIGH',
    vulns: [],
    risk,
    advice,
    versionAccuracy: tech.confidence,
    supplyChainScore,
    activeVerification: {
      tested: 0,
      exploitable: 0,
      notExploitable: 0
    }
  };
}

// Main function
export async function runTechStackScan(job: { 
  domain: string; 
  scanId: string;
  targets?: string[];
}): Promise<number> {
  const { domain, scanId, targets: providedTargets } = job;
  const start = Date.now();
  console.log(`[techStackScan] START ${domain} at ${new Date().toISOString()}`);
  log(`techstack=start domain=${domain}`);

  try {
    // 1. TARGET DISCOVERY
    const targetResult = await discoverTargets(domain, providedTargets);
    const allTargets = targetResult.primary;
    
    console.log(`[techStackScan] Target discovery complete: ${targetResult.total} targets found`);
    log(`techstack=targets total=${targetResult.total} html=${allTargets.length}`);
    
    // 2. TECHNOLOGY DETECTION WITH CONCURRENCY
    let circuitBreakerTripped = false;
    let consecutiveFailures = 0;
    
    // Process targets concurrently with circuit breaker
    const detectionsPerUrl = await mapConcurrent(
      allTargets.slice(0, 5),
      CONFIG.MAX_CONCURRENCY,
      async (url) => {
        // Check circuit breaker
        if (circuitBreakerTripped) {
          console.log(`[techStackScan] Skipping ${url} - circuit breaker tripped`);
          return { url, detections: [], error: 'circuit-breaker-tripped' };
        }
        
        const urlDetections: TechResult[] = [];
        let hasError = false;
        
        try {
          console.log(`[techStackScan] Starting httpx detection for ${url}...`);
          const webtech = await detectTechnologiesWithWebTech(url); // This now uses httpx internally
          urlDetections.push(...webtech.technologies);
          console.log(`[techStackScan] httpx complete: ${webtech.technologies.length} technologies found`);
          
          // Run WhatWeb if httpx found nothing
          if (webtech.technologies.length === 0) {
            console.log(`[techStackScan] Starting WhatWeb detection for ${url}...`);
            const whatweb = await detectTechnologiesWithWhatWeb(url);
            urlDetections.push(...whatweb.technologies);
            console.log(`[techStackScan] WhatWeb complete: ${whatweb.technologies.length} technologies found`);
          }
          
          // Headers fallback if still nothing
          if (urlDetections.length === 0) {
            console.log(`[techStackScan] Starting header detection for ${url}...`);
            const headers = await detectFromHeaders(url);
            urlDetections.push(...headers);
            console.log(`[techStackScan] Header detection complete: ${headers.length} technologies found`);
          }

          // Always try favicon (it's cheap and adds signals)
          console.log(`[techStackScan] Starting favicon detection for ${url}...`);
          const favicon = await detectTechnologyByFavicon(url);
          if (favicon.length > 0) {
            urlDetections.push(...favicon);
          }
          console.log(`[techStackScan] Favicon detection complete: ${favicon.length} technologies found`);
          
        } catch (err) {
          hasError = true;
          log(`Error detecting tech for ${url}:`, (err as Error).message);
        }
        
        // Update circuit breaker state
        if (hasError && urlDetections.length === 0) {
          consecutiveFailures++;
          if (consecutiveFailures >= CONFIG.TECH_CIRCUIT_BREAKER) {
            circuitBreakerTripped = true;
            console.log(`[techStackScan] Circuit breaker tripped after ${consecutiveFailures} failures`);
          }
        } else {
          consecutiveFailures = 0; // Reset on success
        }
        
        return { url, detections: urlDetections, error: hasError ? 'detection-failed' : undefined };
      }
    );
    
    // Merge all detections
    let allDetections: TechResult[] = [];
    for (const result of detectionsPerUrl) {
      allDetections.push(...result.detections);
    }

    const techMap = new Map<string, TechResult>();
    for (const tech of allDetections) {
      if (!techMap.has(tech.slug) || (techMap.get(tech.slug)!.confidence < tech.confidence)) {
        techMap.set(tech.slug, tech);
      }
    }
    
    console.log(`[techStackScan] Technology detection phase complete: ${techMap.size} unique technologies identified`);
    log(`techstack=tech_detection_complete techs=${techMap.size}`);
    
    // 3. SECURITY ANALYSIS
    console.log(`[techStackScan] Starting vulnerability enrichment for ${techMap.size} technologies...`);
    const analysisMap = new Map<string, EnhancedSecAnalysis>();
    for (const [slug, tech] of techMap) {
      analysisMap.set(slug, await analyzeSecurityEnhanced(tech));
    }
    console.log(`[techStackScan] Vulnerability enrichment complete`);
    
    // 4. ARTIFACT GENERATION
    let artCount = 0;
    let supplyFindings = 0;
    
    for (const [slug, tech] of techMap) {
      const analysis = analysisMap.get(slug)!;
      const artId = await insertArtifact({
        type: 'technology',
        val_text: `${tech.name}${tech.version ? ' v' + tech.version : ''}`,
        severity: RISK_TO_SEVERITY[analysis.risk],
        meta: { 
          scan_id: scanId, 
          scan_module: 'techStackScan', 
          technology: tech, 
          security: analysis, 
          ecosystem: detectEcosystem(tech), 
          supply_chain_score: analysis.supplyChainScore, 
          version_accuracy: analysis.versionAccuracy, 
          active_verification: analysis.activeVerification 
        }
      });
      artCount++;
      
      if (analysis.vulns.length) {
        await insertFinding({
          scan_id: scanId,
          type: 'EXPOSED_SERVICE',
          severity: 'HIGH',
          title: `${analysis.vulns.length} vulnerabilities detected`,
          description: analysis.advice.join(' '),
          data: { vulnerabilities: summarizeVulnIds(analysis.vulns, CONFIG.MAX_VULN_IDS_PER_FINDING) }
        });
      } else if (analysis.advice.length && (analysis.risk === 'MEDIUM' || analysis.risk === 'HIGH' || analysis.risk === 'CRITICAL')) {
        // Only create findings for meaningful security concerns, not just "detected"
        await insertFinding({
          scan_id: scanId,
          type: 'TECHNOLOGY_RISK',
          severity: analysis.risk,
          title: analysis.advice.join(' '),
          description: `Security concern: ${tech.name}${tech.version ? ' v'+tech.version : ''}. Supply chain score: ${analysis.supplyChainScore.toFixed(1)}/10.`,
          data: { technology: tech.name, version: tech.version, supply_chain_score: analysis.supplyChainScore }
        });
      }
      
      if (analysis.supplyChainScore >= 7.0) {
        supplyFindings++;
      }
    }

    // Generate discovered_endpoints artifact for dependent modules
    const endpointsForDeps = allTargets.map(url => ({
      url,
      method: 'GET',
      status: 200,
      title: 'Discovered endpoint',
      contentType: 'text/html',
      contentLength: 0,
      requiresAuth: false,
      isStaticContent: false,
      allowsStateChanging: false
    }));

    await insertArtifact({
      type: 'discovered_endpoints',
      val_text: `${endpointsForDeps.length} endpoints discovered for tech scanning`,
      severity: 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'techStackScan',
        endpoints: endpointsForDeps,
        total_count: endpointsForDeps.length
      }
    });

    // Generate discovered_web_assets artifact for dependent modules  
    await insertArtifact({
      type: 'discovered_web_assets',
      val_text: `${allTargets.length} web assets discovered for tech scanning`,
      severity: 'INFO',
      meta: {
        scan_id: scanId,
        scan_module: 'techStackScan',
        assets: allTargets.map(url => ({ url, type: 'html' })),
        total_count: allTargets.length
      }
    });

    // 5. METRICS AND SUMMARY
    const runMs = Date.now() - start;
    const targetsFailed = detectionsPerUrl.filter(r => r.error).length;
    const detectorsUsed = new Set<string>();
    
    // Track which detectors found something
    for (const tech of allDetections) {
      if (tech.categories?.includes('httpx')) detectorsUsed.add('httpx');
      if (tech.categories?.includes('WhatWeb')) detectorsUsed.add('whatweb');
      if (tech.categories?.includes('Headers')) detectorsUsed.add('headers');
      if (tech.categories?.includes('Favicon')) detectorsUsed.add('favicon');
    }
    
    const metrics: ScanMetrics = {
      totalTargets: targetResult.total,
      targetsScanned: detectionsPerUrl.length,
      targetsFailed,
      uniqueTechs: techMap.size,
      supplyFindings,
      runMs,
      circuitBreakerTripped,
      detectorsUsed: Array.from(detectorsUsed)
    };

    await insertArtifact({
      type: 'scan_summary',
      val_text: `Tech scan: ${metrics.uniqueTechs} techs, ${supplyFindings} supply chain risks`,
      severity: 'INFO',
      meta: { 
        scan_id: scanId, 
        scan_module: 'techStackScan', 
        metrics, 
        scan_duration_ms: runMs 
      }
    });
    
    console.log(`[techStackScan] COMPLETE in ${runMs}ms with ${techMap.size} technologies`);
    log(`techstack=complete domain=${domain} artifacts=${artCount} runtime=${runMs}ms`);
    return artCount;

  } catch (error) {
    console.log(`[techStackScan] ERROR: ${(error as Error).message}`);
    console.log(`[techStackScan] Stack trace:`, (error as Error).stack);
    log(`techstack=error domain=${domain} error="${(error as Error).message}"`);
    await insertArtifact({
      type: 'scan_error',
      val_text: `Tech stack scan failed: ${(error as Error).message}`,
      severity: 'HIGH',
      meta: { 
        scan_id: scanId, 
        scan_module: 'techStackScan', 
        error: (error as Error).message, 
        stack: (error as Error).stack 
      }
    });
    return 0;
  }
}