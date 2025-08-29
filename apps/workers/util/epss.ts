/*
 * =============================================================================
 * MODULE: epss.ts
 * =============================================================================
 * Fetches EPSS (Exploit Prediction Scoring System) scores from FIRST.org API
 * Provides exploit likelihood predictions for CVEs
 * 
 * Key features:
 * - Batch fetching for multiple CVEs
 * - LRU caching to minimize API calls
 * - No authentication required (public API)
 * =============================================================================
 */

import axios from 'axios';
import { UnifiedCache } from '../modules/techCache/index.js';
import { logLegacy as log } from '../core/logger.js';

const EPSS_API_BASE = 'https://api.first.org/data/v1/epss';
const CACHE_TTL = 86400000; // 24 hours in milliseconds (EPSS updates daily)
const BATCH_SIZE = 100; // API supports up to 100 CVEs per request

// Initialize cache instance
const cache = new UnifiedCache({
  maxEntries: 10000,
  maxMemoryMB: 50,
  defaultTtlMs: CACHE_TTL
});

export interface EPSSScore {
  cve: string;
  epss: number;      // Probability (0-1) of exploitation in next 30 days
  percentile: number; // Percentile ranking among all CVEs
  date: string;      // Date of the score
}

/**
 * Fetches EPSS scores for a list of CVE IDs
 * @param cveIds Array of CVE IDs (e.g., ['CVE-2021-44228', 'CVE-2021-45046'])
 * @returns Map of CVE ID to EPSS score (0-1 scale)
 */
export async function getEpssScores(cveIds: string[]): Promise<Map<string, number>> {
  const scores = new Map<string, number>();
  
  if (!cveIds || cveIds.length === 0) {
    return scores;
  }

  // Deduplicate CVE IDs
  const uniqueCves = [...new Set(cveIds)];
  const uncachedCves: string[] = [];

  // Check cache first
  for (const cveId of uniqueCves) {
    const cacheKey = { type: 'epss' as const, cveId };
    const cached = await cache.get<EPSSScore>(cacheKey);
    
    if (cached && cached.epss !== undefined) {
      scores.set(cveId, cached.epss);
      log(`[epss] Cache hit for ${cveId}: ${cached.epss}`);
    } else {
      uncachedCves.push(cveId);
    }
  }

  // If all scores were cached, return early
  if (uncachedCves.length === 0) {
    return scores;
  }

  log(`[epss] Fetching scores for ${uncachedCves.length} uncached CVEs`);

  // Batch fetch uncached CVEs
  for (let i = 0; i < uncachedCves.length; i += BATCH_SIZE) {
    const batch = uncachedCves.slice(i, i + BATCH_SIZE);
    
    try {
      const response = await axios.get(EPSS_API_BASE, {
        params: {
          cve: batch.join(',')
        },
        timeout: 10000
      });

      if (response.data?.status === 'OK' && response.data?.data) {
        for (const item of response.data.data) {
          const epssScore = parseFloat(item.epss);
          const percentile = parseFloat(item.percentile);
          
          scores.set(item.cve, epssScore);
          
          // Cache the score
          const cacheKey = { type: 'epss' as const, cveId: item.cve };
          await cache.set(cacheKey, {
            cve: item.cve,
            epss: epssScore,
            percentile,
            date: item.date
          }, CACHE_TTL);
          
          log(`[epss] Fetched ${item.cve}: score=${epssScore.toFixed(4)}, percentile=${percentile.toFixed(4)}`);
        }
      }
    } catch (error) {
      log(`[epss] API error for batch:`, (error as Error).message);
      // Continue with partial results
    }
  }

  // Set missing CVEs to 0 (no EPSS data available)
  for (const cveId of uncachedCves) {
    if (!scores.has(cveId)) {
      scores.set(cveId, 0);
      
      // Cache the absence of data
      const cacheKey = { type: 'epss' as const, cveId };
      await cache.set(cacheKey, { 
        cve: cveId,
        epss: 0,
        percentile: 0,
        date: new Date().toISOString()
      }, CACHE_TTL);
    }
  }

  return scores;
}

/**
 * Get a single EPSS score
 * @param cveId CVE ID (e.g., 'CVE-2021-44228')
 * @returns EPSS score (0-1 scale) or 0 if not found
 */
export async function getEpssScore(cveId: string): Promise<number> {
  const scores = await getEpssScores([cveId]);
  return scores.get(cveId) || 0;
}

/**
 * Determines risk multiplier based on EPSS score
 * Used for adjusting EAL calculations
 */
export function getEpssRiskMultiplier(epssScore: number): number {
  if (epssScore > 0.9) return 10.0;  // 90%+ exploitation probability
  if (epssScore > 0.5) return 5.0;   // 50%+ exploitation probability
  if (epssScore > 0.1) return 2.0;   // 10%+ exploitation probability
  return 1.0; // Default multiplier
}