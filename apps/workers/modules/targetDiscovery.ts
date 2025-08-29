/* =============================================================================
 * MODULE: targetDiscovery.ts
 * =============================================================================
 * Target discovery and classification for security scanning.
 * Handles URL discovery, asset type classification, and third-party origin detection.
 * =============================================================================
 */

import { pool } from '../core/artifactStore.js';
import { logLegacy as rootLog } from '../core/logger.js';
import { withPage } from '../util/dynamicBrowser.js';
// Removed import for deleted module

const log = (...m: unknown[]) => rootLog('[targetDiscovery]', ...m);

// Configuration
const CONFIG = {
  PAGE_TIMEOUT_MS: 25_000,
  MAX_THIRD_PARTY_REQUESTS: 200,
  MAX_DISCOVERED_ENDPOINTS: 100,
} as const;

// Types
export interface ClassifiedTarget {
  url: string;
  assetType: 'html' | 'nonHtml';
}

export interface TargetDiscoveryConfig {
  maxThirdPartyRequests?: number;
  pageTimeout?: number;
  maxDiscoveredEndpoints?: number;
  enablePuppeteer?: boolean;
}

export interface TargetDiscoveryResult {
  primary: ClassifiedTarget[];
  thirdParty: ClassifiedTarget[];
  total: number;
  metrics: {
    htmlCount: number;
    nonHtmlCount: number;
    discoveredCount: number;
    thirdPartySkipped: boolean;
  };
}

export class TargetDiscovery {
  constructor(private config: TargetDiscoveryConfig = {}) {}

  /* Filter out problematic domains that cause issues with scanners */
  private isProblematicDomain(hostname: string): boolean {
    const problematicDomains = [
      // CDNs and large platforms that scanners struggle with
      'google.com', 'www.google.com', 'gstatic.com', 'www.gstatic.com',
      'googleapis.com', 'fonts.googleapis.com', 'fonts.gstatic.com',
      'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com',
      'cloudflare.com', 'amazonaws.com', 'azure.com',
      // Content delivery networks
      'cdn.', 'cdnjs.', 'jsdelivr.', 'unpkg.com',
      'contentful.com', 'ctfassets.net'
    ];
    
    return problematicDomains.some(domain => 
      hostname === domain || hostname.endsWith('.' + domain) || hostname.startsWith(domain)
    );
  }

  /* Build enhanced target list with asset type classification */
  async buildTargets(scanId: string, domain: string): Promise<ClassifiedTarget[]> {
    const baseTargets = [`https://${domain}`, `https://www.${domain}`];
    const targets = new Map<string, ClassifiedTarget>();
    
    // Add base domain targets (always HTML)
    baseTargets.forEach(url => {
      targets.set(url, { url, assetType: 'html' });
    });
    
    try {
    // Pool query removed for GCP migration - starting fresh
    const rows: any[] = [];
    const result = { rows: [] };      
      // Add discovered endpoints with classification (limit for performance)
      const maxEndpoints = this.config.maxDiscoveredEndpoints || CONFIG.MAX_DISCOVERED_ENDPOINTS;
      const discoveredCount = rows[0]?.urls?.length || 0;
      
      rows[0]?.urls?.slice(0, maxEndpoints).forEach((url: string) => {
        if (url && typeof url === 'string' && url !== 'null' && url.startsWith('http')) {
          // Additional validation to prevent problematic URLs
          try {
            const urlObj = new URL(url);
            // Skip if URL is valid and not problematic
            if (urlObj.hostname && !this.isProblematicDomain(urlObj.hostname)) {
              const assetType = 'html';
              targets.set(url, { url, assetType });
            }
          } catch {
            // Skip invalid URLs
          }
        }
      });
      
      const htmlCount = Array.from(targets.values()).filter(t => t.assetType === 'html').length;
      const nonHtmlCount = Array.from(targets.values()).filter(t => t.assetType === 'nonHtml').length;
      log(`buildTargets discovered=${discoveredCount} total=${targets.size} (html=${htmlCount}, nonHtml=${nonHtmlCount})`);
      
    } catch (error) {
      log(`buildTargets error: ${(error as Error).message}`);
    }
    
    return Array.from(targets.values());
  }

  /* Third-party sub-resource discovery using shared Puppeteer */
  async discoverThirdPartyOrigins(domain: string): Promise<ClassifiedTarget[]> {
    // Check if Puppeteer is enabled
    const puppeteerEnabled = this.config.enablePuppeteer !== false && process.env.ENABLE_PUPPETEER !== '0';
    if (!puppeteerEnabled) {
      log(`thirdParty=skipped domain=${domain} reason="puppeteer_disabled"`);
      return [];
    }
    
    try {
      return await withPage(async (page) => {
        const origins = new Set<string>();
        
        // Track network requests
        await page.setRequestInterception(true);
        page.on('request', (request) => {
          const url = request.url();
          try {
            const urlObj = new URL(url);
            const origin = urlObj.origin;
            
            // Filter to third-party origins (different eTLD+1) and exclude problematic domains
            if (!origin.includes(domain) && 
                !origin.includes('localhost') && 
                !origin.includes('127.0.0.1') &&
                !this.isProblematicDomain(urlObj.hostname)) {
              origins.add(origin);
            }
          } catch {
            // Invalid URL, ignore
          }
          
          // Continue the request
          request.continue();
        });
        
        // Navigate and wait for resources with fallback
        const pageTimeout = this.config.pageTimeout || CONFIG.PAGE_TIMEOUT_MS;
        try {
          await page.goto(`https://${domain}`, { 
            timeout: pageTimeout,
            waitUntil: 'networkidle2' 
          });
        } catch (navError) {
          // Fallback: try with less strict wait condition
          log(`thirdParty=navigation_fallback domain=${domain} error="${(navError as Error).message}"`);
          await page.goto(`https://${domain}`, { 
            timeout: pageTimeout,
            waitUntil: 'domcontentloaded' 
          });
        }
        
        // Limit results to prevent excessive discovery and classify each one
        const maxRequests = this.config.maxThirdPartyRequests || CONFIG.MAX_THIRD_PARTY_REQUESTS;
        const limitedOrigins = Array.from(origins).slice(0, maxRequests);
        const classifiedTargets = limitedOrigins.map(url => ({
          url,
          assetType: 'html' as const
        }));
        
        const htmlCount = classifiedTargets.length; // All third-party origins are treated as HTML
        const nonHtmlCount = 0; // No non-HTML origins in this discovery method
        log(`thirdParty=discovered domain=${domain} total=${limitedOrigins.length} (html=${htmlCount}, nonHtml=${nonHtmlCount})`);
        
        return classifiedTargets;
      });
      
    } catch (error) {
      log(`thirdParty=error domain=${domain} error="${(error as Error).message}"`);
      return [];
    }
  }

  /* Main target discovery orchestrator */
  async discoverTargets(scanId: string, domain: string, providedTargets?: string[]): Promise<TargetDiscoveryResult> {
    let primary: ClassifiedTarget[] = [];
    let thirdParty: ClassifiedTarget[] = [];
    let thirdPartySkipped = false;

    if (providedTargets) {
      // Convert provided targets to classified format (assume HTML for compatibility)
      primary = providedTargets.map(url => ({ url, assetType: 'html' as const }));
      thirdPartySkipped = true;
    } else {
      // Discover targets from various sources
      const [primaryTargets, thirdPartyTargets] = await Promise.all([
        this.buildTargets(scanId, domain),
        this.discoverThirdPartyOrigins(domain)
      ]);
      
      primary = primaryTargets;
      thirdParty = thirdPartyTargets;
    }

    const allTargets = [...primary, ...thirdParty];
    const htmlCount = allTargets.filter(t => t.assetType === 'html').length;
    const nonHtmlCount = allTargets.filter(t => t.assetType === 'nonHtml').length;

    return {
      primary,
      thirdParty,
      total: allTargets.length,
      metrics: {
        htmlCount,
        nonHtmlCount,
        discoveredCount: primary.length + thirdParty.length,
        thirdPartySkipped
      }
    };
  }

  /* Extract just HTML targets for scanner compatibility */
  getHtmlTargets(targets: ClassifiedTarget[]): string[] {
    return targets
      .filter(t => t.assetType === 'html')
      .map(t => t.url);
  }

  /* Extract non-HTML targets (typically bypassed by most scanners) */
  getNonHtmlTargets(targets: ClassifiedTarget[]): ClassifiedTarget[] {
    return targets.filter(t => t.assetType === 'nonHtml');
  }
}

// Create default target discovery instance
export function createTargetDiscovery(config?: TargetDiscoveryConfig) {
  return new TargetDiscovery(config);
} 