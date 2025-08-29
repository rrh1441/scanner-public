/*
 * =============================================================================
 * MODULE: webArchiveScanner.ts
 * =============================================================================
 * Web archive discovery using Wayback Machine and other archive services.
 * Discovers historical URLs that might have exposed secrets or sensitive files.
 * =============================================================================
 */

import { httpClient } from '../net/httpClient.js';
import * as https from 'node:https';
import { insertArtifact } from '../core/artifactStore.js';
import { logLegacy as log } from '../core/logger.js';

// Configuration - Tier-based scanning
const TIER1_MAX_ARCHIVE_URLS = 20;      // Quick scan: 20 URLs
const TIER2_MAX_ARCHIVE_URLS = 200;     // Deep dive: 200 URLs
const TIER1_MAX_YEARS_BACK = 1;         // Quick scan: 1 year
const TIER2_MAX_YEARS_BACK = 3;         // Deep dive: 3 years
const MAX_CONCURRENT_FETCHES = 8;      // Reduced from 12 for stability
const ARCHIVE_TIMEOUT = 8000;           // Reduced timeout
const WAYBACK_API_URL = 'https://web.archive.org/cdx/search/cdx';

interface ArchiveUrl {
    url: string;
    timestamp: string;
    statusCode: string;
    mimeType: string;
    digest: string;
    originalUrl: string;
    confidence: 'high' | 'medium' | 'low';
    reason: string;
}

interface ArchiveResult {
    url: string;
    content: string;
    size: number;
    accessible: boolean;
    archiveTimestamp: string;
    archiveUrl?: string;
    confidence?: 'high' | 'medium' | 'low';
    reason?: string;
}

const USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15'
];

/**
 * Get historical URLs from Wayback Machine
 */
async function getWaybackUrls(domain: string, tier: 'tier1' | 'tier2' = 'tier1'): Promise<ArchiveUrl[]> {
    const archiveUrls: ArchiveUrl[] = [];
    
    try {
        const currentYear = new Date().getFullYear();
        const maxYearsBack = tier === 'tier1' ? TIER1_MAX_YEARS_BACK : TIER2_MAX_YEARS_BACK;
        const maxUrls = tier === 'tier1' ? TIER1_MAX_ARCHIVE_URLS : TIER2_MAX_ARCHIVE_URLS;
        const startYear = currentYear - maxYearsBack;
        
        log(`[webArchiveScanner] ${tier.toUpperCase()} scan: Querying Wayback Machine for ${domain} (${startYear}-${currentYear})`);
        
        // Query Wayback Machine CDX API
        const response = await httpClient.get(WAYBACK_API_URL, {
            params: {
                url: `*.${domain}/*`,
                output: 'json',
                collapse: 'digest',
                from: startYear.toString(),
                to: currentYear.toString(),
                limit: maxUrls * 2, // Get more to filter down
                filter: 'statuscode:200'
            },
            timeout: ARCHIVE_TIMEOUT
        });
        
        if (!Array.isArray(response.data) || response.data.length < 2) {
            log('[webArchiveScanner] No archive data found');
            return archiveUrls;
        }
        
        // Skip header row and process results
        const results = response.data.slice(1);
        log(`[webArchiveScanner] Found ${results.length} archived URLs`);
        
        for (const row of results) {
            if (archiveUrls.length >= maxUrls) break;
            
            const [urlkey, timestamp, originalUrl, mimeType, statusCode, digest] = row;
            
            if (!originalUrl || !timestamp) continue;
            
            // Filter for interesting URLs
            const confidence = categorizeUrl(originalUrl);
            if (confidence === 'low') continue;
            
            archiveUrls.push({
                url: `https://web.archive.org/web/${timestamp}/${originalUrl}`,
                timestamp,
                statusCode,
                mimeType: mimeType || 'unknown',
                digest,
                originalUrl,
                confidence,
                reason: getUrlReason(originalUrl)
            });
        }
        
        // Sort by confidence and recency
        archiveUrls.sort((a, b) => {
            const confidenceScore = { high: 3, medium: 2, low: 1 };
            const aScore = confidenceScore[a.confidence];
            const bScore = confidenceScore[b.confidence];
            
            if (aScore !== bScore) return bScore - aScore;
            return b.timestamp.localeCompare(a.timestamp);
        });
        
        log(`[webArchiveScanner] Filtered to ${archiveUrls.length} high-interest archived URLs`);
        
    } catch (error) {
        log('[webArchiveScanner] Error querying Wayback Machine:', (error as Error).message);
    }
    
    const maxUrls = tier === 'tier1' ? TIER1_MAX_ARCHIVE_URLS : TIER2_MAX_ARCHIVE_URLS;
    return archiveUrls.slice(0, maxUrls);
}

/**
 * Categorize URLs by likelihood of containing secrets
 */
function categorizeUrl(url: string): 'high' | 'medium' | 'low' {
    const urlLower = url.toLowerCase();
    
    // High-value patterns
    const highPatterns = [
        /\.env/i,
        /config\.(json|js|php|yaml|yml)/i,
        /settings\.(json|js|php|yaml|yml)/i,
        /\.git\//i,
        /\.svn\//i,
        /backup/i,
        /\.sql$/i,
        /\.zip$/i,
        /\.tar\.gz$/i,
        /admin/i,
        /debug/i,
        /test/i,
        /staging/i,
        /dev/i,
        /api.*config/i,
        /swagger\.(json|yaml|yml)/i,
        /openapi\.(json|yaml|yml)/i,
        /\.map$/i, // Source maps
        /package\.json$/i,
        /composer\.json$/i,
        /requirements\.txt$/i,
        /Gemfile/i,
        /pom\.xml$/i,
        /web\.config$/i,
        /\.htaccess$/i,
        /wp-config\.php$/i,
        /database\.(php|json|yml|yaml)/i
    ];
    
    // Medium-value patterns
    const mediumPatterns = [
        /\.(js|css)$/i,
        /\/api\//i,
        /\/docs?\//i,
        /\/help/i,
        /\/info/i,
        /\.(php|asp|aspx|jsp)$/i,
        /robots\.txt$/i,
        /sitemap\.xml$/i,
        /\.well-known\//i
    ];
    
    for (const pattern of highPatterns) {
        if (pattern.test(urlLower)) return 'high';
    }
    
    for (const pattern of mediumPatterns) {
        if (pattern.test(urlLower)) return 'medium';
    }
    
    return 'low';
}

/**
 * Get reason why URL is interesting
 */
function getUrlReason(url: string): string {
    const urlLower = url.toLowerCase();
    
    if (/\.env/i.test(url)) return 'Environment configuration file';
    if (/config\./i.test(url)) return 'Configuration file';
    if (/settings\./i.test(url)) return 'Settings file';
    if (/\.git\//i.test(url)) return 'Git repository exposure';
    if (/backup/i.test(url)) return 'Backup file';
    if (/admin/i.test(url)) return 'Admin interface';
    if (/debug/i.test(url)) return 'Debug endpoint';
    if (/swagger|openapi/i.test(url)) return 'API documentation';
    if (/\.map$/i.test(url)) return 'Source map file';
    if (/package\.json$/i.test(url)) return 'Package manifest';
    if (/wp-config\.php$/i.test(url)) return 'WordPress configuration';
    if (/database\./i.test(url)) return 'Database configuration';
    if (/api/i.test(url)) return 'API endpoint';
    
    return 'Potentially sensitive file';
}

/**
 * Fetch archived content that might contain secrets
 */
async function fetchArchivedContent(archiveUrls: ArchiveUrl[]): Promise<ArchiveResult[]> {
    const results: ArchiveResult[] = [];
    const httpsAgent = new https.Agent({ rejectUnauthorized: false });
    
    // Process URLs in chunks to control concurrency
    for (let i = 0; i < archiveUrls.length; i += MAX_CONCURRENT_FETCHES) {
        const chunk = archiveUrls.slice(i, i + MAX_CONCURRENT_FETCHES);
        
        const chunkResults = await Promise.allSettled(
            chunk.map(async (archiveUrl) => {
                try {
                    log(`[webArchiveScanner] Fetching archived content: ${archiveUrl.originalUrl}`);
                    
                    const response = await httpClient.get(archiveUrl.url, {
                        timeout: ARCHIVE_TIMEOUT,
                        maxContentLength: 5 * 1024 * 1024, // 5MB max
                        httpsAgent,
                        headers: {
                            'User-Agent': USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)]
                        },
                        validateStatus: () => true
                    });
                    
                    if (response.status === 200 && response.data) {
                        const content = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
                        
                        return {
                            url: archiveUrl.originalUrl,
                            content: content.length > 100000 ? content.substring(0, 100000) + '...[truncated]' : content,
                            size: content.length,
                            accessible: true,
                            archiveTimestamp: archiveUrl.timestamp,
                            archiveUrl: archiveUrl.url,
                            confidence: archiveUrl.confidence,
                            reason: archiveUrl.reason
                        };
                    }
                    
                } catch (error) {
                    log(`[webArchiveScanner] Failed to fetch ${archiveUrl.originalUrl}:`, (error as Error).message);
                }
                
                return null;
            })
        );
        
        // Process chunk results
        for (const result of chunkResults) {
            if (result.status === 'fulfilled' && result.value) {
                results.push(result.value);
                log(`[webArchiveScanner] Successfully fetched archived content: ${result.value.url}`);
            }
        }
        
        // Rate limiting delay
        if (i + MAX_CONCURRENT_FETCHES < archiveUrls.length) {
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
    
    return results;
}

/**
 * Check if gau tool is available for alternative archive discovery
 */
async function checkGauAvailability(): Promise<boolean> {
    try {
        const { execFile } = await import('node:child_process');
        const { promisify } = await import('node:util');
        const exec = promisify(execFile);
        
        await exec('gau', ['--version']);
        return true;
    } catch (error) {
        return false;
    }
}

/**
 * Use gau tool for additional archive discovery
 */
async function getGauUrls(domain: string): Promise<string[]> {
    try {
        log('[webArchiveScanner] Using gau for additional archive discovery');
        
        const { execFile } = await import('node:child_process');
        const { promisify } = await import('node:util');
        const exec = promisify(execFile);
        
        const { stdout } = await exec('gau', [
            domain,
            '--threads', '5',
            '--timeout', '30',
            '--retries', '2'
        ], { timeout: 60000 });
        
        const urls = stdout.trim().split('\n').filter(Boolean);
        log(`[webArchiveScanner] gau discovered ${urls.length} URLs`);
        
        // Filter for interesting URLs
        return urls.filter(url => categorizeUrl(url) !== 'low').slice(0, 100);
        
    } catch (error) {
        log('[webArchiveScanner] Error using gau:', (error as Error).message);
        return [];
    }
}

/**
 * Main Web Archive Scanner function
 */
export async function runWebArchiveScanner(job: { domain: string; scanId?: string; tier?: 'tier1' | 'tier2' }): Promise<number> {
    const tier = job.tier || 'tier1';
    log(`[webArchiveScanner] Starting ${tier.toUpperCase()} web archive discovery for ${job.domain}`);
    
    if (!job.scanId) {
        log('[webArchiveScanner] No scanId provided - skipping archive scanning');
        return 0;
    }
    
    try {
        let totalFindings = 0;
        
        // 1. Get historical URLs from Wayback Machine
        const waybackUrls = await getWaybackUrls(job.domain, tier);
        
        // 2. Try gau tool if available (tier2 only for comprehensive scans)
        const gauAvailable = await checkGauAvailability();
        let gauUrls: string[] = [];
        if (gauAvailable && tier === 'tier2') {
            gauUrls = await getGauUrls(job.domain);
        } else if (tier === 'tier1') {
            log('[webArchiveScanner] Skipping gau in tier1 for speed');
        } else {
            log('[webArchiveScanner] gau tool not available - using Wayback Machine only');
        }
        
        // 3. Fetch archived content for high-value URLs
        const archivedContent = await fetchArchivedContent(waybackUrls);
        
        // 4. Save archived content as web assets for secret scanning
        if (archivedContent.length > 0) {
            await insertArtifact({
                type: 'discovered_web_assets',
                val_text: `Discovered ${archivedContent.length} archived web assets for secret scanning on ${job.domain}`,
                severity: 'INFO',
                meta: {
                    scan_id: job.scanId,
                    scan_module: 'webArchiveScanner',
                    assets: archivedContent.map(content => ({
                        url: content.url,
                        type: 'html',
                        size: content.size,
                        confidence: content.confidence,
                        source: 'web_archive',
                        content: content.content,
                        mimeType: 'text/html',
                        archive_timestamp: content.archiveTimestamp,
                        archive_url: content.archiveUrl,
                        reason: content.reason
                    }))
                }
            });
            
            totalFindings += archivedContent.length;
        }
        
        // 5. Save historical URL list for reference
        if (waybackUrls.length > 0 || gauUrls.length > 0) {
            await insertArtifact({
                type: 'historical_urls',
                val_text: `Discovered ${waybackUrls.length + gauUrls.length} historical URLs for ${job.domain}`,
                severity: 'INFO',
                meta: {
                    scan_id: job.scanId,
                    scan_module: 'webArchiveScanner',
                    wayback_urls: waybackUrls,
                    gau_urls: gauUrls,
                    years_scanned: tier === 'tier1' ? TIER1_MAX_YEARS_BACK : TIER2_MAX_YEARS_BACK,
                    total_historical_urls: waybackUrls.length + gauUrls.length,
                    tier: tier
                }
            });
        }
        
        log(`[webArchiveScanner] Completed ${tier} web archive discovery: ${totalFindings} assets found from ${waybackUrls.length + gauUrls.length} historical URLs`);
        return totalFindings;
        
    } catch (error) {
        log('[webArchiveScanner] Error in web archive discovery:', (error as Error).message);
        return 0;
    }
}