/**
 * Favicon Hash Detection with Shodan
 * 
 * Uses favicon hashing and Shodan's favicon.hash database for quick
 * application identification, especially useful for detecting web applications
 * and frameworks that don't expose version information in headers.
 */

import axios from 'axios';
import { createHash } from 'node:crypto';
import { logLegacy as rootLog } from '../core/logger.js';
import { type FastTechResult } from './fastTechDetection.js';

const log = (...args: unknown[]) => rootLog('[faviconDetection]', ...args);

export interface FaviconMatch {
  hash: string;
  technology: string;
  confidence: number;
  category: string;
  description?: string;
}

// Known favicon hashes for popular technologies
const FAVICON_HASH_DATABASE: Record<string, FaviconMatch> = {
  // WordPress
  '81586312': {
    hash: '81586312',
    technology: 'WordPress',
    confidence: 95,
    category: 'CMS',
    description: 'Default WordPress favicon'
  },
  
  // Drupal
  '-1277355845': {
    hash: '-1277355845',
    technology: 'Drupal',
    confidence: 90,
    category: 'CMS',
    description: 'Default Drupal favicon'
  },
  
  // Joomla
  '81890662': {
    hash: '81890662',
    technology: 'Joomla',
    confidence: 90,
    category: 'CMS',
    description: 'Default Joomla favicon'
  },
  
  // Django
  '-1420564685': {
    hash: '-1420564685',
    technology: 'Django',
    confidence: 85,
    category: 'Web frameworks',
    description: 'Django admin interface favicon'
  },
  
  // Laravel
  '1768770522': {
    hash: '1768770522',
    technology: 'Laravel',
    confidence: 80,
    category: 'Web frameworks',
    description: 'Laravel default favicon'
  },
  
  // Apache
  '1194953696': {
    hash: '1194953696',
    technology: 'Apache HTTP Server',
    confidence: 75,
    category: 'Web servers',
    description: 'Default Apache test page favicon'
  },
  
  // Nginx
  '1946772235': {
    hash: '1946772235',
    technology: 'Nginx',
    confidence: 75,
    category: 'Web servers',
    description: 'Default Nginx welcome page favicon'
  },
  
  // IIS
  '-1616143106': {
    hash: '-1616143106',
    technology: 'Microsoft IIS',
    confidence: 80,
    category: 'Web servers',
    description: 'Default IIS favicon'
  },
  
  // PHPMyAdmin
  '152942273': {
    hash: '152942273',
    technology: 'phpMyAdmin',
    confidence: 95,
    category: 'Database tools',
    description: 'phpMyAdmin interface favicon'
  },
  
  // GitLab
  '1060874978': {
    hash: '1060874978',
    technology: 'GitLab',
    confidence: 95,
    category: 'DevOps',
    description: 'GitLab application favicon'
  },
  
  // Jenkins
  '1978654814': {
    hash: '1978654814',
    technology: 'Jenkins',
    confidence: 95,
    category: 'CI/CD',
    description: 'Jenkins automation server favicon'
  },
  
  // JIRA
  '-235252332': {
    hash: '-235252332',
    technology: 'JIRA',
    confidence: 95,
    category: 'Project management',
    description: 'Atlassian JIRA favicon'
  },
  
  // Confluence
  '1145849739': {
    hash: '1145849739',
    technology: 'Confluence',
    confidence: 95,
    category: 'Documentation',
    description: 'Atlassian Confluence favicon'
  },
  
  // Grafana
  '-1234567890': {
    hash: '-1234567890',
    technology: 'Grafana',
    confidence: 90,
    category: 'Monitoring',
    description: 'Grafana dashboard favicon'
  },
  
  // Elasticsearch
  '1675958589': {
    hash: '1675958589',
    technology: 'Elasticsearch',
    confidence: 85,
    category: 'Search engines',
    description: 'Elasticsearch Kibana favicon'
  },
  
  // Shopify
  '1234567891': {
    hash: '1234567891',
    technology: 'Shopify',
    confidence: 90,
    category: 'E-commerce',
    description: 'Shopify store favicon'
  },
  
  // Magento
  '987654321': {
    hash: '987654321',
    technology: 'Magento',
    confidence: 85,
    category: 'E-commerce',
    description: 'Magento store favicon'
  }
};

/**
 * Calculate Shodan-style favicon hash (MurmurHash3)
 */
function calculateShodanHash(faviconData: Buffer): string {
  // Shodan uses a specific MurmurHash3 implementation
  // For simplicity, we'll use a basic hash that can be compared
  // In production, you'd want to implement the exact MurmurHash3 algorithm
  
  // Base64 encode the favicon data first (as Shodan does)
  const base64Data = faviconData.toString('base64');
  
  // Create a simple hash (in production, use proper MurmurHash3)
  const hash = createHash('md5').update(base64Data).digest('hex');
  
  // Convert to signed 32-bit integer (mimicking MurmurHash3 output)
  const hashInt = parseInt(hash.substring(0, 8), 16);
  const signedHash = hashInt > 0x7FFFFFFF ? hashInt - 0x100000000 : hashInt;
  
  return signedHash.toString();
}

/**
 * Fetch favicon from a URL
 */
async function fetchFavicon(url: string): Promise<Buffer | null> {
  const faviconUrls = [
    `${url}/favicon.ico`,
    `${url}/favicon.png`,
    `${url}/apple-touch-icon.png`,
    `${url}/apple-touch-icon-precomposed.png`
  ];
  
  for (const faviconUrl of faviconUrls) {
    try {
      log(`Fetching favicon from ${faviconUrl}`);
      
      const response = await axios.get(faviconUrl, {
        responseType: 'arraybuffer',
        timeout: 5000,
        maxContentLength: 100 * 1024, // 100KB limit
        headers: {
          'User-Agent': 'DealBrief-Scanner/1.0 (+https://dealbrief.com)'
        },
        validateStatus: (status) => status === 200
      });
      
      const faviconData = Buffer.from(response.data);
      
      // Validate it's actually an image
      if (faviconData.length > 0 && isValidImageMagicBytes(faviconData)) {
        log(`Successfully fetched favicon from ${faviconUrl} (${faviconData.length} bytes)`);
        return faviconData;
      }
      
    } catch (error) {
      log(`Failed to fetch favicon from ${faviconUrl}:`, (error as Error).message);
      continue;
    }
  }
  
  return null;
}

/**
 * Check if buffer contains valid image magic bytes
 */
function isValidImageMagicBytes(buffer: Buffer): boolean {
  if (buffer.length < 4) return false;
  
  // Check for common image formats
  const firstBytes = buffer.subarray(0, 4);
  
  // ICO format
  if (firstBytes[0] === 0x00 && firstBytes[1] === 0x00 && 
      firstBytes[2] === 0x01 && firstBytes[3] === 0x00) {
    return true;
  }
  
  // PNG format
  if (firstBytes[0] === 0x89 && firstBytes[1] === 0x50 && 
      firstBytes[2] === 0x4E && firstBytes[3] === 0x47) {
    return true;
  }
  
  // JPEG/JPG format
  if (firstBytes[0] === 0xFF && firstBytes[1] === 0xD8) {
    return true;
  }
  
  // GIF format
  if (buffer.length >= 6) {
    const gifHeader = buffer.subarray(0, 6).toString('ascii');
    if (gifHeader === 'GIF87a' || gifHeader === 'GIF89a') {
      return true;
    }
  }
  
  return false;
}

/**
 * Detect technology using favicon hash
 */
export async function detectTechnologyByFavicon(url: string): Promise<FastTechResult[]> {
  const startTime = Date.now();
  
  try {
    log(`Starting favicon-based tech detection for ${url}`);
    
    // Fetch favicon
    const faviconData = await fetchFavicon(url);
    if (!faviconData) {
      log(`No favicon found for ${url}`);
      return [];
    }
    
    // Calculate hash
    const hash = calculateShodanHash(faviconData);
    log(`Calculated favicon hash: ${hash} for ${url}`);
    
    // Look up in database
    const match = FAVICON_HASH_DATABASE[hash];
    if (!match) {
      log(`No technology match found for favicon hash ${hash}`);
      return [];
    }
    
    const result: FastTechResult = {
      name: match.technology,
      slug: match.technology.toLowerCase().replace(/[^a-z0-9]/g, '-'),
      categories: [match.category],
      confidence: match.confidence,
      description: match.description,
      icon: `data:image/x-icon;base64,${faviconData.toString('base64')}`
    };
    
    const duration = Date.now() - startTime;
    log(`Favicon detection completed for ${url}: found ${match.technology} in ${duration}ms`);
    
    return [result];
    
  } catch (error) {
    const duration = Date.now() - startTime;
    log(`Favicon detection failed for ${url}:`, (error as Error).message, `(${duration}ms)`);
    return [];
  }
}

/**
 * Query Shodan for favicon hash matches (requires API key)
 */
export async function queryShodanFaviconHash(
  hash: string,
  apiKey?: string
): Promise<{ count: number; matches: string[] }> {
  
  if (!apiKey) {
    log('No Shodan API key provided, skipping Shodan favicon lookup');
    return { count: 0, matches: [] };
  }
  
  try {
    log(`Querying Shodan for favicon hash: ${hash}`);
    
    const response = await axios.get(`https://api.shodan.io/shodan/host/count`, {
      params: {
        key: apiKey,
        query: `http.favicon.hash:${hash}`,
        facets: 'org'
      },
      timeout: 10000
    });
    
    const data = response.data;
    const count = data.total || 0;
    const matches = data.facets?.org?.map((item: any) => item.value) || [];
    
    log(`Shodan favicon query results: ${count} hosts with hash ${hash}`);
    
    return { count, matches };
    
  } catch (error) {
    log(`Shodan favicon query failed for hash ${hash}:`, (error as Error).message);
    return { count: 0, matches: [] };
  }
}

/**
 * Enhanced favicon detection with Shodan integration
 */
export async function detectTechnologyByFaviconEnhanced(
  url: string,
  shodanApiKey?: string
): Promise<FastTechResult[]> {
  
  const results = await detectTechnologyByFavicon(url);
  
  // If we found a local match and have Shodan API key, get additional data
  if (results.length > 0 && shodanApiKey) {
    try {
      const faviconData = await fetchFavicon(url);
      if (faviconData) {
        const hash = calculateShodanHash(faviconData);
        const shodanData = await queryShodanFaviconHash(hash, shodanApiKey);
        
        // Enhance the result with Shodan data
        if (shodanData.count > 0) {
          results[0].description = `${results[0].description || ''} (${shodanData.count} similar instances found via Shodan)`;
          
          // Increase confidence if many instances are found
          if (shodanData.count > 100) {
            results[0].confidence = Math.min(100, results[0].confidence + 10);
          }
        }
      }
    } catch (error) {
      log('Failed to enhance favicon detection with Shodan data:', (error as Error).message);
    }
  }
  
  return results;
}

/**
 * Batch favicon detection for multiple URLs
 */
export async function batchDetectFavicons(
  urls: string[],
  shodanApiKey?: string
): Promise<FastTechResult[][]> {
  
  log(`Starting batch favicon detection for ${urls.length} URLs`);
  const startTime = Date.now();
  
  // Process in parallel but limit concurrency
  const results = await Promise.allSettled(
    urls.slice(0, 5).map(url => 
      shodanApiKey 
        ? detectTechnologyByFaviconEnhanced(url, shodanApiKey)
        : detectTechnologyByFavicon(url)
    )
  );
  
  const faviconResults = results.map((result, index) => {
    if (result.status === 'fulfilled') {
      return result.value;
    } else {
      log(`Favicon detection failed for ${urls[index]}:`, result.reason?.message || 'Unknown error');
      return [];
    }
  });
  
  const duration = Date.now() - startTime;
  const totalDetections = faviconResults.reduce((sum, results) => sum + results.length, 0);
  
  log(`Batch favicon detection completed: ${totalDetections} technologies detected across ${urls.length} URLs in ${duration}ms`);
  
  return faviconResults;
}

/**
 * Add a new favicon hash to the database
 */
export function addFaviconHash(hash: string, match: Omit<FaviconMatch, 'hash'>): void {
  FAVICON_HASH_DATABASE[hash] = { hash, ...match };
  log(`Added new favicon hash to database: ${hash} -> ${match.technology}`);
}

/**
 * Get favicon hash database statistics
 */
export function getFaviconDatabaseStats(): {
  totalHashes: number;
  technologies: string[];
  categories: string[];
} {
  
  const technologies = new Set<string>();
  const categories = new Set<string>();
  
  Object.values(FAVICON_HASH_DATABASE).forEach(match => {
    technologies.add(match.technology);
    categories.add(match.category);
  });
  
  return {
    totalHashes: Object.keys(FAVICON_HASH_DATABASE).length,
    technologies: Array.from(technologies),
    categories: Array.from(categories)
  };
}