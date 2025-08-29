/*
 * =============================================================================
 * MODULE: tierConfig.ts
 * =============================================================================
 * Configuration for two-tier scanning system:
 * - Tier 1: Quick scan (3-5 minutes) for immediate security assessment
 * - Tier 2: Deep dive (10-15 minutes) for comprehensive analysis
 * =============================================================================
 */

export interface ScanTier {
    name: 'tier1' | 'tier2';
    description: string;
    targetTime: string;
}

export const SCAN_TIERS: Record<'tier1' | 'tier2', ScanTier> = {
    tier1: {
        name: 'tier1',
        description: 'Quick security assessment',
        targetTime: '3-5 minutes'
    },
    tier2: {
        name: 'tier2', 
        description: 'Comprehensive deep analysis',
        targetTime: '10-15 minutes'
    }
};

// Endpoint Discovery Configuration
export const ENDPOINT_DISCOVERY_CONFIG = {
    tier1: {
        maxCrawlDepth: 2,
        maxConcurrentRequests: 12,      // Reduced from 20 to 12 for stability
        requestTimeout: 3000,           // Reduced from 8000
        maxJsFileSize: 2 * 1024 * 1024, // 2MB max
        maxFilesPerCrawl: 25,           // Reduced from 35
        maxTotalCrawlSize: 20 * 1024 * 1024, // 20MB total
        maxPages: 50,                   // Reduced from 75
        highValuePathsOnly: true        // Focus on likely targets
    },
    tier2: {
        maxCrawlDepth: 3,               // Deeper crawling
        maxConcurrentRequests: 10,      // Reduced from 15 for stability  
        requestTimeout: 8000,           // Full timeout
        maxJsFileSize: 5 * 1024 * 1024, // 5MB max
        maxFilesPerCrawl: 75,           // Full coverage
        maxTotalCrawlSize: 50 * 1024 * 1024, // 50MB total
        maxPages: 150,                  // Comprehensive crawling
        highValuePathsOnly: false       // Scan everything
    }
};

// TruffleHog Configuration
export const TRUFFLEHOG_CONFIG = {
    tier1: {
        maxContentSize: 2 * 1024 * 1024,    // 2MB per file
        maxFilesToScan: 20,                  // Top 20 files only
        skipLargeFiles: true,
        prioritizeJavaScript: true
    },
    tier2: {
        maxContentSize: 10 * 1024 * 1024,   // 10MB per file
        maxFilesToScan: 100,                 // More comprehensive
        skipLargeFiles: false,
        prioritizeJavaScript: false
    }
};

// Database Port Scan Configuration
export const DB_PORT_SCAN_CONFIG = {
    tier1: {
        maxConcurrentScans: 8,              // Reduced from 12 to 8 for stability
        nmapTimeout: 30000,                 // Reduced from 60000
        nucleiTimeout: 60000,               // Reduced from 300000
        skipSlowScripts: true
    },
    tier2: {
        maxConcurrentScans: 6,              // Reduced from 8 to 6 for stability
        nmapTimeout: 120000,                // Full timeout
        nucleiTimeout: 300000,              // Full timeout
        skipSlowScripts: false
    }
};

// Web Archive Scanner Configuration
export const WEB_ARCHIVE_CONFIG = {
    tier1: {
        maxArchiveUrls: 20,                 // Quick scan: 20 URLs
        maxYearsBack: 1,                    // Recent year only
        maxConcurrentFetches: 8,            // Reduced from 12 to 8 for stability
        archiveTimeout: 5000,               // Quick timeout
        skipGau: false                      // Keep gau for speed
    },
    tier2: {
        maxArchiveUrls: 200,                // Deep dive: 200 URLs  
        maxYearsBack: 3,                    // 3 years back
        maxConcurrentFetches: 6,            // Reduced from 8 to 6 for stability
        archiveTimeout: 15000,              // Full timeout
        skipGau: false
    }
};

// AI Path Finder Configuration
export const AI_PATH_FINDER_CONFIG = {
    tier1: {
        maxPathsToGenerate: 25,             // Reduced from 50
        maxConcurrentProbes: 10,            // Reduced from 15 to 10 for stability
        probeTimeout: 4000,                 // Reduced from 8000
        aiTimeout: 15000,                   // Quick AI response
        fallbackOnly: false                 // Use AI for better results
    },
    tier2: {
        maxPathsToGenerate: 75,             // More comprehensive
        maxConcurrentProbes: 8,             // Reduced from 10 to 8 for stability
        probeTimeout: 8000,                 // Full timeout
        aiTimeout: 30000,                   // Full AI timeout
        fallbackOnly: false
    }
};

// Module execution order and parallelization
export const MODULE_EXECUTION_PLAN = {
    tier1: {
        // Phase 1: Independent discovery (parallel)
        phase1: [
            'endpointDiscovery'
            // Skip webArchiveScanner for speed in tier1
        ],
        // Phase 2: Dependent scanning (parallel) 
        phase2: [
            'trufflehog',       // Depends on endpointDiscovery
            'dbPortScan'        // Can run in parallel with trufflehog
        ],
        estimatedTime: '3-5 minutes'
    },
    tier2: {
        // Phase 1: Independent discovery (parallel)
        phase1: [
            'endpointDiscovery',
            'webArchiveScanner', 
            'aiPathFinder'
        ],
        // Phase 2: Dependent scanning (parallel)
        phase2: [
            'trufflehog',       // Depends on discovery modules
            'dbPortScan'        // Depends on trufflehog secrets
        ],
        estimatedTime: '10-15 minutes'
    }
};

/**
 * Get configuration for a specific module and tier
 */
export function getModuleConfig<T>(module: string, tier: 'tier1' | 'tier2'): T {
    const configs: Record<string, any> = {
        endpointDiscovery: ENDPOINT_DISCOVERY_CONFIG,
        trufflehog: TRUFFLEHOG_CONFIG,
        dbPortScan: DB_PORT_SCAN_CONFIG,
        webArchiveScanner: WEB_ARCHIVE_CONFIG,
        aiPathFinder: AI_PATH_FINDER_CONFIG
    };
    
    return configs[module]?.[tier] as T;
}

/**
 * Check if a module should be skipped for a tier
 */
export function shouldSkipModule(module: string, tier: 'tier1' | 'tier2'): boolean {
    // Skip web archive scanner in tier1 for speed
    if (tier === 'tier1' && module === 'webArchiveScanner') {
        return true;
    }
    
    return false;
}