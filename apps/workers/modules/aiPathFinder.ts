/*
 * =============================================================================
 * MODULE: aiPathFinder.ts
 * =============================================================================
 * AI-powered intelligent path generation for discovering sensitive files and endpoints.
 * Uses OpenAI to generate context-aware paths based on detected technology stack.
 * =============================================================================
 */

import { OpenAI } from 'openai';
import { httpClient } from '../net/httpClient.js';
import * as https from 'node:https';
import { insertArtifact } from '../core/artifactStore.js';
import { logLegacy as log } from '../core/logger.js';

// Configuration
const AI_MODEL = 'gpt-4.1-mini-2025-04-14'; // Using specified model
const MAX_PATHS_TO_GENERATE = 50;
const MAX_CONCURRENT_PROBES = 8;
const PROBE_TIMEOUT = 8000;

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15'
];

interface TechStack {
  frameworks: string[];
  languages: string[];
  servers: string[];
  databases: string[];
  cms: string[];
  cloud_services: string[];
}

interface GeneratedPath {
  path: string;
  confidence: 'high' | 'medium' | 'low';
  reasoning: string;
  category: string;
}

interface ProbeResult {
  url: string;
  statusCode: number;
  size: number;
  contentType: string;
  accessible: boolean;
}

/**
 * Get technology stack from previous scan results
 */
async function getTechStack(scanId: string, domain: string): Promise<TechStack> {
    const defaultStack: TechStack = {
        frameworks: [],
        languages: [],
        servers: [],
        databases: [],
        cms: [],
        cloud_services: []
    };

    try {
        // Query for tech stack artifacts from previous scans
    // Pool query removed for GCP migration - starting fresh
    const rows: any[] = [];
    const result = { rows: rows };
        for (const row of result.rows) {
            const meta = row.meta;
            
            // Extract technology information from various formats
            if (meta.technologies) {
                defaultStack.frameworks.push(...(meta.technologies.frameworks || []));
                defaultStack.languages.push(...(meta.technologies.languages || []));
                defaultStack.servers.push(...(meta.technologies.servers || []));
                defaultStack.databases.push(...(meta.technologies.databases || []));
                defaultStack.cms.push(...(meta.technologies.cms || []));
                defaultStack.cloud_services.push(...(meta.technologies.cloud || []));
            }
            
            // Handle flat technology lists
            if (meta.technology) {
                const tech = meta.technology.toLowerCase();
                if (tech.includes('react') || tech.includes('vue') || tech.includes('angular')) {
                    defaultStack.frameworks.push(tech);
                } else if (tech.includes('node') || tech.includes('python') || tech.includes('php')) {
                    defaultStack.languages.push(tech);
                } else if (tech.includes('nginx') || tech.includes('apache') || tech.includes('cloudflare')) {
                    defaultStack.servers.push(tech);
                }
            }
        }

        // Deduplicate arrays
        Object.keys(defaultStack).forEach(key => {
            defaultStack[key as keyof TechStack] = [...new Set(defaultStack[key as keyof TechStack])];
        });

        log(`[aiPathFinder] Detected tech stack: ${JSON.stringify(defaultStack)}`);
        
    } catch (error) {
        log('[aiPathFinder] Error querying tech stack:', (error as Error).message);
    }

    return defaultStack;
}

/**
 * Generate intelligent paths using OpenAI
 */
async function generateIntelligentPaths(domain: string, techStack: TechStack): Promise<GeneratedPath[]> {
    if (!process.env.OPENAI_API_KEY) {
        log('[aiPathFinder] No OpenAI API key - using fallback path generation');
        return generateFallbackPaths(techStack);
    }

    console.log(`[aiPathFinder] Preparing OpenAI request for ${domain}...`);
    const apiStart = Date.now();
    try {
        const openai = new OpenAI({ timeout: 30000 });
        
        // Sanitize domain input to prevent AI prompt injection
        const safeDomain = domain.replace(/[^a-zA-Z0-9.-]/g, '').slice(0, 253);
        const safeTechStack = JSON.stringify(techStack).slice(0, 2000); // Limit tech stack size
        
        const prompt = `You are a cybersecurity expert specializing in web application reconnaissance. Your task is to generate a list of potential file paths that might expose sensitive information or provide insight into the application's structure.

TARGET INFORMATION:
- Domain: ${safeDomain}
- Detected Technologies: ${safeTechStack}

REQUIREMENTS:
1. Generate ${MAX_PATHS_TO_GENERATE} potential paths that are likely to exist on this specific technology stack
2. Focus on paths that might contain:
   - Configuration files (.env, config.json, settings.yaml)
   - Build artifacts (webpack configs, source maps, package files)
   - Development/staging endpoints
   - API documentation (swagger.json, openapi.yaml)
   - Admin interfaces
   - Debug endpoints
   - Backup files
   - Log files
   - Framework-specific paths

3. Tailor paths to the detected technologies. For example:
   - React: /_next/static/, /build/, /static/js/
   - Vue: /dist/, /.nuxt/
   - Node.js: /package.json, /node_modules/
   - WordPress: /wp-config.php, /wp-admin/
   - Laravel: /.env, /storage/logs/
   - Django: /settings.py, /debug/

4. Return ONLY a JSON array with this exact format:
[
  {
    "path": "/example/path",
    "confidence": "high|medium|low",
    "reasoning": "Brief explanation why this path might exist",
    "category": "config|build|api|admin|debug|backup|logs|other"
  }
]

IMPORTANT: Return ONLY the JSON array, no additional text or explanation.`;

        const response = await openai.chat.completions.create({
            model: AI_MODEL,
            messages: [
                {
                    role: 'system',
                    content: 'You are a cybersecurity expert. Return only valid JSON arrays as requested.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            temperature: 0.7,
            max_tokens: 2000
        });
        
        console.log(`[aiPathFinder] OpenAI response received in ${Date.now() - apiStart}ms`);

        const content = response.choices[0]?.message?.content?.trim();
        if (!content) {
            throw new Error('Empty response from OpenAI');
        }

        // Parse the JSON response
        const generatedPaths: GeneratedPath[] = JSON.parse(content);
        
        // Validate the response format
        if (!Array.isArray(generatedPaths)) {
            throw new Error('Response is not an array');
        }

        // Filter and validate paths
        const validPaths = generatedPaths.filter(path => 
            path.path && 
            path.confidence && 
            path.reasoning && 
            path.category &&
            path.path.startsWith('/')
        );

        // Log each AI-suggested path
        validPaths.forEach(path => {
            console.log(`[aiPathFinder] AI suggested path: ${path.path} (${path.confidence} confidence)`);
        });

        log(`[aiPathFinder] Generated ${validPaths.length} AI-powered paths`);
        return validPaths.slice(0, MAX_PATHS_TO_GENERATE);

    } catch (error) {
        log('[aiPathFinder] Error generating AI paths:', (error as Error).message);
        log('[aiPathFinder] Falling back to rule-based path generation');
        return generateFallbackPaths(techStack);
    }
}

/**
 * Fallback path generation when AI is unavailable
 */
function generateFallbackPaths(techStack: TechStack): GeneratedPath[] {
    const paths: GeneratedPath[] = [];
    
    // Universal high-value paths
    const universalPaths = [
        { path: '/.env', confidence: 'high' as const, reasoning: 'Common environment file', category: 'config' },
        { path: '/config.json', confidence: 'high' as const, reasoning: 'Common config file', category: 'config' },
        { path: '/package.json', confidence: 'medium' as const, reasoning: 'Node.js package info', category: 'build' },
        { path: '/swagger.json', confidence: 'medium' as const, reasoning: 'API documentation', category: 'api' },
        { path: '/api/config', confidence: 'medium' as const, reasoning: 'API configuration endpoint', category: 'api' }
    ];
    
    paths.push(...universalPaths);
    
    // Framework-specific paths
    if (techStack.frameworks.some(f => f.toLowerCase().includes('react'))) {
        paths.push(
            { path: '/_next/static/chunks/webpack.js', confidence: 'high', reasoning: 'Next.js webpack config', category: 'build' },
            { path: '/build/static/js/main.js', confidence: 'medium', reasoning: 'React build artifact', category: 'build' }
        );
    }
    
    if (techStack.frameworks.some(f => f.toLowerCase().includes('vue'))) {
        paths.push(
            { path: '/.nuxt/dist/', confidence: 'medium', reasoning: 'Nuxt.js build directory', category: 'build' },
            { path: '/dist/js/app.js', confidence: 'medium', reasoning: 'Vue build artifact', category: 'build' }
        );
    }
    
    if (techStack.cms.some(c => c.toLowerCase().includes('wordpress'))) {
        paths.push(
            { path: '/wp-config.php', confidence: 'high', reasoning: 'WordPress configuration', category: 'config' },
            { path: '/wp-admin/admin.php', confidence: 'medium', reasoning: 'WordPress admin interface', category: 'admin' }
        );
    }
    
    log(`[aiPathFinder] Generated ${paths.length} fallback paths`);
    return paths;
}

/**
 * Probe generated paths to see which ones are accessible
 */
async function probeGeneratedPaths(baseUrl: string, paths: GeneratedPath[]): Promise<ProbeResult[]> {
    const results: ProbeResult[] = [];
    const httpsAgent = new https.Agent({ rejectUnauthorized: false });
    
    // Process paths in chunks to control concurrency
    for (let i = 0; i < paths.length; i += MAX_CONCURRENT_PROBES) {
        const chunk = paths.slice(i, i + MAX_CONCURRENT_PROBES);
        
        const chunkResults = await Promise.allSettled(
            chunk.map(async (pathInfo) => {
                const url = `${baseUrl}${pathInfo.path}`;
                
                try {
                    const response = await httpClient.head(url, {
                        timeout: PROBE_TIMEOUT,
                        httpsAgent,
                        headers: {
                            'User-Agent': USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)]
                        },
                        validateStatus: () => true, // Don't throw on 4xx/5xx
                        maxRedirects: 3
                    });
                    
                    const accessible = response.status < 400;
                    if (accessible) {
                        log(`[aiPathFinder] Found accessible path: ${url} (${response.status})`);
                    }
                    
                    return {
                        url,
                        statusCode: response.status,
                        size: parseInt(response.headers['content-length'] || '0'),
                        contentType: response.headers['content-type'] || 'unknown',
                        accessible,
                        pathInfo
                    };
                    
                } catch (error) {
                    return {
                        url,
                        statusCode: 0,
                        size: 0,
                        contentType: 'error',
                        accessible: false,
                        pathInfo,
                        error: (error as Error).message
                    };
                }
            })
        );
        
        // Process chunk results
        for (const result of chunkResults) {
            if (result.status === 'fulfilled' && result.value.accessible) {
                results.push(result.value);
            }
        }
        
        // Rate limiting delay
        if (i + MAX_CONCURRENT_PROBES < paths.length) {
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    }
    
    return results;
}

/**
 * Main AI Path Finder function
 */
export async function runAiPathFinder(job: { domain: string; scanId?: string }): Promise<number> {
  console.log(`[aiPathFinder] START at ${new Date().toISOString()}`);
    const start = Date.now();
    log(`[aiPathFinder] Starting AI-powered path discovery for ${job.domain}`);
    
    if (!job.scanId) {
        log('[aiPathFinder] No scanId provided - skipping AI path finding');
        return 0;
    }
    
    const baseUrl = `https://${job.domain}`;
    
    try {
        // 1. Get technology stack from previous scans
        const techStack = await getTechStack(job.scanId, job.domain);
        
        // 2. Generate intelligent paths using AI
        const generatedPaths = await generateIntelligentPaths(job.domain, techStack);
        
        // 3. Probe the generated paths
        const accessiblePaths = await probeGeneratedPaths(baseUrl, generatedPaths);
        
        // 4. Save results as artifacts for other modules to use
        if (accessiblePaths.length > 0) {
            await insertArtifact({
                type: 'ai_discovered_paths',
                val_text: `AI discovered ${accessiblePaths.length} accessible paths on ${job.domain}`,
                severity: 'INFO',
                meta: {
                    scan_id: job.scanId,
                    scan_module: 'aiPathFinder',
                    accessible_paths: accessiblePaths,
                    generated_paths_count: generatedPaths.length,
                    tech_stack: techStack,
                    ai_model_used: AI_MODEL,
                    success_rate: `${((accessiblePaths.length / generatedPaths.length) * 100).toFixed(1)}%`
                }
            });
            
            // Save high-confidence paths as web assets for secret scanning
            for (const pathResult of accessiblePaths.filter(p => p.contentType.includes('text') || p.contentType.includes('json'))) {
                await insertArtifact({
                    type: 'discovered_web_assets',
                    val_text: `AI-discovered web asset: ${pathResult.url}`,
                    severity: 'INFO',
                    meta: {
                        scan_id: job.scanId,
                        scan_module: 'aiPathFinder',
                        assets: [{
                            url: pathResult.url,
                            type: pathResult.contentType.includes('json') ? 'json' : 'other',
                            confidence: 'high',
                            source: 'ai_generated',
                            mimeType: pathResult.contentType,
                            size: pathResult.size
                        }]
                    }
                });
            }
        }
        
        console.log(`[aiPathFinder] COMPLETE: Found ${accessiblePaths.length} AI-suggested paths in ${Date.now() - start}ms`);
        log(`[aiPathFinder] Completed AI path discovery: ${accessiblePaths.length}/${generatedPaths.length} paths accessible`);
        return accessiblePaths.length;
        
    } catch (error) {
        console.log(`[aiPathFinder] ERROR: ${(error as Error).message}`);
        console.log(`[aiPathFinder] Stack trace:`, (error as Error).stack);
        log('[aiPathFinder] Error in AI path discovery:', (error as Error).message);
        return 0;
    }
}