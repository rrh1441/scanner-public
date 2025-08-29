/*
 * =============================================================================
 * MODULE: rateLimitScan.ts (Consolidated & Refactored)
 * =============================================================================
 * This module replaces zapRateIp.ts, zapRateTest.ts, and zapRateToken.ts
 * with a single, comprehensive rate limit testing engine.
 *
 * Key Improvements:
 * 1.  **Integrated Endpoint Discovery:** Uses the output from the endpointDiscovery
 * module to find the best targets (login, API, auth endpoints) for testing.
 * 2.  **Structured Testing:** Establishes a baseline to confirm a rate limit
 * exists before attempting a wide range of bypass techniques.
 * 3.  **Expanded Bypass Techniques:** Tests for bypasses via IP spoofing headers,
 * HTTP method switching, path variations, and parameter pollution.
 * 4.  **Consolidated Findings:** Groups all successful bypass methods for a
 * single endpoint into one actionable artifact.
 * =============================================================================
 */

import { httpClient } from '../net/httpClient.js';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as log } from '../core/logger.js';

const REQUEST_BURST_COUNT = 25; // Number of requests to send to trigger a baseline limit.
const REQUEST_TIMEOUT = 5000;

interface DiscoveredEndpoint {
  url: string;
  path: string;
  method?: string; // Original method, may not be present
}

interface RateLimitTestResult {
    bypassed: boolean;
    technique: string;
    details: string;
    statusCode?: number;
}

const IP_SPOOFING_HEADERS = [
    { 'X-Forwarded-For': '127.0.0.1' }, { 'X-Real-IP': '127.0.0.1' },
    { 'X-Client-IP': '127.0.0.1' }, { 'X-Originating-IP': '127.0.0.1' },
    { 'X-Remote-IP': '127.0.0.1' }, { 'Forwarded': 'for=127.0.0.1' },
    { 'X-Forwarded': '127.0.0.1' }, { 'Forwarded-For': '127.0.0.1' },
];

/**
 * Fetches interesting endpoints discovered by other modules.
 */
async function getTestableEndpoints(scanId: string, domain: string): Promise<DiscoveredEndpoint[]> {
    try {
    // Pool query removed for GCP migration - starting fresh
    const rows: any[] = [];
    const result = { rows: [] as any[] };        if (result.rows.length > 0 && result.rows[0].meta.endpoints) {
            const endpoints = result.rows[0].meta.endpoints as DiscoveredEndpoint[];
            // Filter for endpoints most likely to have rate limits
            return endpoints.filter(e => 
                e.path.includes('login') || e.path.includes('register') || 
                e.path.includes('auth') || e.path.includes('api') || e.path.includes('password')
            );
        }
    } catch (e) {
        log('[rateLimitScan] [ERROR] Could not fetch endpoints from database:', (e as Error).message);
    }
    // Fallback if no discovered endpoints are found
    log('[rateLimitScan] No discovered endpoints found, using fallback list.');
    return [
        { url: `https://${domain}/login`, path: '/login' },
        { url: `https://${domain}/api/login`, path: '/api/login' },
        { url: `https://${domain}/auth/login`, path: '/auth/login' },
        { url: `https://${domain}/password/reset`, path: '/password/reset' },
    ];
}

/**
 * Sends a burst of requests to establish a baseline and see if a rate limit is triggered.
 * Now includes inter-burst delays and full response distribution analysis.
 */
async function establishBaseline(endpoint: DiscoveredEndpoint): Promise<{ hasRateLimit: boolean; responseDistribution: Record<number, number> }> {
    log(`[rateLimitScan] Establishing baseline for ${endpoint.url}...`);
    
    const responseDistribution: Record<number, number> = {};
    const chunkSize = 5; // Send requests in smaller chunks
    const interBurstDelay = 100; // 100ms delay between chunks
    
    for (let chunk = 0; chunk < REQUEST_BURST_COUNT / chunkSize; chunk++) {
        const promises = [];
        
        // Send chunk of requests
        for (let i = 0; i < chunkSize; i++) {
            promises.push(
                httpClient.post(endpoint.url, {u:'test',p:'test'}, { 
                    timeout: REQUEST_TIMEOUT, 
                    validateStatus: () => true 
                }).catch(error => ({ 
                    status: error.response?.status || 0 
                }))
            );
        }
        
        const responses = await Promise.allSettled(promises);
        
        // Collect response status codes
        for (const response of responses) {
            if (response.status === 'fulfilled') {
                const statusCode = response.value.status;
                responseDistribution[statusCode] = (responseDistribution[statusCode] || 0) + 1;
            }
        }
        
        // Add delay between chunks (except for the last chunk)
        if (chunk < (REQUEST_BURST_COUNT / chunkSize) - 1) {
            await new Promise(resolve => setTimeout(resolve, interBurstDelay));
        }
    }
    
    log(`[rateLimitScan] Response distribution for ${endpoint.url}:`, responseDistribution);
    
    // Analyze the response distribution to determine if rate limiting is present
    const has429 = responseDistribution[429] > 0;
    const hasProgressiveFailure = Object.keys(responseDistribution).length > 2; // Multiple status codes suggest rate limiting
    const successRate = (responseDistribution[200] || 0) / REQUEST_BURST_COUNT;
    
    // Rate limiting is likely present if:
    // 1. We got 429 responses, OR
    // 2. We have progressive failure patterns (multiple status codes), OR  
    // 3. Success rate drops significantly (< 80%)
    const hasRateLimit = has429 || hasProgressiveFailure || successRate < 0.8;
    
    return { hasRateLimit, responseDistribution };
}

/**
 * Attempts to bypass a rate limit using various techniques.
 * Now includes delays between bypass attempts to avoid interference.
 */
async function testBypassTechniques(endpoint: DiscoveredEndpoint): Promise<RateLimitTestResult[]> {
    const results: RateLimitTestResult[] = [];
    const testPayload = { user: 'testuser', pass: 'testpass' };
    const bypassDelay = 200; // 200ms delay between bypass attempts

    // 1. IP Spoofing Headers
    for (const header of IP_SPOOFING_HEADERS) {
        try {
            const response = await httpClient.post(endpoint.url, testPayload, { 
                headers: header, 
                timeout: REQUEST_TIMEOUT, 
                validateStatus: () => true 
            });
            if (response.status !== 429) {
                results.push({ 
                    bypassed: true, 
                    technique: 'IP_SPOOFING_HEADER', 
                    details: `Header: ${Object.keys(header)[0]}`, 
                    statusCode: response.status 
                });
            }
            await new Promise(resolve => setTimeout(resolve, bypassDelay));
        } catch { /* ignore */ }
    }

    // 2. HTTP Method Switching
    try {
        const response = await httpClient.get(endpoint.url, { 
            params: testPayload, 
            timeout: REQUEST_TIMEOUT, 
            validateStatus: () => true 
        });
        if (response.status !== 429) {
            results.push({ 
                bypassed: true, 
                technique: 'HTTP_METHOD_SWITCH', 
                details: 'Used GET instead of POST', 
                statusCode: response.status 
            });
        }
        await new Promise(resolve => setTimeout(resolve, bypassDelay));
    } catch { /* ignore */ }
    
    // 3. Path Variation
    for (const path of [`${endpoint.path}/`, `${endpoint.path}.json`, endpoint.path.toUpperCase()]) {
        try {
            const url = new URL(endpoint.url);
            url.pathname = path;
            const response = await httpClient.post(url.toString(), testPayload, { 
                timeout: REQUEST_TIMEOUT, 
                validateStatus: () => true 
            });
            if (response.status !== 429) {
                results.push({ 
                    bypassed: true, 
                    technique: 'PATH_VARIATION', 
                    details: `Path used: ${path}`, 
                    statusCode: response.status 
                });
            }
            await new Promise(resolve => setTimeout(resolve, bypassDelay));
        } catch { /* ignore */ }
    }

    return results;
}

export async function runRateLimitScan(job: { domain: string, scanId: string }): Promise<number> {
    log('[rateLimitScan] Starting comprehensive rate limit scan for', job.domain);
    let findingsCount = 0;

    const endpoints = await getTestableEndpoints(job.scanId, job.domain);
    if (endpoints.length === 0) {
        log('[rateLimitScan] No testable endpoints found. Skipping.');
        return 0;
    }

    log(`[rateLimitScan] Found ${endpoints.length} endpoints to test.`);

    for (const endpoint of endpoints) {
        const { hasRateLimit, responseDistribution } = await establishBaseline(endpoint);

        if (!hasRateLimit) {
            log(`[rateLimitScan] No baseline rate limit detected on ${endpoint.url}.`);
            const artifactId = await insertArtifact({
                type: 'rate_limit_missing',
                val_text: `No rate limiting detected on endpoint: ${endpoint.path}`,
                severity: 'MEDIUM',
                src_url: endpoint.url,
                meta: { 
                    scan_id: job.scanId, 
                    scan_module: 'rateLimitScan', 
                    endpoint: endpoint.path,
                    response_distribution: responseDistribution
                }
            });
            await insertFinding({
                scan_id: job.scanId,
                type: 'MISSING_RATE_LIMITING',
                severity: 'HIGH',
                title: `Missing rate limiting on ${endpoint.path}`,
                description: `The endpoint did not show rate limiting behavior after ${REQUEST_BURST_COUNT} rapid requests. Response distribution: ${JSON.stringify(responseDistribution)}`,
                data: {
                    recommendation: `Implement strict rate limiting on this endpoint (${endpoint.path}) to prevent brute-force attacks.`,
                    endpoint_path: endpoint.path,
                    request_count: REQUEST_BURST_COUNT,
                    response_distribution: responseDistribution
                }
            });
            findingsCount++;
            continue;
        }

        log(`[rateLimitScan] Baseline rate limit detected on ${endpoint.url}. Testing for bypasses...`);
        
        // Wait a bit before testing bypasses to let any rate limits reset
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        const bypassResults = await testBypassTechniques(endpoint);
        const successfulBypasses = bypassResults.filter(r => r.bypassed);

        if (successfulBypasses.length > 0) {
            log(`[rateLimitScan] [VULNERABLE] Found ${successfulBypasses.length} bypass techniques for ${endpoint.url}`);
            const artifactId = await insertArtifact({
                type: 'rate_limit_bypass',
                val_text: `Rate limit bypass possible on endpoint: ${endpoint.path}`,
                severity: 'HIGH',
                src_url: endpoint.url,
                meta: {
                    scan_id: job.scanId,
                    scan_module: 'rateLimitScan',
                    endpoint: endpoint.path,
                    bypasses: successfulBypasses,
                    baseline_distribution: responseDistribution
                }
            });
            await insertFinding({
                scan_id: job.scanId,
                type: 'RATE_LIMIT_BYPASS',
                severity: 'HIGH',
                title: `Rate limiting bypass detected on ${endpoint.path}`,
                description: `Successful bypass techniques: ${successfulBypasses.map(b => b.technique).join(', ')}.`,
                data: {
                    recommendation: `The rate limiting implementation on ${endpoint.path} can be bypassed. Ensure that the real client IP is correctly identified and that logic is not easily evaded by simple transformations.`,
                    endpoint_path: endpoint.path,
                    bypass_techniques: successfulBypasses.map(b => b.technique),
                    bypass_details: successfulBypasses
                }
            });
            findingsCount++;
        } else {
            log(`[rateLimitScan] Rate limiting on ${endpoint.url} appears to be robust.`);
        }
    }

    await insertArtifact({
        type: 'scan_summary',
        val_text: `Rate limit scan completed: ${findingsCount} issues found`,
        severity: 'INFO',
        meta: {
            scan_id: job.scanId,
            scan_module: 'rateLimitScan',
            total_findings: findingsCount,
            endpoints_tested: endpoints.length,
            timestamp: new Date().toISOString()
        }
    });

    return findingsCount;
}
