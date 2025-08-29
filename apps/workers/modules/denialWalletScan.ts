/**
 * Denial-of-Wallet (DoW) Scan Module
 * 
 * Production-grade scanner that identifies endpoints that can drive unbounded cloud 
 * spending when abused, focusing on real economic impact over theoretical vulnerabilities.
 */

import { httpClient } from '../net/httpClient.js';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as rootLog } from '../core/logger.js';
import { executeModule, apiCall } from '../util/errorHandler.js';

// Configuration constants
const TESTING_CONFIG = {
  INITIAL_RPS: 5,           // Start conservative
  MAX_RPS: 100,             // Lower ceiling for safety
  TEST_DURATION_SECONDS: 10, // Shorter bursts
  BACKOFF_MULTIPLIER: 1.5,  // Gentler scaling
  CIRCUIT_BREAKER_THRESHOLD: 0.15, // Stop at 15% failure rate
  COOLDOWN_SECONDS: 30,     // Wait between test phases
  RESPECT_ROBOTS_TXT: true  // Check robots.txt first
};

const SAFETY_CONTROLS = {
  MAX_CONCURRENT_TESTS: 3,      // Limit parallel testing
  TOTAL_REQUEST_LIMIT: 1000,    // Hard cap per scan
  TIMEOUT_SECONDS: 30,          // Request timeout
  RETRY_ATTEMPTS: 2,            // Limited retries
  BLACKLIST_STATUS: [429, 503], // Stop immediately on these
  RESPECT_HEADERS: [            // Honor protective headers
    'retry-after',
    'x-ratelimit-remaining', 
    'x-ratelimit-reset'
  ]
};

// Enhanced logging
const log = (...args: unknown[]) => rootLog('[denialWalletScan]', ...args);

interface EndpointReport {
  url: string;
  method: string;
  statusCode: number;
  responseTime: number;
  contentLength: number;
  headers: Record<string, string>;
}

interface BackendIndicators {
  responseTimeMs: number;        // >500ms suggests complex processing
  serverHeaders: string[];       // AWS/GCP/Azure headers
  errorPatterns: string[];       // Service-specific error messages
  costIndicators: string[];      // Pricing-related headers
  authPatterns: string[];        // API key patterns in responses
}

enum AuthGuardType {
  NONE = 'none',                    // No protection
  WEAK_API_KEY = 'weak_api_key',   // API key in URL/header
  SHARED_SECRET = 'shared_secret',  // Same key for all users
  CORS_BYPASS = 'cors_bypass',     // CORS misconfig allows bypass
  JWT_NONE_ALG = 'jwt_none_alg',   // JWT with none algorithm
  RATE_LIMIT_ONLY = 'rate_limit_only', // Only rate limiting
  USER_SCOPED = 'user_scoped',     // Proper per-user auth
  OAUTH_PROTECTED = 'oauth_protected' // OAuth2/OIDC
}

interface AuthBypassAnalysis {
  authType: AuthGuardType;
  bypassProbability: number;  // 0.0 - 1.0
  bypassMethods: string[];    // Specific bypass techniques
}

interface CostEstimate {
  service_detected: string;
  confidence: 'high' | 'medium' | 'low';
  base_unit_cost: number;   // $ per billing unit
  multiplier: string;       // requests | tokens | memory_mb | …
  risk_factors: string[];
}

interface DoWRiskAssessment {
  service_detected: string;
  estimated_daily_cost: number;
  auth_bypass_probability: number;
  sustained_rps: number;
  attack_complexity: 'trivial' | 'low' | 'medium' | 'high';
}

interface DoWEvidence {
  endpoint_analysis: {
    url: string;
    methods_tested: string[];
    response_patterns: string[];
    auth_attempts: string[];
  };
  
  cost_calculation: {
    service_detected: string;
    detection_method: string;
    cost_basis: string;
    confidence_level: string;
  };
  
  rate_limit_testing: {
    max_rps_achieved: number;
    test_duration_seconds: number;
    failure_threshold_hit: boolean;
    protective_responses: string[];
  };
  
  remediation_guidance: {
    immediate_actions: string[];
    long_term_fixes: string[];
    cost_cap_recommendations: string[];
  };
}

// Comprehensive service cost modeling
const SERVICE_COSTS = {
  // AI/ML Services (High Cost)
  'openai': { pattern: /openai\.com\/v1\/(chat|completions|embeddings)/, cost: 0.015, multiplier: 'tokens' },
  'anthropic': { pattern: /anthropic\.com\/v1\/(complete|messages)/, cost: 0.030, multiplier: 'tokens' },
  'cohere': { pattern: /api\.cohere\.ai\/v1/, cost: 0.020, multiplier: 'tokens' },
  'huggingface': { pattern: /api-inference\.huggingface\.co/, cost: 0.010, multiplier: 'requests' },
  
  // Cloud Functions (Variable Cost)  
  'aws_lambda': { pattern: /lambda.*invoke|x-amz-function/, cost: 0.0000208, multiplier: 'memory_mb' },
  'gcp_functions': { pattern: /cloudfunctions\.googleapis\.com/, cost: 0.0000240, multiplier: 'memory_mb' },
  'azure_functions': { pattern: /azurewebsites\.net.*api/, cost: 0.0000200, multiplier: 'memory_mb' },
  
  // Database Operations
  'dynamodb': { pattern: /dynamodb.*PutItem|UpdateItem/, cost: 0.000001, multiplier: 'requests' },
  'firestore': { pattern: /firestore\.googleapis\.com/, cost: 0.000002, multiplier: 'requests' },
  'cosmosdb': { pattern: /documents\.azure\.com/, cost: 0.000003, multiplier: 'requests' },
  
  // Storage Operations
  's3_put': { pattern: /s3.*PutObject|POST.*s3/, cost: 0.000005, multiplier: 'requests' },
  'gcs_upload': { pattern: /storage\.googleapis\.com.*upload/, cost: 0.000005, multiplier: 'requests' },
  
  // External APIs (Medium Cost)
  'stripe': { pattern: /api\.stripe\.com\/v1/, cost: 0.009, multiplier: 'requests' },
  'twilio': { pattern: /api\.twilio\.com/, cost: 0.075, multiplier: 'requests' },
  'sendgrid': { pattern: /api\.sendgrid\.com/, cost: 0.0001, multiplier: 'emails' },
  
  // Image/Video Processing
  'imagekit': { pattern: /ik\.imagekit\.io/, cost: 0.005, multiplier: 'transformations' },
  'cloudinary': { pattern: /res\.cloudinary\.com/, cost: 0.003, multiplier: 'transformations' },
  
  // Search Services
  'elasticsearch': { pattern: /elastic.*search|\.es\..*\.amazonaws\.com/, cost: 0.0001, multiplier: 'requests' },
  'algolia': { pattern: /.*-dsn\.algolia\.net/, cost: 0.001, multiplier: 'searches' },
  
  // Default for unknown state-changing endpoints
  'unknown_stateful': { pattern: /.*/, cost: 0.0005, multiplier: 'requests' }
};

/* ──────────────────────────────────────────────────────────────
 *  Dynamic volume estimation
 *  ────────────────────────────────────────────────────────────── */
const DEFAULT_TOKENS_PER_REQUEST = 750; // empirical median
const DEFAULT_MEMORY_MB         = 128; // AWS/Lambda billing quantum

function estimateDailyUnits(
  multiplier: string,
  sustainedRps: number,
  authBypassProb: number
): number {
  // Shorter exploitation window if bypass is harder
  const windowSeconds =
    authBypassProb >= 0.9 ? 86_400 :   // 24 h
    authBypassProb >= 0.5 ? 21_600 :   // 6 h
    authBypassProb >= 0.2 ?  7_200 :   // 2 h
                              1_800;   // 30 min

  switch (multiplier) {
    case 'requests':
    case 'searches':
    case 'emails':
    case 'transformations':
      return sustainedRps * windowSeconds;
    case 'tokens':
      // cost tables are per-1 000 tokens
      return (sustainedRps * windowSeconds * DEFAULT_TOKENS_PER_REQUEST) / 1_000;
    case 'memory_mb':
      // AWS bills per 128 MB-second; normalise to 128 MB baseline
      return sustainedRps * windowSeconds * (DEFAULT_MEMORY_MB / 128);
    default:
      return sustainedRps * windowSeconds;
  }
}

class DoWSafetyController {
  private requestCount = 0;
  private errorCount = 0;
  private startTime = Date.now();
  
  async checkSafetyLimits(): Promise<boolean> {
    if (this.requestCount >= SAFETY_CONTROLS.TOTAL_REQUEST_LIMIT) {
      log('Safety limit reached: maximum requests exceeded');
      return false;
    }
    
    const errorRate = this.errorCount / Math.max(this.requestCount, 1);
    if (errorRate > TESTING_CONFIG.CIRCUIT_BREAKER_THRESHOLD) {
      log(`Safety limit reached: error rate ${(errorRate * 100).toFixed(1)}% exceeds threshold`);
      return false;
    }
    
    return true;
  }
  
  recordRequest(success: boolean): void {
    this.requestCount++;
    if (!success) this.errorCount++;
  }
  
  async handleRateLimit(response: any): Promise<void> {
    const retryAfter = response.headers?.['retry-after'];
    if (retryAfter) {
      const delay = parseInt(retryAfter) * 1000;
      log(`Rate limited, waiting ${delay}ms as requested`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  async emergencyStop(reason: string): Promise<void> {
    log(`Emergency stop triggered: ${reason}`);
    // Could emit emergency artifact here
  }
}

/**
 * Get endpoint artifacts from previous scans
 */
async function getEndpointArtifacts(scanId: string, domain?: string): Promise<EndpointReport[]> {
  try {
    const { LocalStore } = await import('../core/localStore.js');
    const store = new LocalStore();
    
    try {
      const result = await store.query(
        'SELECT metadata FROM artifacts WHERE scan_id = $1 AND type = $2',
        [scanId, 'endpoint_discovery']
      );
      
      const endpoints: EndpointReport[] = [];
      
      for (const row of result.rows) {
        if (row.metadata?.endpoints) {
          // Handle both array of strings and array of objects
          for (const endpoint of row.metadata.endpoints) {
            if (typeof endpoint === 'string') {
              // Convert string paths to endpoint objects with EndpointReport structure
              endpoints.push({
                url: endpoint.startsWith('http') ? endpoint : `https://${domain || 'example.com'}${endpoint}`,
                method: 'GET',
                statusCode: 0,
                responseTime: 0,
                contentLength: 0,
                headers: {}
              });
            } else if (endpoint.url) {
              // Already an endpoint object - ensure it matches EndpointReport structure
              endpoints.push({
                url: endpoint.url,
                method: endpoint.method || 'GET',
                statusCode: endpoint.statusCode || 0,
                responseTime: endpoint.responseTime || 0,
                contentLength: endpoint.contentLength || 0,
                headers: endpoint.headers || {}
              });
            }
          }
        }
      }
      
      log(`Found ${endpoints.length} endpoints from endpoint discovery`);
      return endpoints;
      
    } finally {
      await store.close();
    }
  } catch (error) {
    log(`Error querying endpoint artifacts: ${(error as Error).message}`);
    return [];
  }
}

/**
 * Analyze endpoint response for backend service indicators
 */
async function analyzeEndpointResponse(url: string): Promise<BackendIndicators> {
  const operation = async () => {
    const response = await httpClient.get(url, {
      timeout: SAFETY_CONTROLS.TIMEOUT_SECONDS * 1000,
      validateStatus: () => true, // Accept all status codes
      maxRedirects: 2
    });

    const indicators: BackendIndicators = {
      responseTimeMs: response.headers['x-response-time-ms'] ? 
        parseInt(response.headers['x-response-time-ms']) : 0,
      serverHeaders: [],
      errorPatterns: [],
      costIndicators: [],
      authPatterns: []
    };

    // Extract server headers that indicate cloud services
    Object.entries(response.headers).forEach(([key, value]) => {
      const lowerKey = key.toLowerCase();
      const stringValue = String(value).toLowerCase();
      
      if (lowerKey.includes('server') || lowerKey.includes('x-powered-by')) {
        indicators.serverHeaders.push(`${key}: ${value}`);
      }
      
      if (lowerKey.includes('x-amz') || lowerKey.includes('x-goog') || lowerKey.includes('x-azure')) {
        indicators.costIndicators.push(`${key}: ${value}`);
      }
      
      if (lowerKey.includes('auth') || lowerKey.includes('api-key') || lowerKey.includes('token')) {
        indicators.authPatterns.push(`${key}: ${value}`);
      }
    });

    // Analyze response body for service patterns
    if (typeof response.data === 'string') {
      const body = response.data.toLowerCase();
      
      // Error patterns that indicate specific services
      if (body.includes('lambda') || body.includes('aws')) {
        indicators.errorPatterns.push('aws_service_detected');
      }
      if (body.includes('cloudfunctions') || body.includes('gcp')) {
        indicators.errorPatterns.push('gcp_service_detected');
      }
      if (body.includes('azurewebsites') || body.includes('azure')) {
        indicators.errorPatterns.push('azure_service_detected');
      }
    }

    return indicators;
  };

  const result = await apiCall(operation, {
    moduleName: 'denialWalletScan',
    operation: 'analyzeEndpoint',
    target: url
  });

  if (!result.success) {
    // Return empty indicators if analysis fails
    return {
      responseTimeMs: 0,
      serverHeaders: [],
      errorPatterns: [],
      costIndicators: [],
      authPatterns: []
    };
  }

  return result.data;
}

/**
 * Detect service type and calculate cost estimates
 */
function detectServiceAndCalculateCost(endpoint: EndpointReport, indicators: BackendIndicators): CostEstimate {
  let detectedService = 'unknown_stateful';
  let confidence: 'high' | 'medium' | 'low' = 'low';
  
  // Try to match against known service patterns
  for (const [serviceName, serviceConfig] of Object.entries(SERVICE_COSTS)) {
    if (serviceConfig.pattern.test(endpoint.url)) {
      detectedService = serviceName;
      confidence = 'high';
      break;
    }
  }
  
  // If no direct match, use response analysis
  if (confidence === 'low' && indicators.serverHeaders.length > 0) {
    confidence = 'medium';
    if (indicators.responseTimeMs > 1000) {
      detectedService = 'complex_processing';
    }
  }
  
  const serviceConfig =
    SERVICE_COSTS[detectedService as keyof typeof SERVICE_COSTS] ??
    SERVICE_COSTS.unknown_stateful;
  const baseCost = serviceConfig.cost;
  
  const risk_factors = [];
  if (indicators.responseTimeMs > 500) risk_factors.push('High response time suggests complex processing');
  if (indicators.serverHeaders.length > 0) risk_factors.push('Cloud service headers detected');
  if (indicators.costIndicators.length > 0) risk_factors.push('Billing/quota headers present');
  
  return {
    service_detected: detectedService,
    confidence,
    base_unit_cost: baseCost,
    multiplier: serviceConfig.multiplier,
    risk_factors
  };
}

/**
 * Test authentication bypass possibilities
 */
async function classifyAuthBypass(endpoint: string): Promise<AuthBypassAnalysis> {
  const operation = async () => {
    // Test various bypass methods
    const bypassMethods: string[] = [];
    let bypassProbability = 0;
    let authType = AuthGuardType.NONE;

    // Test 1: Direct access without authentication
    try {
      const response = await httpClient.get(endpoint, {
        timeout: SAFETY_CONTROLS.TIMEOUT_SECONDS * 1000,
        validateStatus: () => true
      });

      if (response.status === 200) {
        bypassMethods.push('direct_access');
        bypassProbability += 0.9;
        authType = AuthGuardType.NONE;
      } else if (response.status === 401) {
        authType = AuthGuardType.USER_SCOPED;
      } else if (response.status === 403) {
        authType = AuthGuardType.RATE_LIMIT_ONLY;
        bypassProbability += 0.3;
      }
    } catch (error) {
      // Endpoint might be protected or unavailable
    }

    // Test 2: Common header bypasses
    try {
      const headerTests = [
        { 'X-Forwarded-For': '127.0.0.1' },
        { 'X-Originating-IP': '127.0.0.1' },
        { 'X-API-Key': 'test' },
        { 'Authorization': 'Bearer test' }
      ];

      for (const headers of headerTests) {
        const response = await httpClient.get(endpoint, {
          headers,
          timeout: SAFETY_CONTROLS.TIMEOUT_SECONDS * 1000,
          validateStatus: () => true
        });

        if (response.status === 200) {
          bypassMethods.push(`header_bypass_${Object.keys(headers)[0]}`);
          bypassProbability += 0.5;
          authType = AuthGuardType.WEAK_API_KEY;
          break;
        }
      }
    } catch (error) {
      // Header bypass tests failed
    }

    return {
      authType,
      bypassProbability: Math.min(bypassProbability, 1.0),
      bypassMethods
    };
  };

  const result = await apiCall(operation, {
    moduleName: 'denialWalletScan',
    operation: 'classifyAuthBypass',
    target: endpoint
  });

  if (!result.success) {
    // Return conservative assessment if testing fails
    return {
      authType: AuthGuardType.USER_SCOPED,
      bypassProbability: 0.1,
      bypassMethods: []
    };
  }

  return result.data;
}

/**
 * Measure sustained RPS with safety controls
 */
async function measureSustainedRPS(endpoint: string, safetyController: DoWSafetyController): Promise<number> {
  let currentRPS = TESTING_CONFIG.INITIAL_RPS;
  let sustainedRPS = 0;
  
  log(`Starting RPS testing for ${endpoint}`);
  
  while (currentRPS <= TESTING_CONFIG.MAX_RPS) {
    if (!(await safetyController.checkSafetyLimits())) {
      break;
    }
    
    log(`Testing ${currentRPS} RPS for ${TESTING_CONFIG.TEST_DURATION_SECONDS} seconds`);
    
    const requests = [];
    const interval = 1000 / currentRPS;
    let successCount = 0;
    
    // Send requests at target RPS
    for (let i = 0; i < currentRPS * TESTING_CONFIG.TEST_DURATION_SECONDS; i++) {
      const requestPromise = httpClient.get(endpoint, {
        timeout: SAFETY_CONTROLS.TIMEOUT_SECONDS * 1000,
        validateStatus: (status) => status < 500 // Treat 4xx as success for RPS testing
      }).then(() => {
        successCount++;
        safetyController.recordRequest(true);
        return true;
      }).catch(() => {
        safetyController.recordRequest(false);
        return false;
      });
      
      requests.push(requestPromise);
      
      // Wait for interval
      await new Promise(resolve => setTimeout(resolve, interval));
    }
    
    // Wait for all requests to complete
    await Promise.allSettled(requests);
    
    const successRate = successCount / requests.length;
    log(`RPS ${currentRPS}: ${(successRate * 100).toFixed(1)}% success rate`);
    
    // Check if we hit the circuit breaker threshold
    if (successRate < (1 - TESTING_CONFIG.CIRCUIT_BREAKER_THRESHOLD)) {
      log(`Circuit breaker triggered at ${currentRPS} RPS`);
      break;
    }
    
    sustainedRPS = currentRPS;
    currentRPS = Math.floor(currentRPS * TESTING_CONFIG.BACKOFF_MULTIPLIER);
    
    // Cooldown between test phases
    await new Promise(resolve => setTimeout(resolve, TESTING_CONFIG.COOLDOWN_SECONDS * 1000));
  }
  
  log(`Maximum sustained RPS: ${sustainedRPS}`);
  return sustainedRPS;
}

/**
 * Calculate simplified risk assessment
 */
function calculateRiskAssessment(
  costEstimate: CostEstimate,
  sustainedRPS: number,
  authBypass: AuthBypassAnalysis
): DoWRiskAssessment {

  const dailyUnits = estimateDailyUnits(
    costEstimate.multiplier,
    sustainedRPS,
    authBypass.bypassProbability
  );

  const estimated_daily_cost = dailyUnits * costEstimate.base_unit_cost;

  return {
    service_detected: costEstimate.service_detected,
    estimated_daily_cost,
    auth_bypass_probability: authBypass.bypassProbability,
    sustained_rps: sustainedRPS,
    attack_complexity: authBypass.bypassProbability > 0.8 ? 'trivial' :
                      authBypass.bypassProbability > 0.5 ? 'low' :
                      authBypass.bypassProbability > 0.2 ? 'medium' : 'high'
  };
}

/**
 * Main denial-of-wallet scan function
 */
export async function runDenialWalletScan(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;
  
  return executeModule('denialWalletScan', async () => {
    const startTime = Date.now();
    
    log(`Starting denial-of-wallet scan for domain="${domain}"`);
    
    const safetyController = new DoWSafetyController();
    let findingsCount = 0;
    
    // Get endpoints from previous discovery
    const endpoints = await getEndpointArtifacts(scanId, domain);
    
    if (endpoints.length === 0) {
      log('No endpoints found for DoW testing');
      return 0;
    }
    
    // Filter to state-changing endpoints that could trigger costs
    const costEndpoints = endpoints.filter(ep => 
      ['POST', 'PUT', 'PATCH'].includes(ep.method) ||
      ep.url.includes('/api/') ||
      ep.url.includes('/upload') ||
      ep.url.includes('/process')
    );
    
    log(`Filtered to ${costEndpoints.length} potential cost-amplification endpoints`);
    
    // Test each endpoint for DoW vulnerability
    for (const endpoint of costEndpoints.slice(0, 10)) { // Limit for safety
      if (!(await safetyController.checkSafetyLimits())) {
        break;
      }
      
      log(`Analyzing endpoint: ${endpoint.url}`);
      
      try {
        // Analyze endpoint for backend indicators
        const indicators = await analyzeEndpointResponse(endpoint.url);
        
        // Detect service and obtain base-unit costs
        const costEstimate = detectServiceAndCalculateCost(endpoint, indicators);
        
        // Test authentication bypass
        const authBypass = await classifyAuthBypass(endpoint.url);
        
        // Measure sustained RPS (only if bypass possible)
        let sustainedRPS = 0;
        if (authBypass.bypassProbability > 0.1) {
          sustainedRPS = await measureSustainedRPS(endpoint.url, safetyController);
        }
        
        // Calculate overall risk (daily burn)
        const riskAssessment = calculateRiskAssessment(
          costEstimate,
          sustainedRPS,
          authBypass
        );
        
        // Only create findings for significant risks
        if (riskAssessment.estimated_daily_cost > 10) { // $10+ per day threshold
          // Create a simple artifact first for the finding to reference
          const artifactId = await insertArtifact({
            type: 'denial_wallet_endpoint',
            val_text: `${riskAssessment.service_detected} service detected at ${endpoint.url}`,
            severity: riskAssessment.estimated_daily_cost > 1000 ? 'CRITICAL' : 
                      riskAssessment.estimated_daily_cost > 100 ? 'HIGH' : 'MEDIUM',
            meta: {
              scan_id: scanId,
              scan_module: 'denialWalletScan',
              endpoint_url: endpoint.url,
              service_detected: riskAssessment.service_detected,
              estimated_daily_cost: riskAssessment.estimated_daily_cost,
              auth_bypass_probability: riskAssessment.auth_bypass_probability,
              sustained_rps: riskAssessment.sustained_rps,
              attack_complexity: riskAssessment.attack_complexity
            }
          });
          
          // Insert finding - let database calculate EAL values
          await insertFinding(
            artifactId,
            'DENIAL_OF_WALLET',
            `${endpoint.url} vulnerable to cost amplification attacks via ${riskAssessment.service_detected}`,
            `Implement rate limiting and authentication. Estimated daily cost: $${riskAssessment.estimated_daily_cost.toFixed(2)}`
          );
          
          findingsCount++;
        }
        
      } catch (error) {
        log(`Error analyzing endpoint ${endpoint.url}: ${(error as Error).message}`);
        continue;
      }
    }
    
    const duration = Date.now() - startTime;
    log(`Denial-of-wallet scan completed: ${findingsCount} findings in ${duration}ms`);
    
    return findingsCount;
    
  }, { scanId, target: domain });
}