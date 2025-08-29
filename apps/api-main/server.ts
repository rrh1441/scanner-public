import { config } from 'dotenv';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifyCors from '@fastify/cors';
import fastifyRateLimit from '@fastify/rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import { PubSub } from '@google-cloud/pubsub';
import { Firestore } from '@google-cloud/firestore';
import { nanoid } from 'nanoid';
// Stub for database queries (will be implemented with proper GCP integration)
const pool = {
  query: async () => ({ rows: [] })
};

// Simple domain normalization function
function normalizeDomain(rawDomain: string) {
  const cleaned = rawDomain.replace(/^https?:\/\//, '').replace(/\/$/, '').toLowerCase();
  return {
    isValid: cleaned.length > 0 && cleaned.includes('.'),
    normalizedDomain: cleaned,
    validationErrors: cleaned.length === 0 || !cleaned.includes('.') ? ['Invalid domain format'] : []
  };
}

config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const fastify = Fastify({ logger: true });
const pubsub = new PubSub();
const firestore = new Firestore();

// GCP constants
const SCAN_JOBS_TOPIC = 'scan-jobs';
const REPORT_GENERATION_TOPIC = 'report-generation';

function log(...args: any[]) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}]`, ...args);
}

// GCP Pub/Sub message publishing
async function publishScanJob(job: any): Promise<void> {
  try {
    const topic = pubsub.topic(SCAN_JOBS_TOPIC);
    const messageBuffer = Buffer.from(JSON.stringify(job));
    
    const messageId = await topic.publishMessage({
      data: messageBuffer,
      attributes: {
        scanId: job.scanId,
        domain: job.domain
      }
    });
    
    log(`[pubsub] Published scan job ${job.scanId} with message ID: ${messageId}`);
  } catch (error) {
    log('[pubsub] Error publishing scan job:', (error as Error).message);
    throw error;
  }
}

// Store scan job in Firestore
async function createScanRecord(job: any): Promise<void> {
  try {
    await firestore.collection('scans').doc(job.scanId).set({
      scan_id: job.scanId,
      company_name: job.companyName,
      domain: job.domain,
      original_domain: job.originalDomain,
      tags: job.tags || [],
      status: 'queued',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });
    
    log(`[firestore] Created scan record for ${job.scanId}`);
  } catch (error) {
    log('[firestore] Error creating scan record:', (error as Error).message);
    throw error;
  }
}

// Get scan status from Firestore
async function getScanStatus(scanId: string): Promise<any> {
  try {
    const doc = await firestore.collection('scans').doc(scanId).get();
    if (!doc.exists) {
      return null;
    }
    return doc.data();
  } catch (error) {
    log('[firestore] Error getting scan status:', (error as Error).message);
    return null;
  }
}

// Get artifacts from Cloud Storage (via GCP artifact store)
async function getScanArtifacts(scanId: string): Promise<any[]> {
  try {
    // Query artifacts from PostgreSQL with GCP artifact store
    const artifactsResult = await pool.query();
    
    return artifactsResult.rows;
  } catch (error) {
    log('[artifacts] Error getting scan artifacts:', (error as Error).message);
    throw error;
  }
}

// Health check for GCP services
async function healthCheck(): Promise<any> {
  try {
    // Test Pub/Sub connectivity
    const topic = pubsub.topic(SCAN_JOBS_TOPIC);
    const [exists] = await topic.exists();
    
    // Test Firestore connectivity  
    await firestore.collection('_health').doc('test').get();
    
    return {
      status: 'healthy',
      pubsub: exists ? 'connected' : 'topic_missing',
      firestore: 'connected',
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      error: (error as Error).message,
      timestamp: new Date().toISOString()
    };
  }
}

// No worker management needed - GCP Cloud Run handles scaling automatically

// Register CORS for frontend access
fastify.register(fastifyCors, {
  origin: [
    'https://dealbriefadmin.vercel.app',
    'https://lfbi.vercel.app',
    /^https:\/\/.*\.lfbi\.vercel\.app$/, // Allow all subdomains of lfbi.vercel.app
    /^https:\/\/.*\.vercel\.app$/, // Allow preview deployments
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
});

// Register rate limiting
fastify.register(fastifyRateLimit, {
  global: true,
  max: 100, // Maximum 100 requests
  timeWindow: '1 minute', // Per minute
  cache: 10000, // Cache up to 10000 rate limit entries
  allowList: ['127.0.0.1', '::1'], // Exclude localhost from rate limits
  redis: undefined, // Use in-memory store (consider Redis for production scaling)
  skipOnError: true, // Don't apply rate limit if store errors
  keyGenerator: (request) => {
    // Rate limit by IP + API key if present
    const apiKey = request.headers['x-api-key'];
    return apiKey ? `${request.ip}-${apiKey}` : request.ip;
  },
  errorResponseBuilder: (request, context) => {
    return {
      statusCode: 429,
      error: 'Too Many Requests',
      message: `Rate limit exceeded, retry in ${context.after}`,
      date: new Date().toISOString(),
      expiresIn: context.after
    };
  },
  onExceeding: (request, key) => {
    log(`[rate-limit] Warning: ${key} is exceeding rate limit`);
  },
  onExceeded: (request, key) => {
    log(`[rate-limit] Rejected: ${key} exceeded rate limit`);
  }
});

// Configure specific rate limits for different endpoints
const scanRateLimit = {
  max: 10, // 10 scans per minute per IP
  timeWindow: '1 minute'
};

const bulkScanRateLimit = {
  max: 2, // 2 bulk operations per minute
  timeWindow: '1 minute'
};

const statusRateLimit = {
  max: 60, // 60 status checks per minute
  timeWindow: '1 minute'
};

// Register static file serving for the public directory
fastify.register(fastifyStatic, {
  root: path.join(__dirname, '..', 'public'),
  prefix: '/', // serve files from root
});

// Health check endpoint
fastify.get('/health', async (request, reply) => {
  return await healthCheck();
});

// Create a new scan (main endpoint)
fastify.post('/scan', { config: { rateLimit: scanRateLimit } }, async (request, reply) => {
  try {
    const { companyName, domain: rawDomain, tags } = request.body as { companyName: string; domain: string; tags?: string[] };
    
    if (!companyName || !rawDomain) {
      log('[api] Scan creation failed: Missing required fields - companyName or domain');
      reply.status(400);
      return { error: 'Company name and domain are required' };
    }

    // Normalize and validate domain
    const validation = normalizeDomain(rawDomain);
    
    if (!validation.isValid) {
      log(`[api] Domain validation failed for ${rawDomain}: ${validation.validationErrors.join(', ')}`);
      reply.status(400);
      return { 
        error: 'Invalid domain format', 
        details: validation.validationErrors,
        suggestion: `Provided: "${rawDomain}", Expected format: "example.com"`
      };
    }

    const normalizedDomain = validation.normalizedDomain;
    const scanId = nanoid(11);
    
    // Validate scanId is a non-empty string
    if (!scanId || typeof scanId !== 'string' || scanId.trim().length === 0) {
      log('[api] CRITICAL: Failed to generate valid scanId');
      reply.status(500);
      return { error: 'Failed to generate scan ID', details: 'Internal server error during scan ID generation' };
    }
    
    const job = {
      scanId,
      companyName,
      domain: normalizedDomain,
      originalDomain: rawDomain,
      tags: tags || [],
      createdAt: new Date().toISOString()
    };

    log(`[api] Attempting to create scan job ${scanId} for ${companyName} (${normalizedDomain}) [original: ${rawDomain}]`);
    
    try {
      // Store in Firestore
      await createScanRecord(job);
      
      // Publish to Pub/Sub
      await publishScanJob(job);
      
      log(`[api] ✅ Successfully created scan job ${scanId} for ${companyName}`);
    } catch (error) {
      log('[api] CRITICAL: Failed to create scan job:', (error as Error).message);
      reply.status(500);
      return { 
        error: 'Failed to create scan job', 
        details: `GCP operation failed: ${(error as Error).message}`,
        scanId: null
      };
    }

    return {
      scanId,
      status: 'queued',
      companyName,
      domain: normalizedDomain,
      originalDomain: rawDomain,
      message: 'Scan started successfully'
    };

  } catch (error) {
    log('[api] CRITICAL: Unexpected error in POST /scan:', (error as Error).message);
    log('[api] Error stack:', (error as Error).stack);
    reply.status(500);
    return { 
      error: 'Internal server error during scan creation', 
      details: (error as Error).message,
      scanId: null
    };
  }
});

// Create a new scan (alias for frontend compatibility)
fastify.post('/scans', { config: { rateLimit: scanRateLimit } }, async (request, reply) => {
  try {
    const { companyName, domain: rawDomain, tags } = request.body as { companyName: string; domain: string; tags?: string[] };
    
    if (!companyName || !rawDomain) {
      log('[api] Scan creation failed: Missing required fields - companyName or domain');
      reply.status(400);
      return { error: 'Company name and domain are required' };
    }

    // Normalize and validate domain
    const validation = normalizeDomain(rawDomain);
    
    if (!validation.isValid) {
      log(`[api] Domain validation failed for ${rawDomain}: ${validation.validationErrors.join(', ')}`);
      reply.status(400);
      return { 
        error: 'Invalid domain format', 
        details: validation.validationErrors,
        suggestion: `Provided: "${rawDomain}", Expected format: "example.com"`
      };
    }

    const normalizedDomain = validation.normalizedDomain;

    const scanId = nanoid(11);
    
    // Validate scanId is a non-empty string
    if (!scanId || typeof scanId !== 'string' || scanId.trim().length === 0) {
      log('[api] CRITICAL: Failed to generate valid scanId');
      reply.status(500);
      return { error: 'Failed to generate scan ID', details: 'Internal server error during scan ID generation' };
    }
    
    const job = {
      scanId,
      companyName,
      domain: normalizedDomain,
      originalDomain: rawDomain,
      tags: tags || [],
      createdAt: new Date().toISOString()
    };

    log(`[api] Attempting to create scan job ${scanId} for ${companyName} (${normalizedDomain}) [original: ${rawDomain}]`);
    
    try {
      // Store in Firestore
      await createScanRecord(job);
      
      // Publish to Pub/Sub
      await publishScanJob(job);
      
      log(`[api] ✅ Successfully created scan job ${scanId} for ${companyName}`);
    } catch (error) {
      log('[api] CRITICAL: Failed to create scan job:', (error as Error).message);
      reply.status(500);
      return { 
        error: 'Failed to create scan job', 
        details: `GCP operation failed: ${(error as Error).message}`,
        scanId: null
      };
    }

    return {
      scanId,
      status: 'queued',
      companyName,
      domain: normalizedDomain,
      originalDomain: rawDomain,
      message: 'Scan started successfully'
    };

  } catch (error) {
    log('[api] CRITICAL: Unexpected error in POST /scans:', (error as Error).message);
    log('[api] Error stack:', (error as Error).stack);
    reply.status(500);
    return { 
      error: 'Internal server error during scan creation', 
      details: (error as Error).message,
      scanId: null
    };
  }
});

// Get scan status
fastify.get('/scan/:scanId/status', { config: { rateLimit: statusRateLimit } }, async (request, reply) => {
  const { scanId } = request.params as { scanId: string };
  
  const status = await getScanStatus(scanId);
  
  if (!status) {
    reply.status(404);
    return { error: 'Scan not found' };
  }

  return {
    scanId,
    ...status
  };
});

// Get raw artifacts from scan
fastify.get('/scan/:scanId/artifacts', async (request, reply) => {
  const { scanId } = request.params as { scanId: string };
  
  try {
    log(`[api] Retrieving artifacts for scan: ${scanId}`);
    
    const artifacts = await getScanArtifacts(scanId);
    
    log(`[api] Found ${artifacts.length} artifacts for scan ${scanId}`);
    
    if (artifacts.length === 0) {
      reply.status(404);
      return { error: 'No artifacts found for this scan' };
    }

    return {
      scanId,
      artifacts,
      count: artifacts.length,
      retrievedAt: new Date().toISOString()
    };
  } catch (error) {
    log('[api] Error retrieving artifacts:', (error as Error).message);
    reply.status(500);
    return { error: 'Failed to retrieve artifacts', details: (error as Error).message };
  }
});

// Get findings from scan
fastify.get('/scan/:scanId/findings', async (request, reply) => {
  const { scanId } = request.params as { scanId: string };
  
  try {
    log(`[api] Retrieving findings for scan: ${scanId}`);
    
    const findingsResult = await pool.query();
    
    log(`[api] Found ${findingsResult.rows.length} findings for scan ${scanId}`);
    
    if (findingsResult.rows.length === 0) {
      reply.status(404);
      return { error: 'No findings found for this scan' };
    }

    return {
      scanId,
      findings: findingsResult.rows,
      count: findingsResult.rows.length,
      retrievedAt: new Date().toISOString()
    };
  } catch (error) {
    log('[api] Error retrieving findings:', (error as Error).message);
    reply.status(500);
    return { error: 'Failed to retrieve findings', details: (error as Error).message };
  }
});

// Bulk scan endpoint for JSON arrays
fastify.post('/scan/bulk', { config: { rateLimit: bulkScanRateLimit } }, async (request, reply) => {
  try {
    const { companies } = request.body as { companies: Array<{ companyName: string; domain: string; tags?: string[] }> };
    
    if (!companies || !Array.isArray(companies) || companies.length === 0) {
      log('[api] Bulk scan failed: Missing or empty companies array');
      reply.status(400);
      return { error: 'Companies array is required and must not be empty' };
    }

    const results = [];
    const errors = [];

    for (const company of companies) {
      try {
        const { companyName, domain: rawDomain } = company;
        
        if (!companyName || !rawDomain) {
          errors.push({ 
            company, 
            error: 'Company name and domain are required',
            scanId: null 
          });
          continue;
        }

        // Normalize and validate domain
        const validation = normalizeDomain(rawDomain);
        
        if (!validation.isValid) {
          errors.push({ 
            company, 
            error: 'Invalid domain format',
            details: validation.validationErrors,
            scanId: null 
          });
          continue;
        }

        const normalizedDomain = validation.normalizedDomain;
        const scanId = nanoid(11);
        
        if (!scanId || typeof scanId !== 'string' || scanId.trim().length === 0) {
          errors.push({ 
            company, 
            error: 'Failed to generate scan ID',
            scanId: null 
          });
          continue;
        }
        
        const job = {
          scanId,
          companyName,
          domain: normalizedDomain,
          originalDomain: rawDomain,
          tags: company.tags || [],
          createdAt: new Date().toISOString()
        };

        // Store in Firestore
        await createScanRecord(job);
        
        // Publish to Pub/Sub
        await publishScanJob(job);
        
        results.push({
          scanId,
          status: 'queued',
          companyName,
          domain: normalizedDomain,
          originalDomain: rawDomain,
          message: 'Scan started successfully'
        });
        
        log(`[api] ✅ Successfully created bulk scan job ${scanId} for ${companyName}`);
        
      } catch (error) {
        errors.push({ 
          company, 
          error: 'Failed to create scan',
          details: (error as Error).message,
          scanId: null 
        });
      }
    }

    // GCP Cloud Run will automatically handle scaling

    return {
      total: companies.length,
      successful: results.length,
      failed: errors.length,
      results,
      errors
    };

  } catch (error) {
    log('[api] Error in bulk scan:', (error as Error).message);
    reply.status(500);
    return { error: 'Failed to process bulk scan', details: (error as Error).message };
  }
});

// CSV upload endpoint
fastify.register(async function (fastify) {
  await fastify.register(import('@fastify/multipart'));
  
  fastify.post('/scan/csv', { config: { rateLimit: bulkScanRateLimit } }, async (request, reply) => {
    try {
      const data = await request.file();
      
      if (!data) {
        reply.status(400);
        return { error: 'No file uploaded' };
      }
      
      if (!data.filename?.endsWith('.csv')) {
        reply.status(400);
        return { error: 'Only CSV files are allowed' };
      }
      
      const buffer = await data.toBuffer();
      const csvContent = buffer.toString('utf-8');
      
      // Enhanced CSV parsing (supports Company,Domain,Tags header)
      const lines = csvContent.split('\n').filter(line => line.trim());
      const companies = [];
      
      for (let i = 1; i < lines.length; i++) { // Skip header
        const line = lines[i].trim();
        if (!line) continue;
        
        const parts = line.split(',').map(part => part.trim().replace(/^"(.*)"$/, '$1'));
        if (parts.length >= 2) {
          const company: { companyName: string; domain: string; tags?: string[] } = {
            companyName: parts[0],
            domain: parts[1].replace(/^https?:\/\//, '').replace(/\/$/, '')
          };
          
          // Parse tags if provided (3rd column)
          if (parts.length >= 3 && parts[2].trim()) {
            company.tags = parts[2].split(';').map(tag => tag.trim()).filter(tag => tag);
          }
          
          companies.push(company);
        }
      }
      
      if (companies.length === 0) {
        reply.status(400);
        return { error: 'No valid companies found in CSV file' };
      }
      
      // Process the companies using the same logic as bulk endpoint
      const results = [];
      const errors = [];

      for (const company of companies) {
        try {
          const { companyName, domain: rawDomain } = company;
          
          if (!companyName || !rawDomain) {
            errors.push({ 
              company, 
              error: 'Company name and domain are required',
              scanId: null 
            });
            continue;
          }

          // Normalize and validate domain
          const validation = normalizeDomain(rawDomain);
          
          if (!validation.isValid) {
            errors.push({ 
              company, 
              error: 'Invalid domain format',
              details: validation.validationErrors,
              scanId: null 
            });
            continue;
          }

          const normalizedDomain = validation.normalizedDomain;
          const scanId = nanoid(11);
          
          if (!scanId || typeof scanId !== 'string' || scanId.trim().length === 0) {
            errors.push({ 
              company, 
              error: 'Failed to generate scan ID',
              scanId: null 
            });
            continue;
          }
          
          const job = {
            scanId,
            companyName,
            domain: normalizedDomain,
            originalDomain: rawDomain,
            tags: company.tags || [],
            createdAt: new Date().toISOString()
          };

          // Store in Firestore
        await createScanRecord(job);
        
        // Publish to Pub/Sub
        await publishScanJob(job);
          
          results.push({
            scanId,
            status: 'queued',
            companyName,
            domain: normalizedDomain,
            originalDomain: rawDomain,
            message: 'Scan started successfully'
          });
          
          log(`[api] ✅ Successfully created CSV scan job ${scanId} for ${companyName}`);
          
        } catch (error) {
          errors.push({ 
            company, 
            error: 'Failed to create scan',
            details: (error as Error).message,
            scanId: null 
          });
        }
      }

      // GCP Cloud Run will automatically handle scaling

      return {
        filename: data.filename,
        total: companies.length,
        successful: results.length,
        failed: errors.length,
        results,
        errors
      };
      
    } catch (error) {
      log('[api] Error in CSV upload:', (error as Error).message);
      reply.status(500);
      return { error: 'Failed to process CSV file', details: (error as Error).message };
    }
  });
});

// API endpoint alias for frontend compatibility (/api/scans)
fastify.post('/api/scans', { config: { rateLimit: scanRateLimit } }, async (request, reply) => {
  try {
    const { companyName, domain: rawDomain, tags } = request.body as { companyName: string; domain: string; tags?: string[] };
    
    if (!companyName || !rawDomain) {
      log('[api] Scan creation failed: Missing required fields - companyName or domain');
      reply.status(400);
      return { error: 'Company name and domain are required' };
    }

    // Normalize and validate domain
    const validation = normalizeDomain(rawDomain);
    
    if (!validation.isValid) {
      log(`[api] Domain validation failed for ${rawDomain}: ${validation.validationErrors.join(', ')}`);
      reply.status(400);
      return { 
        error: 'Invalid domain format', 
        details: validation.validationErrors,
        suggestion: `Provided: "${rawDomain}", Expected format: "example.com"`
      };
    }

    const normalizedDomain = validation.normalizedDomain;

    const scanId = nanoid(11);
    
    if (!scanId || typeof scanId !== 'string' || scanId.trim().length === 0) {
      log('[api] CRITICAL: Failed to generate valid scanId');
      reply.status(500);
      return { error: 'Failed to generate scan ID', details: 'Internal server error during scan ID generation' };
    }
    
    const job = {
      scanId,
      companyName,
      domain: normalizedDomain,
      originalDomain: rawDomain,
      tags: tags || [],
      createdAt: new Date().toISOString()
    };

    log(`[api] Attempting to create scan job ${scanId} for ${companyName} (${normalizedDomain}) [original: ${rawDomain}] via /api/scans`);
    
    try {
      // Store in Firestore
      await createScanRecord(job);
      
      // Publish to Pub/Sub
      await publishScanJob(job);
      
      log(`[api] ✅ Successfully created scan job ${scanId} for ${companyName} via /api/scans`);
    } catch (error) {
      log('[api] CRITICAL: Failed to create scan job:', (error as Error).message);
      reply.status(500);
      return { 
        error: 'Failed to create scan job', 
        details: `GCP operation failed: ${(error as Error).message}`,
        scanId: null
      };
    }

    return {
      scanId,
      status: 'queued',
      companyName,
      domain: normalizedDomain,
      originalDomain: rawDomain,
      message: 'Scan started successfully'
    };

  } catch (error) {
    log('[api] CRITICAL: Unexpected error in POST /api/scans:', (error as Error).message);
    log('[api] Error stack:', (error as Error).stack);
    reply.status(500);
    return { 
      error: 'Internal server error during scan creation', 
      details: (error as Error).message,
      scanId: null
    };
  }
});

// API endpoint for getting scan status (/api/scans/{scanId})
fastify.get('/api/scans/:scanId', async (request, reply) => {
  const { scanId } = request.params as { scanId: string };
  
  try {
    const status = await getScanStatus(scanId);
    
    if (!status) {
      reply.status(404);
      return { error: 'Scan not found' };
    }

    return {
      scanId,
      ...status
    };
  } catch (error) {
    log('[api] Error retrieving scan status via /api/scans:', (error as Error).message);
    reply.status(500);
    return { error: 'Failed to retrieve scan status', details: (error as Error).message };
  }
});

// Manual sync trigger endpoint (deprecated - GCP handles scaling automatically)
fastify.post('/admin/sync', async (request, reply) => {
  try {
    // GCP Cloud Run handles scaling automatically
    return {
      message: 'This endpoint is deprecated. GCP Cloud Run handles worker scaling automatically.',
      timestamp: new Date().toISOString(),
      migration_status: 'Migrated to GCP Cloud Run'
    };
  } catch (error) {
    log('[api] Error in /admin/sync:', (error as Error).message);
    reply.status(500);
    return { error: 'Failed to trigger sync', details: (error as Error).message };
  }
});

// Debug endpoint to test GCP services
fastify.post('/admin/debug-gcp', async (request, reply) => {
  try {
    log('[api] GCP services debug requested');
    
    const health = await healthCheck();
    
    // Test publishing a debug message
    const testJob = {
      scanId: `debug-${Date.now()}`,
      companyName: 'Debug Test',
      domain: 'example.com',
      originalDomain: 'example.com',
      tags: ['debug'],
      createdAt: new Date().toISOString()
    };
    
    try {
      await publishScanJob(testJob);
      health.pubsub_test = 'success';
    } catch (error) {
      health.pubsub_test = `failed: ${(error as Error).message}`;
    }
    
    return health;
  } catch (error) {
    log('[api] Error in GCP debug:', (error as Error).message);
    reply.status(500);
    return { error: 'Failed to debug GCP', details: (error as Error).message };
  }
});

// Debug endpoint to see GCP service status
fastify.get('/admin/debug-services', async (request, reply) => {
  try {
    const result = await healthCheck();
    
    // Add more GCP service information
    try {
      const scanTopic = pubsub.topic(SCAN_JOBS_TOPIC);
      const [metadata] = await scanTopic.getMetadata();
      result.scan_topic_info = {
        name: metadata.name,
        labels: metadata.labels
      };
    } catch (error) {
      result.scan_topic_error = (error as Error).message;
    }
    
    try {
      const collections = await firestore.listCollections();
      result.firestore_collections = collections.map(c => c.id);
    } catch (error) {
      result.firestore_error = (error as Error).message;
    }
    
    return result;
  } catch (error) {
    return { error: (error as Error).message };
  }
});

// Webhook callback endpoint (for future use)
fastify.post('/scan/:id/callback', async (request, reply) => {
  try {
    const { id } = request.params as { id: string };
    log('[api] Received callback for scan', id);
    return { received: true };
  } catch (error) {
    log('[api] Error handling callback:', (error as Error).message);
    return reply.status(500).send({ error: 'Callback failed' });
  }
});

const start = async () => {
  try {
    const port = parseInt(process.env.PORT || '3000');
    await fastify.listen({ port, host: '0.0.0.0' });
    log(`[api] GCP API Server listening on port ${port}`);
    
    // Test GCP connectivity on startup
    const health = await healthCheck();
    log('[api] GCP Services Health:', health);
    
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
