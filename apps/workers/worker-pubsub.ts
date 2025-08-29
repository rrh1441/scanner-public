// Pub/Sub push endpoint adapter for Cloud Run Service
import { config } from 'dotenv';
import { initializeApp } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';
import express from 'express';
import { processScan } from './worker.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import { PubSub } from '@google-cloud/pubsub';

const execAsync = promisify(exec);

config();

// Only initialize if running in GCP
const isGCP = process.env.K_SERVICE || process.env.CLOUD_RUN_JOB;

if (!isGCP) {
  console.log('Not running in GCP, exiting Pub/Sub adapter');
  process.exit(0);
}

const app = initializeApp();
const db = getFirestore(app);
const pubsub = new PubSub();

// Structured logging for GCP
function log(severity: 'ERROR' | 'INFO', message: string, context: object = {}) {
  console.log(JSON.stringify({
    severity,
    message,
    timestamp: new Date().toISOString(),
    ...context
  }));
}

// Validate security tools at startup
async function validateSecurityTools() {
  const requiredTools = [
    { name: 'sslscan', command: 'sslscan --version' },
    { name: 'nuclei', command: 'nuclei --version' },
    { name: 'trufflehog', command: 'trufflehog --version' },
    { name: 'nmap', command: 'nmap --version' },
    { name: 'python3', command: 'python3 --version' }
  ];

  const missingTools: string[] = [];
  const availableTools: string[] = [];

  for (const tool of requiredTools) {
    try {
      await execAsync(tool.command);
      availableTools.push(tool.name);
      log('INFO', `Tool validation passed: ${tool.name}`);
    } catch (error) {
      missingTools.push(tool.name);
      log('ERROR', `Tool validation failed: ${tool.name}`, { 
        error: (error as Error).message 
      });
    }
  }

  log('INFO', 'Tool validation completed', {
    available: availableTools,
    missing: missingTools,
    total: requiredTools.length
  });

  // Continue even with missing tools for graceful degradation
  if (missingTools.length > 0) {
    log('INFO', `Starting with ${availableTools.length}/${requiredTools.length} tools available`);
  }
}

// Start HTTP server for health checks and Pub/Sub push endpoint
const server = express();
server.use(express.json());

// Health check endpoint
server.get('/health', (req, res) => res.json({ status: 'healthy' }));

// Pub/Sub push endpoint - handles both direct push and Eventarc CloudEvents
server.post('/', async (req, res) => {
  let scanId: string | undefined;
  
  try {
    // Handle both direct Pub/Sub push AND Eventarc CloudEvents
    let data: any;
    
    if (req.body.message) {
      // Direct Pub/Sub push format
      const message = req.body.message;
      data = JSON.parse(Buffer.from(message.data, 'base64').toString());
      log('INFO', 'Received direct Pub/Sub push message', { 
        messageId: message.messageId 
      });
    } else if (req.headers['ce-type'] === 'google.cloud.pubsub.topic.v1.messagePublished') {
      // Eventarc CloudEvents format
      const pubsubMessage = req.body.message || req.body;
      data = JSON.parse(Buffer.from(pubsubMessage.data, 'base64').toString());
      log('INFO', 'Received Eventarc CloudEvent message', { 
        ceId: req.headers['ce-id'],
        ceSource: req.headers['ce-source']
      });
    } else {
      log('ERROR', 'Unknown message format', { 
        headers: req.headers,
        bodyKeys: Object.keys(req.body) 
      });
      res.status(400).send('Bad Request: unknown message format');
      return;
    }
    
    scanId = data.scanId;
    
    log('INFO', 'Processing scan request', { 
      scanId,
      companyName: data.companyName,
      domain: data.domain 
    });
    
    // Validate required fields
    if (!scanId || !data.companyName || !data.domain) {
      log('ERROR', 'Invalid message format', { data });
      res.status(204).send(); // Acknowledge to prevent redelivery
      return;
    }
    
    // Create or update Firestore document
    await db.collection('scans').doc(scanId).set({
      status: 'processing',
      updated_at: new Date(),
      worker_id: process.env.K_REVISION || 'unknown',
      started_at: new Date(),
      scanId: scanId,
      companyName: data.companyName,
      domain: data.domain,
      createdAt: data.createdAt || new Date().toISOString()
    }, { merge: true });
    
    // Process the scan
    await processScan({
      scanId: data.scanId,
      domain: data.domain,
      companyName: data.companyName,
      createdAt: data.createdAt || new Date().toISOString()
    });
    
    // Update Firestore with completion
    await db.collection('scans').doc(scanId).set({
      status: 'completed',
      completed_at: new Date(),
      json: { 
        scanId,
        companyName: data.companyName,
        domain: data.domain 
      }
    }, { merge: true });
    
    // Emit report-generation event
    try {
      await pubsub.topic('report-generation').publishMessage({
        json: {
          scanId,
          companyName: data.companyName,
          domain: data.domain
        }
      });
      log('INFO', 'Published report-generation event', { scanId });
    } catch (publishError) {
      log('ERROR', 'Failed to publish report-generation event', {
        scanId,
        error: (publishError as Error).message
      });
    }
    
    log('INFO', 'Successfully processed scan', { scanId });
    res.status(204).send(); // Acknowledge success
    
  } catch (error) {
    log('ERROR', 'Failed to process push message', { 
      error: (error as Error).message,
      stack: (error as Error).stack,
      scanId
    });
    
    // Update Firestore with failure status if we have a scanId
    if (scanId) {
      try {
        await db.collection('scans').doc(scanId).set({
          status: 'failed',
          error: (error as Error).message,
          failed_at: new Date()
        }, { merge: true });
      } catch (updateError) {
        log('ERROR', 'Failed to update scan status', { 
          scanId,
          error: (updateError as Error).message 
        });
      }
    }
    
    // Return error to retry later (with 600s ack deadline we have time)
    res.status(500).send('Internal Server Error');
  }
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  log('INFO', 'HTTP server listening', { port: PORT });
  validateSecurityTools().catch((error) => {
    log('ERROR', 'Security tools validation failed', { error: error.message });
  });
});