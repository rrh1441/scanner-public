/**
 * Dedicated ZAP Worker Process
 * 
 * Runs on separate machines that auto-scale to zero when idle.
 * Handles ZAP scan requests via queue system for optimal pay-per-second economics.
 */

import { config } from 'dotenv';
import { GCPQueue } from './core/queue.js';
import { initializeDatabase } from './core/artifactStoreGCP.js';
import { runZAPScan } from './modules/zapScan.js';

config();

const queue = new GCPQueue(); // Using GCP Cloud Tasks implementation

function log(...args: unknown[]) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [zap-worker]`, ...args);
}

interface ZAPJob {
  id: string;
  type: 'zap_scan';
  domain: string;
  scanId: string;
  createdAt: string;
}

/**
 * Process a single ZAP scan job
 */
async function processZAPJob(job: ZAPJob): Promise<void> {
  const { id, domain, scanId } = job;
  
  log(`🕷️ ZAP JOB PICKED UP: Processing ZAP scan ${id} for ${domain} (${scanId})`);
  
  try {
    // Update job status to processing
    await queue.updateStatus(id, 'processing', 'ZAP web application security scan in progress...');
    
    // Run ZAP scan
    const findingsCount = await runZAPScan({ domain, scanId });
    
    // Update job status to completed
    await queue.updateStatus(
      id, 
      'done', 
      `ZAP scan completed - ${findingsCount} web application vulnerabilities found`
    );
    
    log(`✅ ZAP SCAN COMPLETED for ${domain}: ${findingsCount} web vulnerabilities found`);
    
  } catch (error) {
    log(`❌ ZAP scan failed for ${domain}:`, (error as Error).message);
    
    // Update job status to failed
    await queue.updateStatus(
      id, 
      'failed', 
      `ZAP scan failed: ${(error as Error).message}`
    );
    
    throw error;
  }
}

/**
 * Main ZAP worker loop
 */
async function startZAPWorker(): Promise<void> {
  // Log worker startup
  const workerInstanceId = process.env.K_SERVICE || `zap-worker-${Date.now()}`;
  log(`Starting dedicated ZAP worker [${workerInstanceId}]`);
  
  // Initialize database connection
  try {
    await initializeDatabase();
    log('Database connection initialized successfully');
  } catch (error) {
    log('Database initialization failed:', (error as Error).message);
    process.exit(1);
  }
  
  // Verify Docker and ZAP image are available
  try {
    const { spawn } = await import('node:child_process');
    
    // Check Docker availability
    const dockerCheck = await new Promise<boolean>((resolve) => {
      const dockerProcess = spawn('docker', ['--version'], { stdio: 'pipe' });
      dockerProcess.on('exit', (code) => resolve(code === 0));
      dockerProcess.on('error', () => resolve(false));
    });
    
    if (!dockerCheck) {
      log('ERROR: Docker is not available for ZAP scanning');
      process.exit(1);
    }
    
    // Check ZAP Docker image availability
    const zapImageCheck = await new Promise<boolean>((resolve) => {
      const inspectProcess = spawn('docker', ['image', 'inspect', 'zaproxy/zap-stable'], { stdio: 'pipe' });
      inspectProcess.on('exit', (code) => resolve(code === 0));
      inspectProcess.on('error', () => resolve(false));
    });
    
    if (!zapImageCheck) {
      log('WARNING: ZAP Docker image not found, attempting to pull...');
      const pullProcess = spawn('docker', ['pull', 'zaproxy/zap-stable'], { stdio: 'pipe' });
      const pullResult = await new Promise<boolean>((resolve) => {
        pullProcess.on('exit', (code) => resolve(code === 0));
        pullProcess.on('error', () => resolve(false));
      });
      
      if (!pullResult) {
        log('ERROR: Failed to pull ZAP Docker image');
        process.exit(1);
      }
    }
    
    log('✅ Docker and ZAP image are available');
  } catch (error) {
    log('ERROR: Failed to verify ZAP setup:', (error as Error).message);
    process.exit(1);
  }
  
  let isShuttingDown = false;
  
  // Graceful shutdown handler
  const gracefulShutdown = (signal: string) => {
    if (isShuttingDown) {
      log(`Already shutting down, ignoring ${signal}`);
      return;
    }
    
    isShuttingDown = true;
    log(`Received ${signal}, initiating graceful shutdown...`);
    
    // ZAP worker can shut down immediately since scans are short-lived
    log('ZAP worker shutdown completed');
    process.exit(0);
  };
  
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  
  // Main processing loop - optimized for ZAP workloads
  while (!isShuttingDown) {
    try {
      // Look for any available jobs - we'll filter for ZAP jobs
      const job = await queue.getNextJob() as unknown as ZAPJob | null;
      
      if (job && !isShuttingDown) {
        // Filter for ZAP jobs only - skip non-ZAP jobs
        if (job.type === 'zap_scan') {
          log(`Processing ZAP job: ${job.id}`);
          await processZAPJob(job);
        } else {
          // Put non-ZAP job back in queue for other workers
          await queue.addJob(job.id, job);
          log(`Skipped non-ZAP job ${job.id} (type: ${(job as any).type || 'unknown'})`);
        }
      } else {
        // No ZAP jobs available, wait before checking again
        // ZAP workers can check more frequently since they scale to zero
        await new Promise(resolve => setTimeout(resolve, 2000)); // 2 second intervals
      }
      
    } catch (error) {
      if (!isShuttingDown) {
        log('ZAP worker error:', (error as Error).message);
        // Wait before retrying on error
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
  }
  
  log('ZAP worker loop exited due to shutdown signal');
}

// Start the ZAP worker
startZAPWorker().catch(error => {
  log('CRITICAL: Failed to start ZAP worker:', (error as Error).message);
  process.exit(1);
});