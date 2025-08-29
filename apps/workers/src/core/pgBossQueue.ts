import Boss from 'pg-boss';
import { nanoid } from 'nanoid';
import type { ScanJob } from './jobTypes.js';

// We'll import database dynamically to avoid circular dependencies
const QUEUE_SCAN = 'scan';

/**
 * PostgreSQL-backed queue service using pg-boss
 * Eliminates Redis dependency and provides better concurrency handling
 */
export class PgBossQueue {
  private boss: Boss;
  private concurrency: number;
  private isStarted = false;

  constructor(concurrency: number = 24) {
    this.concurrency = concurrency;
    
    // Initialize pg-boss with existing database connection
    this.boss = new Boss({
      connectionString: process.env.DATABASE_URL || 'postgresql://localhost/scanner_local',
      schema: 'boss', // Separate schema for queue tables
      // Archive completed jobs for observability
      archiveCompletedAfterSeconds: 3600, // 1 hour
      deleteAfterSeconds: 86400, // 24 hours
      // Monitor state for health checks
      monitorStateIntervalSeconds: 10
    });

    this.setupEventHandlers();
  }

  private setupEventHandlers() {
    this.boss.on('error', (error) => {
      console.error('[PgBossQueue] Queue error:', error);
    });

    this.boss.on('monitor-states', (states) => {
      console.log('[PgBossQueue] Queue states:', {
        active: states.active,
        created: states.created,
        completed: states.completed,
        failed: states.failed
      });
    });
  }

  async start(): Promise<void> {
    if (this.isStarted) return;

    try {
      await this.boss.start();
      this.isStarted = true;
      console.log(`[PgBossQueue] Started with concurrency: ${this.concurrency}`);
    } catch (error) {
      console.error('[PgBossQueue] Failed to start queue:', error);
      throw error;
    }
  }

  async stop(): Promise<void> {
    if (!this.isStarted) return;

    try {
      await this.boss.stop({ graceful: true, timeout: 15000 });
      this.isStarted = false;
      console.log('[PgBossQueue] Queue stopped gracefully');
    } catch (error) {
      console.error('[PgBossQueue] Error stopping queue:', error);
      throw error;
    }
  }

  /**
   * Start processing jobs with the scan worker
   */
  async startWorker() {
    await this.start();

    // Setup the worker with bounded concurrency
    await this.boss.work<ScanJob>(
      QUEUE_SCAN,
      { teamSize: this.concurrency },
      async (job) => {
        const { scan_id, domain, companyName } = job.data;
        console.log(`[PgBossQueue] Processing scan ${scan_id} for ${domain}`);

        // Dynamic import to avoid circular dependencies
        const { database } = await import('./database.js');
        
        // Update scan status to running
        await database.insertScan({
          id: scan_id,
          domain: domain.toLowerCase(),
          status: 'running',
          created_at: new Date(),
          findings_count: 0,
          artifacts_count: 0,
          metadata: {
            started_at: new Date().toISOString(),
            worker_id: `pgboss-${job.id}`,
            job_id: job.id
          }
        });

        try {
          // Dynamic import to avoid circular dependency
          const { executeScan } = await import('../scan/executeScan.js');
          const startTime = Date.now();

          // Execute the scan with rate limiting built into modules
          const result = await executeScan({
            scan_id,
            domain,
            companyName
          });

          const duration = Date.now() - startTime;

          // Update scan as completed
          await database.insertScan({
            id: scan_id,
            domain: domain.toLowerCase(),
            status: 'completed',
            completed_at: new Date(),
            findings_count: 0, // Will be updated by scan modules
            artifacts_count: 0, // Will be updated by scan modules
            duration_ms: duration,
            metadata: {
              completed_at: new Date().toISOString(),
              worker_id: `pgboss-${job.id}`,
              job_id: job.id,
              modules_completed: result.metadata?.modules_completed || 0,
              scan_result: result
            }
          });

          console.log(`[PgBossQueue] Completed scan ${scan_id} in ${duration}ms`);
          return result;

        } catch (error) {
          console.error(`[PgBossQueue] Scan ${scan_id} failed:`, error);

          // Update scan as failed
          await database.insertScan({
            id: scan_id,
            domain: domain.toLowerCase(),
            status: 'failed',
            completed_at: new Date(),
            findings_count: 0,
            artifacts_count: 0,
            duration_ms: Date.now() - (job.createdon?.getTime() || Date.now()),
            metadata: {
              failed_at: new Date().toISOString(),
              worker_id: `pgboss-${job.id}`,
              job_id: job.id,
              error_message: error instanceof Error ? error.message : 'Unknown error'
            }
          });

          throw error; // Re-throw to mark job as failed
        }
      }
    );

    console.log(`[PgBossQueue] Worker started with ${this.concurrency} concurrent jobs`);
  }

  /**
   * Add a scan job to the queue
   */
  async enqueue(jobData: Omit<ScanJob, 'scan_id'>): Promise<string> {
    await this.start();

    const scan_id = `scan-${nanoid()}`;
    const job: ScanJob = {
      ...jobData,
      scan_id,
      domain: jobData.domain.toLowerCase()
    };

    // Dynamic import to avoid circular dependencies
    const { database } = await import('./database.js');

    // Store initial scan record in database
    await database.insertScan({
      id: scan_id,
      domain: job.domain,
      status: 'queued',
      created_at: new Date(),
      findings_count: 0,
      artifacts_count: 0,
      metadata: {
        queued_at: new Date().toISOString(),
        company_name: job.companyName
      }
    });

    // Add job to pg-boss queue with retry configuration
    const jobId = await this.boss.send(QUEUE_SCAN, job, {
      retryLimit: 3,
      retryDelay: 3000,
      retryBackoff: true,
      priority: job.priority || 50
    });

    console.log(`[PgBossQueue] Enqueued scan ${scan_id} as job ${jobId}`);
    return scan_id;
  }

  /**
   * Health check for the queue
   */
  async healthCheck() {
    if (!this.isStarted) {
      return { status: 'stopped', error: 'Queue not started' };
    }

    try {
      // Get queue metrics from pg-boss (returns total count, not object)
      const queueSize = await this.boss.getQueueSize(QUEUE_SCAN);
      
      return {
        status: 'ok',
        queue_name: QUEUE_SCAN,
        concurrency: this.concurrency,
        waiting: queueSize || 0,
        active: 0, // pg-boss doesn't separate these easily
        completed: 0,
        failed: 0
      };
    } catch (error) {
      return {
        status: 'error',
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Get detailed queue metrics
   */
  async getMetrics() {
    if (!this.isStarted) {
      return { error: 'Queue not started' };
    }

    try {
      const queueSize = await this.boss.getQueueSize(QUEUE_SCAN);
      
      return {
        queue: QUEUE_SCAN,
        max_concurrent: this.concurrency,
        waiting: queueSize || 0,
        active: 0,
        completed: 0,
        failed: 0,
        paused: false
      };
    } catch (error) {
      return { error: error instanceof Error ? error.message : 'Unknown error' };
    }
  }
}