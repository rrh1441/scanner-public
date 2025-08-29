import Bull, { Queue, Job, JobOptions } from 'bull';
import { nanoid } from 'nanoid';
import { database, ScanData } from './database.js';

export interface ScanJobData {
  scan_id: string;
  domain: string;
  companyName?: string;
  priority?: 'low' | 'normal' | 'high';
  created_at: Date;
}

export interface ScanJobStatus {
  scan_id: string;
  status: 'queued' | 'active' | 'completed' | 'failed' | 'delayed' | 'waiting';
  position_in_queue?: number;
  progress?: number;
  started_at?: Date;
  completed_at?: Date;
  error_message?: string;
  duration_ms?: number;
}

export interface QueueMetrics {
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  delayed: number;
  paused: boolean;
}

/**
 * Redis-based queue service using Bull
 * Provides persistent, scalable job queue management
 */
export class QueueService {
  private scanQueue: Queue<ScanJobData>;
  private redisConfig: any;

  constructor(concurrency: number = 8) {
    // Redis connection config
    this.redisConfig = {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      db: parseInt(process.env.REDIS_DB || '0'),
      maxRetriesPerRequest: 3,
      retryDelayOnFailover: 100,
    };

    // Initialize scan queue
    this.scanQueue = new Bull<ScanJobData>('scan-queue', {
      redis: this.redisConfig,
      defaultJobOptions: {
        removeOnComplete: 50, // Keep last 50 completed jobs
        removeOnFail: 50,     // Keep last 50 failed jobs
        attempts: 1,          // No retries for scans to avoid duplicates
        backoff: {
          type: 'exponential',
          delay: 2000
        }
      }
    });

    this.setupProcessor(concurrency);
    this.setupEventHandlers();
  }

  private setupProcessor(concurrency: number) {
    // Process scan jobs with specified concurrency
    this.scanQueue.process(concurrency, async (job: Job<ScanJobData>) => {
      const { scan_id, domain, companyName } = job.data;
      
      console.log(`[Queue] Processing scan ${scan_id} for ${domain}`);
      
      // Update scan status to running
      await database.insertScan({
        id: scan_id,
        domain: domain.toLowerCase(),
        status: 'running',
        created_at: job.data.created_at,
        findings_count: 0,
        artifacts_count: 0,
        metadata: {
          started_at: new Date().toISOString(),
          worker_id: `worker-${job.id}`
        }
      });

      try {
        // Dynamic import to avoid circular dependency
        const { executeScan } = await import('../scan/executeScan.js');
        
        const startTime = Date.now();
        
        // Execute the scan
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
          created_at: job.data.created_at,
          completed_at: new Date(),
          findings_count: 0, // Will be updated by scan modules
          artifacts_count: 0, // Will be updated by scan modules
          duration_ms: duration,
          metadata: {
            completed_at: new Date().toISOString(),
            worker_id: `worker-${job.id}`,
            modules_completed: result.metadata?.modules_completed || 0,
            scan_result: result
          }
        });

        console.log(`[Queue] Completed scan ${scan_id} in ${duration}ms`);
        return result;

      } catch (error) {
        console.error(`[Queue] Scan ${scan_id} failed:`, error);
        
        // Update scan as failed
        await database.insertScan({
          id: scan_id,
          domain: domain.toLowerCase(),
          status: 'failed',
          created_at: job.data.created_at,
          completed_at: new Date(),
          findings_count: 0,
          artifacts_count: 0,
          duration_ms: Date.now() - job.processedOn!,
          metadata: {
            failed_at: new Date().toISOString(),
            worker_id: `worker-${job.id}`,
            error_message: error instanceof Error ? error.message : 'Unknown error'
          }
        });

        throw error; // Re-throw to mark job as failed
      }
    });
  }

  private setupEventHandlers() {
    this.scanQueue.on('completed', (job, result) => {
      console.log(`[Queue] Job ${job.id} completed successfully`);
    });

    this.scanQueue.on('failed', (job, err) => {
      console.error(`[Queue] Job ${job.id} failed:`, err.message);
    });

    this.scanQueue.on('stalled', (job) => {
      console.warn(`[Queue] Job ${job.id} stalled and will be retried`);
    });

    this.scanQueue.on('error', (error) => {
      console.error('[Queue] Queue error:', error);
    });
  }

  /**
   * Add a scan job to the queue
   */
  async enqueue(jobData: Omit<ScanJobData, 'scan_id' | 'created_at'>): Promise<string> {
    const scan_id = `scan-${nanoid()}`;
    const created_at = new Date();
    
    const job: ScanJobData = {
      ...jobData,
      scan_id,
      created_at,
      domain: jobData.domain.toLowerCase()
    };

    // Store initial scan record in database
    await database.insertScan({
      id: scan_id,
      domain: job.domain,
      status: 'queued',
      created_at,
      findings_count: 0,
      artifacts_count: 0,
      metadata: {
        priority: jobData.priority || 'normal',
        queued_at: created_at.toISOString()
      }
    });

    // Add to Redis queue with priority
    const priority = this.getPriorityValue(jobData.priority);
    const bullJob = await this.scanQueue.add(job, {
      priority,
      delay: 0
    });

    console.log(`[Queue] Enqueued scan ${scan_id} for ${job.domain} (job ID: ${bullJob.id})`);
    
    return scan_id;
  }

  /**
   * Get job status from queue or database
   */
  async getJobStatus(scan_id: string): Promise<ScanJobStatus | null> {
    // First try to find in Redis queue (active/waiting jobs)
    const jobs = await this.scanQueue.getJobs(['waiting', 'active', 'completed', 'failed', 'delayed']);
    const queueJob = jobs.find(job => job.data.scan_id === scan_id);
    
    if (queueJob) {
      // Get position in queue for waiting jobs
      let position: number | undefined;
      if (await queueJob.getState() === 'waiting') {
        const waiting = await this.scanQueue.getWaiting();
        position = waiting.findIndex(j => j.id === queueJob.id) + 1;
        position = position > 0 ? position : undefined;
      }

      return {
        scan_id,
        status: await queueJob.getState() as any,
        position_in_queue: position,
        progress: queueJob.progress(),
        started_at: queueJob.processedOn ? new Date(queueJob.processedOn) : undefined,
        completed_at: queueJob.finishedOn ? new Date(queueJob.finishedOn) : undefined,
        error_message: queueJob.failedReason,
        duration_ms: queueJob.finishedOn && queueJob.processedOn ? 
          queueJob.finishedOn - queueJob.processedOn : undefined
      };
    }

    // If not in queue, check database for completed/failed scans
    const scan = await database.getScan(scan_id);
    if (!scan) return null;

    return {
      scan_id,
      status: scan.status as any,
      started_at: scan.metadata?.started_at ? new Date(scan.metadata.started_at) : undefined,
      completed_at: scan.completed_at,
      error_message: scan.metadata?.error_message,
      duration_ms: scan.duration_ms
    };
  }

  /**
   * Cancel a job (if it's still in queue)
   */
  async cancelJob(scan_id: string): Promise<boolean> {
    const jobs = await this.scanQueue.getJobs(['waiting', 'delayed']);
    const job = jobs.find(j => j.data.scan_id === scan_id);
    
    if (job) {
      await job.remove();
      
      // Update database
      await database.insertScan({
        id: scan_id,
        domain: 'cancelled',
        status: 'cancelled',
        created_at: new Date(),
        completed_at: new Date(),
        findings_count: 0,
        artifacts_count: 0
      });

      console.log(`[Queue] Cancelled job ${scan_id}`);
      return true;
    }

    return false;
  }

  /**
   * Get queue metrics
   */
  async getMetrics(): Promise<QueueMetrics> {
    const [waiting, active, completed, failed, delayed] = await Promise.all([
      this.scanQueue.getWaiting(),
      this.scanQueue.getActive(),
      this.scanQueue.getCompleted(),
      this.scanQueue.getFailed(),
      this.scanQueue.getDelayed()
    ]);

    return {
      waiting: waiting.length,
      active: active.length,
      completed: completed.length,
      failed: failed.length,
      delayed: delayed.length,
      paused: await this.scanQueue.isPaused()
    };
  }

  /**
   * Get all jobs in various states
   */
  async getAllJobs() {
    const [waiting, active, completed, failed, delayed] = await Promise.all([
      this.scanQueue.getWaiting(),
      this.scanQueue.getActive(),
      this.scanQueue.getCompleted().then(jobs => jobs.slice(0, 20)), // Limit recent
      this.scanQueue.getFailed().then(jobs => jobs.slice(0, 20)),
      this.scanQueue.getDelayed()
    ]);

    return { waiting, active, completed, failed, delayed };
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<{ status: 'ok' | 'error'; details: any }> {
    try {
      const metrics = await this.getMetrics();
      const redisInfo = await this.scanQueue.client.ping();
      
      return {
        status: 'ok',
        details: {
          redis_ping: redisInfo,
          queue_metrics: metrics,
          queue_name: this.scanQueue.name
        }
      };
    } catch (error) {
      return {
        status: 'error',
        details: { error: error instanceof Error ? error.message : 'Unknown error' }
      };
    }
  }

  /**
   * Clean completed/failed jobs
   */
  async cleanJobs(grace: number = 24 * 60 * 60 * 1000): Promise<void> {
    await this.scanQueue.clean(grace, 'completed');
    await this.scanQueue.clean(grace, 'failed');
    console.log('[Queue] Cleaned old completed/failed jobs');
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    console.log('[Queue] Shutting down queue service...');
    
    // Wait for active jobs to complete (with timeout)
    const activeJobs = await this.scanQueue.getActive();
    if (activeJobs.length > 0) {
      console.log(`[Queue] Waiting for ${activeJobs.length} active jobs to complete...`);
      
      // Wait max 2 minutes for jobs to complete
      const timeout = setTimeout(async () => {
        console.log('[Queue] Timeout reached, closing queue');
        await this.scanQueue.close();
      }, 2 * 60 * 1000);

      await this.scanQueue.whenCurrentJobsFinished();
      clearTimeout(timeout);
    }

    await this.scanQueue.close();
    console.log('✅ Queue service shutdown complete');
  }

  private getPriorityValue(priority?: string): number {
    switch (priority) {
      case 'high': return 10;
      case 'normal': return 5;
      case 'low': return 1;
      default: return 5;
    }
  }
}