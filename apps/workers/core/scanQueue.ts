import { EventEmitter } from 'events';
import { nanoid } from 'nanoid';
import { LocalStore } from './localStore.js';

export interface ScanJobRequest {
  scan_id: string;
  domain: string;
  companyName?: string;
  priority?: 'low' | 'normal' | 'high';
  created_at: Date;
}

export interface ScanJobStatus {
  scan_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  position_in_queue?: number;
  worker_id?: string;
  started_at?: Date;
  completed_at?: Date;
  error_message?: string;
  progress?: {
    total_modules: number;
    completed_modules: number;
    current_module?: string;
  };
}

export interface QueueMetrics {
  queued_jobs: number;
  running_jobs: number;
  total_workers: number;
  active_workers: number;
  completed_today: number;
  failed_today: number;
  average_scan_time_ms: number;
}

export class ScanQueue extends EventEmitter {
  private queue: ScanJobRequest[] = [];
  private runningJobs = new Map<string, ScanJobStatus>();
  private completedJobs = new Map<string, ScanJobStatus>();
  private workers = new Map<string, ScanWorker>();
  private store: LocalStore;
  private maxConcurrentScans: number;
  private isProcessing = false;

  constructor(maxConcurrentScans = 3, store?: LocalStore) {
    super();
    this.maxConcurrentScans = maxConcurrentScans;
    this.store = store || new LocalStore();
    
    // Initialize workers
    for (let i = 0; i < maxConcurrentScans; i++) {
      const workerId = `worker-${i + 1}`;
      const worker = new ScanWorker(workerId, this.store);
      this.workers.set(workerId, worker);
      
      // Listen for worker events
      worker.on('job-started', (jobStatus: ScanJobStatus) => {
        this.runningJobs.set(jobStatus.scan_id, jobStatus);
        this.emit('job-started', jobStatus);
      });
      
      worker.on('job-progress', (jobStatus: ScanJobStatus) => {
        this.runningJobs.set(jobStatus.scan_id, jobStatus);
        this.emit('job-progress', jobStatus);
      });
      
      worker.on('job-completed', (jobStatus: ScanJobStatus) => {
        this.runningJobs.delete(jobStatus.scan_id);
        this.completedJobs.set(jobStatus.scan_id, jobStatus);
        this.emit('job-completed', jobStatus);
        
        // Process next job in queue
        this.processQueue();
      });
      
      worker.on('job-failed', (jobStatus: ScanJobStatus) => {
        this.runningJobs.delete(jobStatus.scan_id);
        this.completedJobs.set(jobStatus.scan_id, jobStatus);
        this.emit('job-failed', jobStatus);
        
        // Process next job in queue
        this.processQueue();
      });
    }
  }

  /**
   * Add a scan job to the queue
   */
  async enqueue(jobRequest: Omit<ScanJobRequest, 'scan_id' | 'created_at'>): Promise<string> {
    const scan_id = jobRequest.domain ? `scan-${nanoid()}` : nanoid();
    
    const job: ScanJobRequest = {
      ...jobRequest,
      scan_id,
      created_at: new Date(),
      priority: jobRequest.priority || 'normal'
    };

    // Store initial scan record
    await this.store.insertScan({
      id: scan_id,
      domain: job.domain.toLowerCase(),
      status: 'queued',
      created_at: job.created_at,
      findings_count: 0,
      artifacts_count: 0,
      metadata: {
        priority: job.priority,
        queued_at: job.created_at.toISOString()
      }
    });

    // Add to queue (sort by priority)
    this.queue.push(job);
    this.sortQueue();
    
    console.log(`[Queue] Enqueued scan ${scan_id} for ${job.domain} (position: ${this.queue.length})`);
    
    this.emit('job-queued', {
      scan_id,
      status: 'queued',
      position_in_queue: this.queue.length
    } as ScanJobStatus);

    // Try to process immediately
    this.processQueue();
    
    return scan_id;
  }

  /**
   * Get status of a specific scan job
   */
  getJobStatus(scan_id: string): ScanJobStatus | null {
    // Check if it's running
    if (this.runningJobs.has(scan_id)) {
      return this.runningJobs.get(scan_id)!;
    }
    
    // Check if it's completed
    if (this.completedJobs.has(scan_id)) {
      return this.completedJobs.get(scan_id)!;
    }
    
    // Check if it's in queue
    const queuePosition = this.queue.findIndex(job => job.scan_id === scan_id);
    if (queuePosition !== -1) {
      return {
        scan_id,
        status: 'queued',
        position_in_queue: queuePosition + 1
      };
    }
    
    return null;
  }

  /**
   * Cancel a queued or running scan
   */
  async cancelJob(scan_id: string): Promise<boolean> {
    // Remove from queue if present
    const queueIndex = this.queue.findIndex(job => job.scan_id === scan_id);
    if (queueIndex !== -1) {
      this.queue.splice(queueIndex, 1);
      
      // Update scan record
      await this.store.insertScan({
        id: scan_id,
        domain: 'cancelled',
        status: 'cancelled',
        created_at: new Date(),
        completed_at: new Date(),
        findings_count: 0,
        artifacts_count: 0
      });
      
      console.log(`[Queue] Cancelled queued scan ${scan_id}`);
      return true;
    }
    
    // Cancel running job
    if (this.runningJobs.has(scan_id)) {
      const jobStatus = this.runningJobs.get(scan_id)!;
      const worker = this.workers.get(jobStatus.worker_id!);
      
      if (worker) {
        await worker.cancelJob(scan_id);
        console.log(`[Queue] Cancelled running scan ${scan_id}`);
        return true;
      }
    }
    
    return false;
  }

  /**
   * Get queue metrics and statistics
   */
  getMetrics(): QueueMetrics {
    const today = new Date().toDateString();
    const completedToday = Array.from(this.completedJobs.values())
      .filter(job => job.completed_at?.toDateString() === today && job.status === 'completed').length;
    
    const failedToday = Array.from(this.completedJobs.values())
      .filter(job => job.completed_at?.toDateString() === today && job.status === 'failed').length;
    
    // Calculate average scan time from recent completions
    const recentCompletions = Array.from(this.completedJobs.values())
      .filter(job => job.status === 'completed' && job.started_at && job.completed_at)
      .slice(-10); // Last 10 scans
    
    const avgScanTime = recentCompletions.length > 0
      ? recentCompletions.reduce((sum, job) => {
          return sum + (job.completed_at!.getTime() - job.started_at!.getTime());
        }, 0) / recentCompletions.length
      : 0;

    return {
      queued_jobs: this.queue.length,
      running_jobs: this.runningJobs.size,
      total_workers: this.workers.size,
      active_workers: Array.from(this.workers.values()).filter(w => w.isBusy()).length,
      completed_today: completedToday,
      failed_today: failedToday,
      average_scan_time_ms: Math.round(avgScanTime)
    };
  }

  /**
   * Get all jobs currently in queue
   */
  getQueuedJobs(): ScanJobStatus[] {
    return this.queue.map((job, index) => ({
      scan_id: job.scan_id,
      status: 'queued' as const,
      position_in_queue: index + 1
    }));
  }

  /**
   * Get all currently running jobs
   */
  getRunningJobs(): ScanJobStatus[] {
    return Array.from(this.runningJobs.values());
  }

  private sortQueue() {
    // Sort by priority (high > normal > low), then by creation time (oldest first)
    this.queue.sort((a, b) => {
      const priorityOrder = { high: 3, normal: 2, low: 1 };
      const aPriority = priorityOrder[a.priority || 'normal'];
      const bPriority = priorityOrder[b.priority || 'normal'];
      
      if (aPriority !== bPriority) {
        return bPriority - aPriority; // Higher priority first
      }
      
      return a.created_at.getTime() - b.created_at.getTime(); // Older first
    });
  }

  private async processQueue() {
    if (this.isProcessing || this.queue.length === 0) {
      return;
    }
    
    this.isProcessing = true;
    
    try {
      // Find available workers
      const availableWorkers = Array.from(this.workers.values()).filter(worker => !worker.isBusy());
      
      // Assign jobs to available workers
      while (this.queue.length > 0 && availableWorkers.length > 0) {
        const job = this.queue.shift()!;
        const worker = availableWorkers.shift()!;
        
        console.log(`[Queue] Assigning scan ${job.scan_id} to ${worker.getId()}`);
        
        // Start job on worker (non-blocking)
        worker.startJob(job).catch(error => {
          console.error(`[Queue] Worker ${worker.getId()} failed to start job ${job.scan_id}:`, error);
        });
      }
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Gracefully shutdown the queue and all workers
   */
  async shutdown(): Promise<void> {
    console.log('[Queue] Shutting down scan queue...');
    
    // Stop accepting new jobs
    this.queue.length = 0;
    
    // Wait for running jobs to complete or timeout after 2 minutes
    const shutdownPromises = Array.from(this.workers.values()).map(worker => 
      worker.shutdown()
    );
    
    try {
      await Promise.race([
        Promise.all(shutdownPromises),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Shutdown timeout')), 120000))
      ]);
      
      console.log('[Queue] All workers shut down gracefully');
    } catch (error) {
      console.error('[Queue] Forced shutdown due to timeout');
    }
    
    // Close database connections
    this.store.close();
  }
}

// Worker class to handle individual scan execution
class ScanWorker extends EventEmitter {
  private workerId: string;
  private store: LocalStore;
  private currentJob: ScanJobRequest | null = null;
  private isCancelled = false;

  constructor(workerId: string, store: LocalStore) {
    super();
    this.workerId = workerId;
    this.store = store;
  }

  getId(): string {
    return this.workerId;
  }

  isBusy(): boolean {
    return this.currentJob !== null;
  }

  async startJob(job: ScanJobRequest): Promise<void> {
    if (this.currentJob) {
      throw new Error(`Worker ${this.workerId} is already busy`);
    }

    this.currentJob = job;
    this.isCancelled = false;

    const jobStatus: ScanJobStatus = {
      scan_id: job.scan_id,
      status: 'running',
      worker_id: this.workerId,
      started_at: new Date(),
      progress: {
        total_modules: 16, // Tier1 module count
        completed_modules: 0
      }
    };

    this.emit('job-started', jobStatus);

    try {
      // Dynamic import to avoid circular dependency
      const { executeScan } = await import('../scan/executeScan.js');
      
      console.log(`[Worker:${this.workerId}] Starting scan ${job.scan_id} for ${job.domain}`);
      
      // Execute the scan
      const result = await executeScan({
        scan_id: job.scan_id,
        domain: job.domain,
        companyName: job.companyName
      });

      if (this.isCancelled) {
        throw new Error('Job was cancelled');
      }

      // Job completed successfully
      jobStatus.status = 'completed';
      jobStatus.completed_at = new Date();
      
      console.log(`[Worker:${this.workerId}] Completed scan ${job.scan_id}`);
      
      this.emit('job-completed', jobStatus);
    } catch (error) {
      console.error(`[Worker:${this.workerId}] Scan ${job.scan_id} failed:`, error);
      
      jobStatus.status = 'failed';
      jobStatus.completed_at = new Date();
      jobStatus.error_message = (error as Error).message;
      
      this.emit('job-failed', jobStatus);
    } finally {
      this.currentJob = null;
    }
  }

  async cancelJob(scan_id: string): Promise<void> {
    if (this.currentJob?.scan_id === scan_id) {
      console.log(`[Worker:${this.workerId}] Cancelling job ${scan_id}`);
      this.isCancelled = true;
    }
  }

  async shutdown(): Promise<void> {
    if (this.currentJob) {
      console.log(`[Worker:${this.workerId}] Waiting for current job to complete...`);
      
      // Wait for current job to finish (with timeout)
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error(`Worker ${this.workerId} shutdown timeout`));
        }, 30000); // 30 second timeout
        
        const checkCompletion = () => {
          if (!this.currentJob) {
            clearTimeout(timeout);
            resolve();
          } else {
            setTimeout(checkCompletion, 1000);
          }
        };
        
        checkCompletion();
      });
    }
  }
}