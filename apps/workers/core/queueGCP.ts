import { CloudTasksClient } from '@google-cloud/tasks';
import { Firestore } from '@google-cloud/firestore';

export interface ScanJob {
  id: string;
  companyName: string;
  domain: string;
  tags?: string[];
  createdAt: string;
}

export interface JobStatus {
  id: string;
  state: 'queued' | 'processing' | 'done' | 'failed';
  updated: number;
  message?: string;
  resultUrl?: string;
  error?: string;
}

export class CloudTasksQueue {
  private tasksClient: CloudTasksClient;
  private firestore: Firestore;
  private queuePath: string;
  private workerId: string;

  constructor() {
    this.tasksClient = new CloudTasksClient();
    this.firestore = new Firestore();
    
    // Generate unique worker ID
    this.workerId = process.env.K_SERVICE || `worker-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    // Queue path format: projects/PROJECT_ID/locations/LOCATION/queues/QUEUE_NAME
    const projectId = process.env.GOOGLE_CLOUD_PROJECT || 'precise-victory-467219-s4';
    const location = process.env.CLOUD_TASKS_LOCATION || 'us-central1';
    const queueName = process.env.CLOUD_TASKS_QUEUE || 'scan-queue';
    
    this.queuePath = this.tasksClient.queuePath(projectId, location, queueName);
    
    console.log(`[queue] Worker initialized with ID: ${this.workerId}`);
    console.log(`[queue] Using Cloud Tasks queue: ${this.queuePath}`);
  }

  async addJob(id: string, job: any): Promise<void> {
    try {
      // Create Cloud Task
      const task = {
        httpRequest: {
          httpMethod: 'POST' as const,
          url: process.env.WORKER_URL || `https://scanner-job-${process.env.GOOGLE_CLOUD_PROJECT}.a.run.app`,
          headers: {
            'Content-Type': 'application/json',
          },
          body: Buffer.from(JSON.stringify({ ...job, id })).toString('base64'),
        },
      };

      await this.tasksClient.createTask({
        parent: this.queuePath,
        task,
      });

      // Store job status in Firestore
      await this.firestore.collection('jobs').doc(id).set({
        state: 'queued',
        updated: Date.now(),
        message: 'Scan queued and waiting for processing',
        ...job
      });

      console.log('[queue] enqueued', id);
    } catch (error) {
      console.error('[queue] Error adding job:', error);
      throw error;
    }
  }

  async getNextJob(): Promise<ScanJob | null> {
    // In Cloud Run, jobs are pushed to the service via HTTP
    // This method is not used in the Cloud Tasks model
    console.log('[queue] getNextJob called - not used with Cloud Tasks push model');
    return null;
  }

  async completeJob(jobId: string): Promise<void> {
    try {
      await this.updateStatus(jobId, 'done', 'Scan completed successfully');
    } catch (error) {
      console.error(`[queue] Error completing job ${jobId}:`, error);
    }
  }

  async failJob(jobId: string, error: string): Promise<void> {
    try {
      await this.updateStatus(jobId, 'failed', `Scan failed: ${error}`);
    } catch (error) {
      console.error(`[queue] Error failing job ${jobId}:`, error);
    }
  }

  async cleanupStaleJobs(): Promise<void> {
    // Cloud Tasks handles retries and cleanup automatically
    console.log('[queue] Cleanup handled by Cloud Tasks');
  }

  async updateStatus(id: string, state: JobStatus['state'], message?: string, resultUrl?: string): Promise<void> {
    const statusUpdate: Partial<JobStatus> = {
      state,
      updated: Date.now()
    };

    if (message) statusUpdate.message = message;
    if (resultUrl) statusUpdate.resultUrl = resultUrl;

    await this.firestore.collection('jobs').doc(id).update(statusUpdate);
    console.log(`[queue] Updated job ${id} status: ${state}${message ? ` - ${message}` : ''}`);
  }

  async getStatus(id: string): Promise<JobStatus | null> {
    const doc = await this.firestore.collection('jobs').doc(id).get();
    if (!doc.exists) return null;
    return doc.data() as JobStatus;
  }

  // Legacy methods for backwards compatibility
  async nextJob(blockMs = 5000): Promise<[string, ScanJob] | null> {
    // Not used with Cloud Tasks
    return null;
  }

  async setStatus(id: string, state: JobStatus['state'], extra: Record<string, any> = {}) {
    await this.firestore.collection('jobs').doc(id).update({
      state,
      updated: Date.now(),
      ...extra
    });
  }
}

// Export as default for drop-in replacement
export default CloudTasksQueue;