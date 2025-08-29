export const QUEUE_SCAN = 'scan';

export interface ScanJob {
  scan_id: string;
  domain: string;
  companyName?: string;
  modules?: string[];
  priority?: number;
  scheduleAt?: string;
}

export interface ScanResult {
  scan_id: string;
  domain: string;
  ok: boolean;
  findings: Array<{
    module: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    message: string;
  }>;
  startedAt: string;
  finishedAt: string;
}