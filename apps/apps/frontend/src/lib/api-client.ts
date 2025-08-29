// Client-side API that uses the proxy route

export interface Scan {
  scan_id: string;
  scanId?: string;
  company_name: string;
  domain: string;
  original_domain: string;
  tags: string[];
  status: 'queued' | 'processing' | 'completed' | 'failed';
  created_at: string;
  updated_at: string;
}

export interface CreateScanRequest {
  companyName: string;
  domain: string;
  tags?: string[];
}

export interface BulkScanRequest {
  companies: CreateScanRequest[];
}

export interface Finding {
  id: string;
  scan_id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  remediation?: string;
  evidence?: Record<string, unknown>;
  created_at: string;
}

export interface ApiHealth {
  status: string;
  pubsub: string;
  firestore: string;
  timestamp: string;
}

export interface BulkScanError {
  error: string;
  company?: CreateScanRequest;
  row?: number;
}

class ScannerAPI {
  private async request(path: string, options?: RequestInit) {
    // Try direct GCP API call first (no auth required if backend is public)
    const GCP_API_BASE = process.env.NEXT_PUBLIC_SCANNER_API_URL || 'https://scanner-api-242181373909.us-central1.run.app';
    
    try {
      const response = await fetch(`${GCP_API_BASE}/${path}`, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...options?.headers,
        },
      });
      
      if (!response.ok) {
        throw new Error(`Request failed: ${response.status}`);
      }
      
      return response.json();
    } catch (error) {
      // Fallback to proxy if direct call fails
      console.warn('Direct API call failed, trying proxy:', error);
      const response = await fetch(`/api/proxy/${path}`, options);
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || `Request failed: ${response.status}`);
      }
      
      return response.json();
    }
  }
  
  async createScan(data: CreateScanRequest): Promise<Scan> {
    return this.request('scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
  }
  
  async getScanStatus(scanId: string): Promise<Scan | null> {
    try {
      return await this.request(`scan/${scanId}/status`);
    } catch (error) {
      if (error instanceof Error && error.message.includes('404')) {
        return null;
      }
      throw error;
    }
  }
  
  async getScanFindings(scanId: string): Promise<Finding[]> {
    try {
      return await this.request(`scan/${scanId}/findings`);
    } catch (error) {
      if (error instanceof Error && error.message.includes('404')) {
        return [];
      }
      throw error;
    }
  }
  
  async getScanArtifacts(scanId: string): Promise<Record<string, unknown> | null> {
    try {
      return await this.request(`scan/${scanId}/artifacts`);
    } catch {
      return null;
    }
  }
  
  async createBulkScans(data: BulkScanRequest): Promise<{ scans: Scan[], errors: BulkScanError[] }> {
    return this.request('scan/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
  }
  
  async uploadCSV(file: File): Promise<{ scans: Scan[], errors: BulkScanError[] }> {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await fetch('/api/proxy/scan/csv', {
      method: 'POST',
      body: formData,
    });
    
    if (!response.ok) {
      const error = await response.text();
      throw new Error(`CSV upload failed: ${error}`);
    }
    
    return response.json();
  }
  
  async checkHealth(): Promise<ApiHealth> {
    // Use local health endpoint instead of backend to avoid auth issues
    const response = await fetch('/api/health');
    if (!response.ok) {
      throw new Error(`Health check failed: ${response.status}`);
    }
    return response.json();
  }
  
  async waitForScanCompletion(
    scanId: string, 
    onUpdate?: (scan: Scan) => void,
    timeoutMs: number = 300000
  ): Promise<Scan> {
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeoutMs) {
      const scan = await this.getScanStatus(scanId);
      
      if (!scan) {
        throw new Error('Scan not found');
      }
      
      if (onUpdate) {
        onUpdate(scan);
      }
      
      if (scan.status === 'completed' || scan.status === 'failed') {
        return scan;
      }
      
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
    
    throw new Error('Scan timeout');
  }
}

export const scannerAPI = new ScannerAPI();