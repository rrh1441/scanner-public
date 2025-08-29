import { Pool, Client } from 'pg';
import { promises as fs } from 'fs';
import { join } from 'path';

export interface ScanData {
  id: string;
  domain: string;
  status: string;
  created_at: Date;
  completed_at?: Date;
  findings_count: number;
  artifacts_count: number;
  duration_ms?: number;
  metadata?: any;
}

export interface FindingData {
  id: string;
  scan_id: string;
  type: string;
  severity: string;
  title: string;
  description?: string;
  data?: any;
  created_at: Date;
}

export interface ArtifactData {
  id: string;
  scan_id: string;
  type: string;
  file_path: string;
  size_bytes: number;
  created_at: Date;
}

export class LocalStore {
  private pool: Pool;
  private reportsDir: string;
  private artifactsDir: string;

  constructor() {
    this.pool = new Pool({
      user: process.env.POSTGRES_USER || process.env.USER || 'postgres',
      host: process.env.POSTGRES_HOST || 'localhost',
      database: process.env.POSTGRES_DB || 'scanner_local',
      password: process.env.POSTGRES_PASSWORD || '',
      port: parseInt(process.env.POSTGRES_PORT || '5432'),
      max: 20, // Maximum number of connections
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    });
    this.reportsDir = './scan-reports';
    this.artifactsDir = './scan-artifacts';
    this.init();
  }

  private async init() {
    // Create directories
    await fs.mkdir(this.reportsDir, { recursive: true });
    await fs.mkdir(this.artifactsDir, { recursive: true });
    
    // Skip database schema creation - assume it's already set up
    // Use setup-pg-schema.sql to initialize the database first
    console.log('💾 PostgreSQL schema assumed to be set up already');
    
    // Test database connection
    const client = await this.pool.connect();
    try {
      // Simple test query to verify connection and schema
      await client.query('SELECT COUNT(*) FROM scans');
      console.log('✅ PostgreSQL connection and schema verified');
    } finally {
      client.release();
    }
  }

  // Database operations
  async insertScan(scan: Partial<ScanData>): Promise<void> {
    console.log('[LocalStore] insertScan called with:', {
      id: scan.id,
      status: scan.status,
      findings_count: scan.findings_count,
      artifacts_count: scan.artifacts_count,
      duration_ms: scan.duration_ms
    });
    
    const client = await this.pool.connect();
    try {
      await client.query(`
        INSERT INTO scans (id, domain, status, created_at, completed_at, findings_count, artifacts_count, duration_ms, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (id) DO UPDATE SET
          status = EXCLUDED.status,
          completed_at = EXCLUDED.completed_at,
          findings_count = EXCLUDED.findings_count,
          artifacts_count = EXCLUDED.artifacts_count,
          duration_ms = EXCLUDED.duration_ms,
          metadata = EXCLUDED.metadata
      `, [
        scan.id,
        scan.domain,
        scan.status || 'pending',
        scan.created_at || new Date(),
        scan.completed_at,
        scan.findings_count ?? 0,
        scan.artifacts_count ?? 0,
        scan.duration_ms,
        scan.metadata
      ]);
    } finally {
      client.release();
    }
  }

  async insertFinding(finding: Partial<FindingData>): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(`
        INSERT INTO findings (id, scan_id, type, severity, title, description, data, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (id) DO NOTHING
      `, [
        finding.id,
        finding.scan_id,
        finding.type,
        finding.severity,
        finding.title,
        finding.description,
        finding.data,
        finding.created_at || new Date()
      ]);
    } finally {
      client.release();
    }
  }

  async insertArtifact(artifact: Partial<ArtifactData & {severity?: string, val_text?: string, src_url?: string, sha256?: string, mime_type?: string, metadata?: any}>): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query(`
        INSERT INTO artifacts (id, scan_id, type, file_path, size_bytes, severity, val_text, src_url, sha256, mime_type, metadata, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (id) DO NOTHING
      `, [
        artifact.id,
        artifact.scan_id,
        artifact.type,
        artifact.file_path,
        artifact.size_bytes || 0,
        (artifact as any).severity,
        (artifact as any).val_text,
        (artifact as any).src_url,
        (artifact as any).sha256,
        (artifact as any).mime_type,
        (artifact as any).metadata,
        artifact.created_at || new Date()
      ]);
    } finally {
      client.release();
    }
  }

  async getScan(scanId: string): Promise<ScanData | null> {
    const client = await this.pool.connect();
    try {
      const result = await client.query('SELECT * FROM scans WHERE id = $1', [scanId]);
      
      if (result.rows.length === 0) return null;
      
      const row = result.rows[0];
      return {
        ...row,
        created_at: new Date(row.created_at),
        completed_at: row.completed_at ? new Date(row.completed_at) : undefined,
        metadata: row.metadata
      };
    } finally {
      client.release();
    }
  }

  async getRecentScans(limit: number = 50): Promise<ScanData[]> {
    const client = await this.pool.connect();
    try {
      const result = await client.query('SELECT * FROM scans ORDER BY created_at DESC LIMIT $1', [limit]);
      
      return result.rows.map(row => ({
        ...row,
        created_at: new Date(row.created_at),
        completed_at: row.completed_at ? new Date(row.completed_at) : undefined,
        metadata: row.metadata
      }));
    } finally {
      client.release();
    }
  }

  async getFindingsByScanId(scanId: string): Promise<FindingData[]> {
    const client = await this.pool.connect();
    try {
      const result = await client.query('SELECT * FROM findings WHERE scan_id = $1 ORDER BY created_at DESC', [scanId]);
      
      return result.rows.map(row => ({
        ...row,
        created_at: new Date(row.created_at),
        data: row.data
      }));
    } finally {
      client.release();
    }
  }

  // File operations  
  async saveReport(scanId: string, report: Buffer, format: 'pdf' | 'html' = 'pdf'): Promise<string> {
    const scanDir = join(this.reportsDir, scanId);
    await fs.mkdir(scanDir, { recursive: true });
    
    const fileName = `report.${format}`;
    const filePath = join(scanDir, fileName);
    await fs.writeFile(filePath, report);
    
    return filePath;
  }

  async saveArtifact(scanId: string, filename: string, data: Buffer): Promise<string> {
    const scanDir = join(this.artifactsDir, scanId);
    await fs.mkdir(scanDir, { recursive: true });
    
    const filePath = join(scanDir, filename);
    await fs.writeFile(filePath, data);
    
    return filePath;
  }

  async getReportPath(scanId: string, format: 'pdf' | 'html' = 'pdf'): Promise<string | null> {
    const filePath = join(this.reportsDir, scanId, `report.${format}`);
    try {
      await fs.access(filePath);
      return filePath;
    } catch {
      return null;
    }
  }

  async getArtifactCount(scanId: string): Promise<number> {
    const client = await this.pool.connect();
    try {
      const result = await client.query('SELECT COUNT(*) FROM artifacts WHERE scan_id = $1', [scanId]);
      return parseInt(result.rows[0].count);
    } finally {
      client.release();
    }
  }

  async query(text: string, params?: any[]): Promise<any> {
    const client = await this.pool.connect();
    try {
      return await client.query(text, params);
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}