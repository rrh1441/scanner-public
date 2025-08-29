import { Pool, PoolClient } from 'pg';
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
  severity?: string;
  val_text?: string;
  src_url?: string;
  sha256?: string;
  mime_type?: string;
  metadata?: any;
}

/**
 * Direct PostgreSQL database service without LocalStore overhead
 * Designed for high concurrency and scalability
 */
export class DatabaseService {
  private pool: Pool;
  private reportsDir: string = './scan-reports';
  private artifactsDir: string = './scan-artifacts';
  private initialized = false;

  constructor() {
    this.pool = new Pool({
      user: process.env.POSTGRES_USER || process.env.USER || 'postgres',
      host: process.env.POSTGRES_HOST || 'localhost',
      database: process.env.POSTGRES_DB || 'scanner_local',
      password: process.env.POSTGRES_PASSWORD || '',
      port: parseInt(process.env.POSTGRES_PORT || '5432'),
      max: 80, // Significantly increased for high concurrency (40% of PG max_connections)
      min: 10, // Minimum pool size for immediate availability
      idleTimeoutMillis: 10000, // Release idle connections faster
      connectionTimeoutMillis: 5000, // Timeout for getting connection
      statement_timeout: 30000, // 30s query timeout
      keepAlive: true, // Keep connections alive
      keepAliveInitialDelayMillis: 10000,
    });

    // Handle pool errors with recovery
    this.pool.on('error', (err) => {
      console.error('[Database] Pool error:', err);
      // Log pool stats during errors for debugging
      console.error('[Database] Pool stats during error:', {
        total: this.pool.totalCount,
        idle: this.pool.idleCount,
        waiting: this.pool.waitingCount
      });
    });

    // Add connection acquire/release logging for debugging
    this.pool.on('acquire', () => {
      // Only log if pool utilization is high
      if (this.pool.totalCount >= 60) {
        console.warn('[Database] High pool utilization:', {
          total: this.pool.totalCount,
          idle: this.pool.idleCount,
          waiting: this.pool.waitingCount
        });
      }
    });

    this.pool.on('connect', () => {
      console.log('[Database] New connection established. Pool size:', this.pool.totalCount);
    });
  }

  /**
   * Initialize database connection (call this explicitly)
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      // Create directories
      await fs.mkdir(this.reportsDir, { recursive: true });
      await fs.mkdir(this.artifactsDir, { recursive: true });
      
      // Test database connection
      const client = await this.pool.connect();
      try {
        await client.query('SELECT COUNT(*) FROM scans LIMIT 1');
        console.log('✅ Database connection verified');
        this.initialized = true;
      } finally {
        client.release();
      }
    } catch (error) {
      console.error('❌ Database initialization failed:', error);
      throw error;
    }
  }

  /**
   * Execute raw SQL query with automatic connection management and retry logic
   */
  async query<T = any>(text: string, params?: any[], retries = 3): Promise<{ rows: T[]; rowCount: number }> {
    let lastError: Error | null = null;
    
    for (let attempt = 1; attempt <= retries; attempt++) {
      let client: PoolClient | null = null;
      
      try {
        // Add timeout to connection acquisition
        client = await Promise.race([
          this.pool.connect(),
          new Promise<never>((_, reject) => 
            setTimeout(() => reject(new Error('Connection acquisition timeout')), 5000)
          )
        ]);
        
        const result = await client.query(text, params);
        return {
          rows: result.rows,
          rowCount: result.rowCount || 0
        };
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        
        if (attempt < retries) {
          console.warn(`[Database] Query attempt ${attempt} failed, retrying:`, lastError.message);
          // Exponential backoff
          await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 100));
        }
      } finally {
        if (client) {
          try {
            client.release();
          } catch (releaseError) {
            console.error('[Database] Error releasing connection:', releaseError);
          }
        }
      }
    }
    
    throw lastError || new Error('Query failed after all retries');
  }

  /**
   * Execute query with transaction support
   */
  async transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  // Scan Operations
  async insertScan(scan: Partial<ScanData>): Promise<void> {
    await this.query(`
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
      scan.status,
      scan.created_at,
      scan.completed_at,
      scan.findings_count || 0,
      scan.artifacts_count || 0,
      scan.duration_ms,
      scan.metadata ? JSON.stringify(scan.metadata) : null
    ]);
  }

  async getScan(scanId: string): Promise<ScanData | null> {
    const result = await this.query<ScanData>(
      'SELECT * FROM scans WHERE id = $1',
      [scanId]
    );
    
    if (result.rows.length === 0) return null;
    
    const scan = result.rows[0];
    // Parse metadata if it exists
    if (scan.metadata && typeof scan.metadata === 'string') {
      try {
        scan.metadata = JSON.parse(scan.metadata);
      } catch (e) {
        console.warn(`Failed to parse metadata for scan ${scanId}:`, e);
      }
    }
    
    return scan;
  }

  async getRecentScans(limit: number = 50): Promise<ScanData[]> {
    const result = await this.query<ScanData>(
      'SELECT * FROM scans ORDER BY created_at DESC LIMIT $1',
      [limit]
    );
    
    // Parse metadata for each scan
    return result.rows.map(scan => {
      if (scan.metadata && typeof scan.metadata === 'string') {
        try {
          scan.metadata = JSON.parse(scan.metadata);
        } catch (e) {
          console.warn(`Failed to parse metadata for scan ${scan.id}:`, e);
        }
      }
      return scan;
    });
  }

  // Finding Operations
  async insertFinding(finding: Partial<FindingData>): Promise<void> {
    await this.query(`
      INSERT INTO findings (id, scan_id, type, severity, title, description, data, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (id) DO UPDATE SET
        type = EXCLUDED.type,
        severity = EXCLUDED.severity,
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        data = EXCLUDED.data
    `, [
      finding.id,
      finding.scan_id,
      finding.type,
      finding.severity,
      finding.title,
      finding.description,
      finding.data ? JSON.stringify(finding.data) : null,
      finding.created_at || new Date()
    ]);
  }

  async getFindingsByScanId(scanId: string): Promise<FindingData[]> {
    const result = await this.query<FindingData>(
      'SELECT * FROM findings WHERE scan_id = $1 ORDER BY created_at DESC',
      [scanId]
    );
    
    // Parse data field for each finding
    return result.rows.map(finding => {
      if (finding.data && typeof finding.data === 'string') {
        try {
          finding.data = JSON.parse(finding.data);
        } catch (e) {
          console.warn(`Failed to parse data for finding ${finding.id}:`, e);
        }
      }
      return finding;
    });
  }

  // Artifact Operations  
  async insertArtifact(artifact: Partial<ArtifactData>): Promise<void> {
    await this.query(`
      INSERT INTO artifacts (id, scan_id, type, file_path, size_bytes, created_at, severity, val_text, src_url, sha256, mime_type, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      ON CONFLICT (id) DO UPDATE SET
        type = EXCLUDED.type,
        file_path = EXCLUDED.file_path,
        size_bytes = EXCLUDED.size_bytes,
        severity = EXCLUDED.severity,
        val_text = EXCLUDED.val_text,
        src_url = EXCLUDED.src_url,
        sha256 = EXCLUDED.sha256,
        mime_type = EXCLUDED.mime_type,
        metadata = EXCLUDED.metadata
    `, [
      artifact.id,
      artifact.scan_id,
      artifact.type,
      artifact.file_path,
      artifact.size_bytes || 0,
      artifact.created_at || new Date(),
      artifact.severity,
      artifact.val_text,
      artifact.src_url,
      artifact.sha256,
      artifact.mime_type,
      artifact.metadata ? JSON.stringify(artifact.metadata) : null
    ]);
  }

  async getArtifactCount(scanId: string): Promise<number> {
    const result = await this.query<{count: number}>(
      'SELECT COUNT(*) as count FROM artifacts WHERE scan_id = $1',
      [scanId]
    );
    return parseInt(result.rows[0].count.toString());
  }

  // File Operations
  async saveReport(scanId: string, report: Buffer, format: 'pdf' | 'html' = 'pdf'): Promise<string> {
    const scanDir = join(this.reportsDir, scanId);
    await fs.mkdir(scanDir, { recursive: true });
    
    const filename = `report.${format}`;
    const filePath = join(scanDir, filename);
    
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
    const reportPath = join(this.reportsDir, scanId, `report.${format}`);
    try {
      await fs.access(reportPath);
      return reportPath;
    } catch {
      return null;
    }
  }

  // Health check
  async healthCheck(): Promise<{ status: 'ok' | 'error'; details: any }> {
    try {
      const result = await this.query('SELECT NOW() as timestamp');
      return {
        status: 'ok',
        details: {
          timestamp: result.rows[0].timestamp,
          pool_total: this.pool.totalCount,
          pool_idle: this.pool.idleCount,
          pool_waiting: this.pool.waitingCount
        }
      };
    } catch (error) {
      return {
        status: 'error',
        details: { error: error instanceof Error ? error.message : 'Unknown error' }
      };
    }
  }

  // Shutdown
  async close(): Promise<void> {
    await this.pool.end();
    console.log('✅ Database connections closed');
  }

  // Getters for pool stats
  get poolStats() {
    return {
      total: this.pool.totalCount,
      idle: this.pool.idleCount,
      waiting: this.pool.waitingCount
    };
  }
}

// Singleton instance
export const database = new DatabaseService();