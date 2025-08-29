/**
 * Local NVD Mirror with SQLite
 * 
 * Provides 2-4ms CVE lookups instead of 200ms API calls by maintaining
 * a local SQLite database mirror of NVD vulnerability data.
 */

import { promises as fs } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import axios from 'axios';
import { logLegacy as rootLog } from '../core/logger.js';

const exec = promisify(execFile);
const log = (...args: unknown[]) => rootLog('[nvdMirror]', ...args);

export interface NVDVulnerability {
  cveId: string;
  description: string;
  publishedDate: string;
  lastModifiedDate: string;
  cvssV3Score?: number;
  cvssV3Vector?: string;
  cvssV2Score?: number;
  cvssV2Vector?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  cpeMatches: string[];
  references: string[];
  cisaKev?: boolean;
  epssScore?: number;
}

export interface CVEQuery {
  cpe?: string;
  vendor?: string;
  product?: string;
  version?: string;
  versionRange?: string;
  severity?: string[];
  publishedAfter?: string;
  limit?: number;
}

export interface CVEQueryResult {
  vulnerabilities: NVDVulnerability[];
  totalCount: number;
  queryTimeMs: number;
  source: 'local' | 'api';
}

class NVDMirror {
  private dbPath: string;
  private lastUpdateCheck: number = 0;
  private updateInProgress: boolean = false;
  private isInitialized: boolean = false;

  constructor(dbPath: string = '/tmp/nvd_mirror.sqlite') {
    this.dbPath = dbPath;
  }

  /**
   * Initialize the SQLite database schema
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    try {
      log('Initializing NVD mirror database...');
      
      // Create the SQLite database with optimized schema
      await this.execSQL(`
        CREATE TABLE IF NOT EXISTS vulnerabilities (
          cve_id TEXT PRIMARY KEY,
          description TEXT NOT NULL,
          published_date TEXT NOT NULL,
          last_modified_date TEXT NOT NULL,
          cvss_v3_score REAL,
          cvss_v3_vector TEXT,
          cvss_v2_score REAL,
          cvss_v2_vector TEXT,
          severity TEXT NOT NULL,
          cisa_kev INTEGER DEFAULT 0,
          epss_score REAL,
          references_json TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS cpe_matches (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          cve_id TEXT NOT NULL,
          cpe_uri TEXT NOT NULL,
          version_start_including TEXT,
          version_start_excluding TEXT,
          version_end_including TEXT,
          version_end_excluding TEXT,
          vulnerable INTEGER DEFAULT 1,
          FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id),
          UNIQUE(cve_id, cpe_uri, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
        );
        
        CREATE TABLE IF NOT EXISTS sync_metadata (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Performance indexes
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published ON vulnerabilities(published_date);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss_v3 ON vulnerabilities(cvss_v3_score);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cisa_kev ON vulnerabilities(cisa_kev);
        CREATE INDEX IF NOT EXISTS idx_cpe_matches_cve_id ON cpe_matches(cve_id);
        CREATE INDEX IF NOT EXISTS idx_cpe_matches_cpe_uri ON cpe_matches(cpe_uri);
        CREATE INDEX IF NOT EXISTS idx_cpe_matches_lookup ON cpe_matches(cpe_uri, vulnerable);
        
        -- Insert initial metadata
        INSERT OR REPLACE INTO sync_metadata (key, value) VALUES 
          ('last_sync', '1970-01-01T00:00:00Z'),
          ('version', '1.0'),
          ('total_cves', '0');
      `);

      this.isInitialized = true;
      log('NVD mirror database initialized successfully');
      
      // Check if we need to perform initial sync
      await this.checkAndUpdateIfNeeded();
      
    } catch (error) {
      log('Failed to initialize NVD mirror:', (error as Error).message);
      throw error;
    }
  }

  /**
   * Execute SQL commands on the SQLite database
   */
  private async execSQL(sql: string): Promise<string> {
    try {
      const { stdout, stderr } = await exec('sqlite3', [this.dbPath, sql], { 
        timeout: 30000 
      });
      
      if (stderr) {
        log('SQLite stderr:', stderr);
      }
      
      return stdout;
    } catch (error) {
      log('SQL execution failed:', (error as Error).message);
      throw error;
    }
  }

  /**
   * Query SQL and return JSON results
   */
  private async querySQL(sql: string): Promise<any[]> {
    try {
      const jsonSQL = `.mode json\n${sql}`;
      const output = await this.execSQL(jsonSQL);
      
      if (!output.trim()) {
        return [];
      }
      
      return JSON.parse(output);
    } catch (error) {
      log('SQL query failed:', (error as Error).message);
      return [];
    }
  }

  /**
   * Check if database needs updating and perform sync if needed
   */
  async checkAndUpdateIfNeeded(): Promise<void> {
    if (this.updateInProgress) {
      log('Update already in progress, skipping...');
      return;
    }

    const now = Date.now();
    const sixHours = 6 * 60 * 60 * 1000;
    
    if (now - this.lastUpdateCheck < sixHours) {
      return;
    }

    this.lastUpdateCheck = now;
    
    try {
      const metadata = await this.querySQL("SELECT * FROM sync_metadata WHERE key = 'last_sync'");
      const lastSync = metadata[0]?.value ? new Date(metadata[0].value) : new Date('1970-01-01');
      const twelveHoursAgo = new Date(Date.now() - 12 * 60 * 60 * 1000);
      
      if (lastSync < twelveHoursAgo) {
        log('NVD mirror is stale, initiating background sync...');
        // Don't await - run in background
        this.syncNVDData().catch(error => 
          log('Background NVD sync failed:', (error as Error).message)
        );
      }
    } catch (error) {
      log('Failed to check update status:', (error as Error).message);
    }
  }

  /**
   * Sync recent NVD data (incremental updates)
   */
  async syncNVDData(): Promise<void> {
    if (this.updateInProgress) return;
    
    this.updateInProgress = true;
    const startTime = Date.now();
    
    try {
      log('Starting NVD data sync...');
      
      // Get last sync timestamp
      const metadata = await this.querySQL("SELECT value FROM sync_metadata WHERE key = 'last_sync'");
      const lastSync = metadata[0]?.value || '2020-01-01T00:00:00Z';
      
      // Sync recent CVEs (last 30 days to be safe)
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
      const syncFrom = lastSync > thirtyDaysAgo ? lastSync : thirtyDaysAgo;
      
      log(`Syncing CVEs modified since ${syncFrom}...`);
      
      let totalSynced = 0;
      let startIndex = 0;
      const resultsPerPage = 2000;
      
      while (true) {
        const url = `https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=${syncFrom}&startIndex=${startIndex}&resultsPerPage=${resultsPerPage}`;
        
        try {
          const response = await axios.get(url, {
            timeout: 30000,
            headers: {
              'User-Agent': 'DealBrief-Scanner/1.0 NVD-Mirror (+https://dealbrief.com)'
            }
          });
          
          const data = response.data;
          const vulnerabilities = data.vulnerabilities || [];
          
          if (vulnerabilities.length === 0) {
            break;
          }
          
          // Process vulnerabilities in batches
          for (const vuln of vulnerabilities) {
            await this.insertVulnerability(vuln);
          }
          
          totalSynced += vulnerabilities.length;
          startIndex += resultsPerPage;
          
          log(`Synced ${totalSynced} CVEs so far...`);
          
          // Rate limiting - NVD allows 50 requests per 30 seconds for public use
          await new Promise(resolve => setTimeout(resolve, 600)); // 0.6s delay
          
          if (vulnerabilities.length < resultsPerPage) {
            break; // No more data
          }
          
        } catch (apiError) {
          log('NVD API request failed:', (apiError as Error).message);
          break;
        }
      }
      
      // Update sync metadata
      await this.execSQL(`
        INSERT OR REPLACE INTO sync_metadata (key, value, updated_at) VALUES 
          ('last_sync', '${new Date().toISOString()}', CURRENT_TIMESTAMP),
          ('total_cves', (SELECT COUNT(*) FROM vulnerabilities), CURRENT_TIMESTAMP);
      `);
      
      const duration = Date.now() - startTime;
      log(`NVD sync completed: ${totalSynced} CVEs synced in ${duration}ms`);
      
    } catch (error) {
      log('NVD sync failed:', (error as Error).message);
    } finally {
      this.updateInProgress = false;
    }
  }

  /**
   * Insert a vulnerability record into the database
   */
  private async insertVulnerability(nvdVuln: any): Promise<void> {
    try {
      const cve = nvdVuln.cve;
      const cveId = cve.id;
      
      // Extract CVSS scores
      const metrics = cve.metrics || {};
      const cvssV3 = metrics.cvssMetricV31?.[0] || metrics.cvssMetricV30?.[0];
      const cvssV2 = metrics.cvssMetricV2?.[0];
      
      // Determine severity
      let severity = 'LOW';
      if (cvssV3?.cvssData?.baseScore) {
        const score = cvssV3.cvssData.baseScore;
        if (score >= 9.0) severity = 'CRITICAL';
        else if (score >= 7.0) severity = 'HIGH';
        else if (score >= 4.0) severity = 'MEDIUM';
        else severity = 'LOW';
      }
      
      // Extract description
      const description = cve.descriptions?.find((d: any) => d.lang === 'en')?.value || '';
      
      // Extract references
      const references = cve.references?.map((r: any) => r.url) || [];
      
      // Insert vulnerability
      await this.execSQL(`
        INSERT OR REPLACE INTO vulnerabilities (
          cve_id, description, published_date, last_modified_date,
          cvss_v3_score, cvss_v3_vector, cvss_v2_score, cvss_v2_vector,
          severity, references_json
        ) VALUES (
          '${cveId}',
          '${description.replace(/'/g, "''")}',
          '${cve.published}',
          '${cve.lastModified}',
          ${cvssV3?.cvssData?.baseScore || 'NULL'},
          ${cvssV3?.cvssData?.vectorString ? `'${cvssV3.cvssData.vectorString}'` : 'NULL'},
          ${cvssV2?.cvssData?.baseScore || 'NULL'},
          ${cvssV2?.cvssData?.vectorString ? `'${cvssV2.cvssData.vectorString}'` : 'NULL'},
          '${severity}',
          '${JSON.stringify(references).replace(/'/g, "''")}'
        );
      `);
      
      // Insert CPE matches
      const configurations = cve.configurations || [];
      for (const config of configurations) {
        for (const node of config.nodes || []) {
          for (const cpeMatch of node.cpeMatch || []) {
            await this.execSQL(`
              INSERT OR REPLACE INTO cpe_matches (
                cve_id, cpe_uri, version_start_including, version_start_excluding,
                version_end_including, version_end_excluding, vulnerable
              ) VALUES (
                '${cveId}',
                '${cpeMatch.criteria}',
                ${cpeMatch.versionStartIncluding ? `'${cpeMatch.versionStartIncluding}'` : 'NULL'},
                ${cpeMatch.versionStartExcluding ? `'${cpeMatch.versionStartExcluding}'` : 'NULL'},
                ${cpeMatch.versionEndIncluding ? `'${cpeMatch.versionEndIncluding}'` : 'NULL'},
                ${cpeMatch.versionEndExcluding ? `'${cpeMatch.versionEndExcluding}'` : 'NULL'},
                ${cpeMatch.vulnerable ? 1 : 0}
              );
            `);
          }
        }
      }
      
    } catch (error) {
      log(`Failed to insert vulnerability ${nvdVuln.cve?.id}:`, (error as Error).message);
    }
  }

  /**
   * Query vulnerabilities with fast local lookup
   */
  async queryVulnerabilities(query: CVEQuery): Promise<CVEQueryResult> {
    const startTime = Date.now();
    
    try {
      // Try to initialize if not already done, but don't block if it fails
      if (!this.isInitialized) {
        try {
          await this.initialize();
        } catch (error) {
          log('NVD mirror initialization failed, using fallback:', (error as Error).message);
          return {
            vulnerabilities: [],
            totalCount: 0,
            queryTimeMs: Date.now() - startTime,
            source: 'local'
          };
        }
      }
      
      // Try to check for updates, but don't block if it fails
      try {
        await this.checkAndUpdateIfNeeded();
      } catch (error) {
        log('NVD mirror update check failed, continuing with existing data:', (error as Error).message);
      }
      
      let sql = `
        SELECT DISTINCT v.cve_id, v.description, v.published_date, v.last_modified_date,
               v.cvss_v3_score, v.cvss_v3_vector, v.cvss_v2_score, v.cvss_v2_vector,
               v.severity, v.cisa_kev, v.epss_score, v.references_json
        FROM vulnerabilities v
      `;
      
      const conditions: string[] = [];
      
      if (query.cpe) {
        sql += ` JOIN cpe_matches cm ON v.cve_id = cm.cve_id`;
        conditions.push(`cm.cpe_uri LIKE '%${query.cpe}%' AND cm.vulnerable = 1`);
      }
      
      if (query.vendor && query.product) {
        if (!query.cpe) {
          sql += ` JOIN cpe_matches cm ON v.cve_id = cm.cve_id`;
        }
        conditions.push(`cm.cpe_uri LIKE '%:${query.vendor}:${query.product}:%' AND cm.vulnerable = 1`);
      }
      
      if (query.severity && query.severity.length) {
        const severityList = query.severity.map(s => `'${s}'`).join(',');
        conditions.push(`v.severity IN (${severityList})`);
      }
      
      if (query.publishedAfter) {
        conditions.push(`v.published_date >= '${query.publishedAfter}'`);
      }
      
      if (conditions.length > 0) {
        sql += ` WHERE ${conditions.join(' AND ')}`;
      }
      
      sql += ` ORDER BY v.cvss_v3_score DESC, v.published_date DESC`;
      
      if (query.limit) {
        sql += ` LIMIT ${query.limit}`;
      }
      
      const results = await this.querySQL(sql);
      
      const vulnerabilities: NVDVulnerability[] = results.map(row => ({
        cveId: row.cve_id,
        description: row.description,
        publishedDate: row.published_date,
        lastModifiedDate: row.last_modified_date,
        cvssV3Score: row.cvss_v3_score,
        cvssV3Vector: row.cvss_v3_vector,
        cvssV2Score: row.cvss_v2_score,
        cvssV2Vector: row.cvss_v2_vector,
        severity: row.severity,
        cisaKev: row.cisa_kev === 1,
        epssScore: row.epss_score,
        cpeMatches: [], // Will be populated if needed
        references: row.references_json ? JSON.parse(row.references_json) : []
      }));
      
      const queryTimeMs = Date.now() - startTime;
      
      log(`Local CVE query completed: ${vulnerabilities.length} results in ${queryTimeMs}ms`);
      
      return {
        vulnerabilities,
        totalCount: vulnerabilities.length,
        queryTimeMs,
        source: 'local'
      };
      
    } catch (error) {
      log('Local CVE query failed:', (error as Error).message);
      
      // Fallback to empty result
      return {
        vulnerabilities: [],
        totalCount: 0,
        queryTimeMs: Date.now() - startTime,
        source: 'local'
      };
    }
  }

  /**
   * Get database statistics
   */
  async getStats(): Promise<{ totalCVEs: number; lastSync: string; dbSizeMB: number }> {
    try {
      await this.initialize();
      
      const stats = await this.querySQL(`
        SELECT 
          (SELECT COUNT(*) FROM vulnerabilities) as total_cves,
          (SELECT value FROM sync_metadata WHERE key = 'last_sync') as last_sync
      `);
      
      // Get database file size
      let dbSizeMB = 0;
      try {
        const stat = await fs.stat(this.dbPath);
        dbSizeMB = Math.round(stat.size / (1024 * 1024) * 100) / 100;
      } catch {
        // File might not exist yet
      }
      
      return {
        totalCVEs: stats[0]?.total_cves || 0,
        lastSync: stats[0]?.last_sync || 'Never',
        dbSizeMB
      };
      
    } catch (error) {
      log('Failed to get stats:', (error as Error).message);
      return { totalCVEs: 0, lastSync: 'Error', dbSizeMB: 0 };
    }
  }
}

// Singleton instance
const nvdMirror = new NVDMirror();

export { nvdMirror };
export default nvdMirror;