import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { runBackendExposureScanner } from '../modules/backendExposureScanner.js';
import { insertArtifact, pool } from '../core/artifactStore.js';
import { BackendIdentifier } from '../modules/endpointDiscovery.js';

describe('Backend Exposure Scanner', () => {
  const testScanId = 'test-backend-exposure-' + Date.now();

  beforeAll(async () => {
    // Setup test data - insert mock backend identifiers
    const mockBackendIds: BackendIdentifier[] = [
      {
        provider: 'firebase',
        id: 'test-project-123',
        raw: 'test-project-123.firebaseio.com',
        src: { file: 'test.js', line: 1 }
      },
      {
        provider: 's3',
        id: 'test-bucket-public',
        raw: 'test-bucket-public.s3.amazonaws.com',
        src: { file: 'config.js', line: 15 }
      },
      {
        provider: 'azure',
        id: 'testaccount123',
        raw: 'testaccount123.blob.core.windows.net',
        src: { file: 'azure-config.js', line: 8 }
      }
    ];

    await insertArtifact({
      type: 'backend_identifiers',
      severity: 'INFO',
      val_text: `Test backend identifiers for scan ${testScanId}`,
      meta: {
        scan_id: testScanId,
        backendArr: mockBackendIds
      }
    });
  });

  afterAll(async () => {
    // Cleanup test data
    await pool.query(
      'DELETE FROM artifacts WHERE meta->>\'scan_id\' = $1',
      [testScanId]
    );
    await pool.query(
      'DELETE FROM findings WHERE artifact_id IN (SELECT id FROM artifacts WHERE meta->>\'scan_id\' = $1)',
      [testScanId]
    );
  });

  it('should process backend identifiers and attempt probes', async () => {
    const findings = await runBackendExposureScanner({ scanId: testScanId });
    
    // Should return number of findings (likely 0 for test backends, but function should complete)
    expect(typeof findings).toBe('number');
    expect(findings).toBeGreaterThanOrEqual(0);
    
    // Verify scan summary artifact was created
    const summaryResult = await pool.query(
      `SELECT * FROM artifacts 
       WHERE type = 'scan_summary' 
       AND meta->>'scan_id' = $1 
       AND meta->>'module' = 'backendExposureScanner'`,
      [testScanId]
    );
    
    expect(summaryResult.rows.length).toBe(1);
    expect(summaryResult.rows[0].meta.findings).toBe(findings);
  }, 30000); // 30 second timeout for network requests

  it('should handle missing backend identifiers gracefully', async () => {
    const noDataScanId = 'no-data-' + Date.now();
    const findings = await runBackendExposureScanner({ scanId: noDataScanId });
    
    // Should return 0 when no backend identifiers are found
    expect(findings).toBe(0);
  });

  it('should throttle requests appropriately', async () => {
    const startTime = Date.now();
    
    // Run scanner which should make multiple throttled requests
    await runBackendExposureScanner({ scanId: testScanId });
    
    const duration = Date.now() - startTime;
    
    // With throttling (2 req/second) and multiple backends, should take some time
    // This is a basic sanity check that throttling is working
    expect(duration).toBeGreaterThan(500); // At least 500ms for throttled requests
  });
});