#!/usr/bin/env npx ts-node

/**
 * Smoke test for Nuclei findings persistence
 * Validates that Nuclei vulnerabilities are properly captured and persisted as artifacts
 */

import { pool } from '../apps/workers/dist/core/artifactStore.js';
import { runNuclei } from '../apps/workers/dist/util/nucleiWrapper.js';

async function smokeTestNuclei(): Promise<void> {
  const testScanId = `smoke-test-${Date.now()}`;
  
  console.log('🔍 Starting Nuclei smoke test...');
  
  try {
    // Test with a known vulnerable target that should trigger findings
    const result = await runNuclei({
      url: 'http://testphp.vulnweb.com',
      tags: ['exposure', 'tech'],
      timeout: 30,
      scanId: testScanId
    });
    
    console.log(`✅ Nuclei execution completed: exit code ${result.exitCode}, success: ${result.success}`);
    console.log(`📊 Results: ${result.results.length} parsed, ${result.persistedCount || 0} persisted`);
    
    // Check if findings were persisted as artifacts
    const rows = await pool.query(
      'SELECT * FROM artifacts WHERE meta->>\'scan_id\' = $1 AND type = \'nuclei_vulnerability\'',
      [testScanId]
    );
    
    if (rows.rows.length === 0) {
      console.error('❌ No nuclei_vulnerability artifacts found in database');
      process.exit(1);
    }
    
    console.log(`✅ Found ${rows.rows.length} nuclei_vulnerability artifacts in database`);
    
    // Validate artifact structure
    const sampleArtifact = rows.rows[0];
    if (!sampleArtifact.meta || !sampleArtifact.meta.template_id) {
      console.error('❌ Artifact missing required metadata (template_id)');
      process.exit(1);
    }
    
    console.log(`✅ Sample artifact validated: ${sampleArtifact.meta.template_id}`);
    
    // Clean up test artifacts
    await pool.query(
      'DELETE FROM artifacts WHERE meta->>\'scan_id\' = $1',
      [testScanId]
    );
    
    console.log('🧹 Cleaned up test artifacts');
    console.log('🎉 Nuclei smoke test PASSED!');
    
  } catch (error) {
    console.error('❌ Nuclei smoke test FAILED:', (error as Error).message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

smokeTestNuclei().catch(error => {
  console.error('💥 Smoke test crashed:', error);
  process.exit(1);
});