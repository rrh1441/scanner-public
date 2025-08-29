#!/usr/bin/env tsx

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import { Pool } from 'pg';
import { runSpiderFoot } from '../apps/workers/modules/spiderFoot.ts';

const exec = promisify(execFile);

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgres://postgres:IewmvSSWz7JLvuG@localhost:5432"
});

let testResults = {
  artifacts: 0,
  subdomains: 0,
  ips: 0,
  emails: 0,
  intel: 0
};

async function log(message: string) {
  console.log(`[SpiderFoot-Validator] ${message}`);
}

async function runSpiderFootTest() {
  log("Running SpiderFoot test with domain: example.com, scanId: selftest");
  
  try {
    // Clear any existing test artifacts
    await pool.query(`DELETE FROM artifacts WHERE meta->>'scan_id' = 'selftest'`);
    
    const startTime = Date.now();
    const artifactsCreated = await runSpiderFoot({ domain: "example.com", scanId: "selftest" });
    const duration = Date.now() - startTime;
    
    log(`SpiderFoot completed in ${duration}ms, reported ${artifactsCreated} artifacts`);
    
    // Get scan summary from database
    const summaryResult = await pool.query(`
      SELECT val_text, meta FROM artifacts 
      WHERE type = 'scan_summary' 
      AND meta->>'scan_id' = 'selftest' 
      AND meta->>'scan_module' = 'spiderfoot'
      ORDER BY created_at DESC LIMIT 1
    `);
    
    // Get actual artifact counts by type
    const countsResult = await pool.query(`
      SELECT type, COUNT(*) as count FROM artifacts 
      WHERE meta->>'scan_id' = 'selftest' 
      AND type != 'scan_summary'
      GROUP BY type
    `);
    
    testResults.artifacts = artifactsCreated;
    
    for (const row of countsResult.rows) {
      switch (row.type) {
        case 'subdomain':
          testResults.subdomains = parseInt(row.count);
          break;
        case 'ip':
          testResults.ips = parseInt(row.count);
          break;
        case 'email':
          testResults.emails = parseInt(row.count);
          break;
        case 'threat':
        case 'breach':
        case 'vuln':
          testResults.intel += parseInt(row.count);
          break;
      }
    }
    
    return {
      artifactsCreated,
      duration,
      summary: summaryResult.rows[0]?.val_text || 'No summary found',
      rawOutputSize: duration > 1000 ? 'OK' : 'TIMEOUT_SUSPECTED'
    };
    
  } catch (error: any) {
    log(`SpiderFoot test failed: ${error.message}`);
    return {
      artifactsCreated: 0,
      duration: 0,
      summary: `Error: ${error.message}`,
      rawOutputSize: 'ERROR',
      error: error.message
    };
  }
}

async function checkBinary() {
  log("Checking SpiderFoot binary availability...");
  
  try {
    // Test if spiderfoot.py is accessible
    await exec('which', ['spiderfoot.py']);
    log("✅ spiderfoot.py found in PATH");
    return true;
  } catch (error) {
    log("❌ spiderfoot.py not found in PATH");
    
    try {
      // Check if sf.py exists
      await fs.access('/opt/spiderfoot/sf.py');
      log("Found /opt/spiderfoot/sf.py, creating symlink...");
      
      await exec('ln', ['-sf', '/opt/spiderfoot/sf.py', '/usr/local/bin/spiderfoot.py']);
      log("✅ Created symlink: /usr/local/bin/spiderfoot.py -> /opt/spiderfoot/sf.py");
      return true;
      
    } catch (linkError: any) {
      log(`❌ Failed to create symlink: ${linkError.message}`);
      return false;
    }
  }
}

async function checkApiKeys() {
  log("Checking API key availability...");
  
  const requiredKeys = [
    'SHODAN_API_KEY',
    'CENSYS_API_ID', 
    'CENSYS_API_SECRET',
    'HAVEIBEENPWNED_API_KEY'
  ];
  
  let missingKeys: string[] = [];
  let availableKeys: string[] = [];
  
  for (const key of requiredKeys) {
    if (process.env[key]) {
      availableKeys.push(`✅ ${key}`);
    } else {
      missingKeys.push(`❌ ${key}`);
    }
  }
  
  log(`API Keys Status:`);
  availableKeys.forEach(key => log(`  ${key}`));
  missingKeys.forEach(key => log(`  ${key}`));
  
  if (missingKeys.length > 0) {
    log(`Warning: ${missingKeys.length} API keys missing. SpiderFoot may have limited functionality.`);
  }
  
  return missingKeys.length === 0;
}

async function checkTimeout() {
  log("Checking timeout configuration...");
  
  const currentTimeout = process.env.SPIDERFOOT_TIMEOUT_MS || '300000';
  log(`Current timeout: ${currentTimeout}ms`);
  
  if (parseInt(currentTimeout) < 480000) {
    log("Increasing timeout to 8 minutes...");
    process.env.SPIDERFOOT_TIMEOUT_MS = '480000';
    return true;
  }
  
  return false;
}

async function analyzeSpiderFootOutput() {
  log("Analyzing SpiderFoot output types...");
  
  try {
    // Get all artifacts from the test run
    const result = await pool.query(`
      SELECT meta FROM artifacts 
      WHERE meta->>'scan_id' = 'selftest' 
      AND meta ? 'spiderfoot_type'
    `);
    
    const uniqueTypes = new Set<string>();
    
    for (const row of result.rows) {
      const spiderfootType = row.meta?.spiderfoot_type;
      if (spiderfootType) {
        uniqueTypes.add(spiderfootType);
      }
    }
    
    log(`Found SpiderFoot types: ${Array.from(uniqueTypes).join(', ')}`);
    
    // Save diagnostic info
    const diagnosticData = {
      timestamp: new Date().toISOString(),
      uniqueTypes: Array.from(uniqueTypes),
      totalArtifacts: result.rows.length,
      testResults
    };
    
    await fs.writeFile('/tmp/sf_diag.json', JSON.stringify(diagnosticData, null, 2));
    log("Diagnostic data saved to /tmp/sf_diag.json");
    
    return uniqueTypes.size > 0;
    
  } catch (error: any) {
    log(`Failed to analyze output: ${error.message}`);
    return false;
  }
}

async function main() {
  log("Starting SpiderFoot validation and self-healing...");
  
  let attempt = 1;
  const maxAttempts = 4;
  
  while (attempt <= maxAttempts) {
    log(`\n=== Attempt ${attempt}/${maxAttempts} ===`);
    
    // Step 1: Run SpiderFoot test
    const testResult = await runSpiderFootTest();
    
    log(`Test result: ${testResult.artifactsCreated} artifacts created`);
    log(`Summary: ${testResult.summary}`);
    log(`Duration: ${testResult.duration}ms`);
    
    // Step 2: Check if successful
    if (testResult.artifactsCreated > 0) {
      log("✅ SpiderFoot OK - artifacts created successfully!");
      
      // Step 4: Log final summary
      log("\n=== Final Summary ===");
      console.log(JSON.stringify(testResults, null, 2));
      
      process.exit(0);
    }
    
    // Step 3: Self-healing attempts
    log(`❌ No artifacts created, attempting remediation...`);
    
    let remediated = false;
    
    // A. Binary check
    if (testResult.error?.includes('not found') || testResult.error?.includes('ENOENT')) {
      log("Attempting binary remediation...");
      if (await checkBinary()) {
        remediated = true;
      }
    }
    
    // B. API key check (always check)
    if (!remediated) {
      log("Checking API keys...");
      await checkApiKeys(); // Always log status, but don't fail on missing keys
    }
    
    // C. Timeout check
    if (!remediated && (testResult.rawOutputSize === 'TIMEOUT_SUSPECTED' || testResult.duration < 5000)) {
      log("Attempting timeout remediation...");
      if (await checkTimeout()) {
        remediated = true;
      }
    }
    
    // D. Output analysis
    if (!remediated) {
      log("Analyzing SpiderFoot output types...");
      await analyzeSpiderFootOutput();
    }
    
    if (!remediated && attempt === maxAttempts) {
      log("❌ All remediation attempts failed");
      
      // Final diagnostic output
      log("\n=== Diagnostic Information ===");
      log(`Final test results: ${JSON.stringify(testResults, null, 2)}`);
      log(`Last error: ${testResult.error || 'Unknown'}`);
      
      process.exit(1);
    }
    
    attempt++;
    
    // Wait before retry
    if (attempt <= maxAttempts) {
      log(`Waiting 5 seconds before retry...`);
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
}

// Handle cleanup
process.on('exit', async () => {
  try {
    await pool.end();
  } catch (error) {
    // Ignore cleanup errors
  }
});

main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
}); 