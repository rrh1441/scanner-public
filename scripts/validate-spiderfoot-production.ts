#!/usr/bin/env tsx

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import { Pool } from 'pg';

const exec = promisify(execFile);

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
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

async function runSpiderFootDirect(domain: string, scanId: string) {
  log(`Running SpiderFoot directly for ${domain} with scanId: ${scanId}`);
  
  try {
    // Clear any existing test artifacts
    await pool.query(`DELETE FROM artifacts WHERE meta->>'scan_id' = $1`, [scanId]);
    
    const timeout = parseInt(process.env.SPIDERFOOT_TIMEOUT_MS || '480000');
    log(`Using timeout: ${timeout}ms`);
    
    // Run SpiderFoot with JSON output
    const result = await exec('timeout', [
      `${Math.floor(timeout / 1000)}s`,
      'spiderfoot.py',
      '-s', domain,
      '-t', 'DOMAIN_NAME',
      '-m', 'sfp_dnsresolve,sfp_subdomain_enum,sfp_shodan,sfp_haveibeenpwned',
      '-o', 'json',
      '-q'
    ]);
    
    log(`SpiderFoot completed. Output size: ${result.stdout.length} bytes`);
    
    if (result.stdout.length < 50) {
      log("⚠️ SpiderFoot output is very small");
      return { artifactsCreated: 0, rawOutput: result.stdout, error: 'Minimal output' };
    }
    
    // Parse JSON output
    let jsonData;
    try {
      jsonData = JSON.parse(result.stdout);
    } catch (parseError) {
      log(`❌ Failed to parse SpiderFoot JSON: ${parseError}`);
      return { artifactsCreated: 0, rawOutput: result.stdout, error: 'JSON parse failed' };
    }
    
    if (!Array.isArray(jsonData)) {
      log("❌ SpiderFoot output is not an array");
      return { artifactsCreated: 0, rawOutput: result.stdout, error: 'Invalid JSON structure' };
    }
    
    log(`SpiderFoot returned ${jsonData.length} raw results`);
    
    // Process results and create artifacts
    let artifactsCreated = 0;
    const keepAsIntel = new Set([
      'MALICIOUS_IPADDR', 'MALICIOUS_SUBDOMAIN', 'MALICIOUS_COHOST',
      'BLACKLISTED_IPADDR', 'BLACKLISTED_SUBDOMAIN', 'BLACKLISTED_COHOST',
      'VULNERABILITY', 'VULNERABILITY_CVE_CRITICAL', 'VULNERABILITY_CVE_HIGH',
      'BREACH_DATA', 'LEAKED_PASSWORD', 'DARKWEB_MENTION',
      'THREAT_INTEL', 'BOTNET_MEMBER', 'MALWARE_HASH'
    ]);
    
    for (const row of jsonData) {
      if (!row.type || !row.data) continue;
      
      let artifactType = 'intel';
      let value = row.data;
      
      // Categorize the finding
      if (row.type.includes('IP_ADDRESS') || row.type.includes('NETBLOCK')) {
        artifactType = 'ip';
      } else if (row.type.includes('SUBDOMAIN') || row.type.includes('DOMAIN')) {
        artifactType = 'subdomain';
      } else if (row.type.includes('EMAIL')) {
        artifactType = 'email';
      } else if (keepAsIntel.has(row.type)) {
        artifactType = 'threat';
      } else {
        continue; // Skip unknown types
      }
      
      // Insert artifact
      await pool.query(`
        INSERT INTO artifacts (type, val_text, meta, severity, created_at) 
        VALUES ($1, $2, $3, $4, NOW())
      `, [
        artifactType,
        value,
        JSON.stringify({
          scan_id: scanId,
          scan_module: 'spiderfoot',
          spiderfoot_type: row.type,
          confidence: row.confidence || 100,
          source_module: row.module || 'unknown'
        }),
        artifactType === 'threat' ? 'medium' : 'info'
      ]);
      
      artifactsCreated++;
      
      // Update test results
      switch (artifactType) {
        case 'subdomain':
          testResults.subdomains++;
          break;
        case 'ip':
          testResults.ips++;
          break;
        case 'email':
          testResults.emails++;
          break;
        case 'threat':
        case 'intel':
          testResults.intel++;
          break;
      }
    }
    
    // Create scan summary
    const summaryText = `SpiderFoot scan completed. Found ${artifactsCreated} artifacts from ${jsonData.length} raw results.`;
    await pool.query(`
      INSERT INTO artifacts (type, val_text, meta, severity, created_at) 
      VALUES ('scan_summary', $1, $2, $3, NOW())
    `, [
      summaryText,
      JSON.stringify({
        scan_id: scanId,
        scan_module: 'spiderfoot',
        artifacts_created: artifactsCreated,
        raw_results: jsonData.length,
        status: 'completed'
      }),
      'info'
    ]);
    
    testResults.artifacts = artifactsCreated;
    
    return {
      artifactsCreated,
      rawOutput: result.stdout,
      rawResults: jsonData.length,
      summary: summaryText
    };
    
  } catch (error: any) {
    log(`SpiderFoot test failed: ${error.message}`);
    
    // Create error summary
    const errorSummary = `SpiderFoot scan failed: ${error.message}`;
    await pool.query(`
      INSERT INTO artifacts (type, val_text, meta, severity, created_at) 
      VALUES ('scan_summary', $1, $2, $3, NOW())
    `, [
      errorSummary,
      JSON.stringify({
        scan_id: scanId,
        scan_module: 'spiderfoot',
        artifacts_created: 0,
        status: 'failed',
        error: error.message
      }),
      'error'
    ]);
    
    return {
      artifactsCreated: 0,
      rawOutput: '',
      error: error.message,
      summary: errorSummary
    };
  }
}

async function checkBinary() {
  log("Checking SpiderFoot binary availability...");
  
  try {
    // Always check if we need to create the wrapper script
    await fs.access('/opt/spiderfoot/sf.py');
    log("Found /opt/spiderfoot/sf.py, creating proper wrapper script...");
    
    // Create a wrapper script that runs SpiderFoot from its directory
    const wrapperScript = `#!/bin/bash
cd /opt/spiderfoot
python3 sf.py "$@"
`;
    await fs.writeFile('/usr/local/bin/spiderfoot.py', wrapperScript);
    await exec('chmod', ['+x', '/usr/local/bin/spiderfoot.py']);
    log("✅ Created SpiderFoot wrapper script");
    return true;
    
  } catch (error: any) {
    log(`❌ Failed to create wrapper script: ${error.message}`);
    return false;
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

async function analyzeSpiderFootOutput(scanId: string) {
  log("Analyzing SpiderFoot output types...");
  
  try {
    // Get all artifacts from the test run
    const result = await pool.query(`
      SELECT meta FROM artifacts 
      WHERE meta->>'scan_id' = $1 
      AND meta ? 'spiderfoot_type'
    `, [scanId]);
    
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
  const testDomain = "example.com";
  const testScanId = "selftest";
  
  while (attempt <= maxAttempts) {
    log(`\n=== Attempt ${attempt}/${maxAttempts} ===`);
    
    // Step 1: Run SpiderFoot test
    const testResult = await runSpiderFootDirect(testDomain, testScanId);
    
    log(`Test result: ${testResult.artifactsCreated} artifacts created`);
    log(`Summary: ${testResult.summary || 'No summary'}`);
    log(`Raw output size: ${testResult.rawOutput?.length || 0} bytes`);
    
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
    
    // A. Binary check - always check if modules directory error occurs
    if (testResult.error?.includes('not found') || testResult.error?.includes('ENOENT') || testResult.error?.includes('Modules directory does not exist')) {
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
    if (!remediated && (testResult.error?.includes('timeout') || (testResult.rawOutput?.length || 0) < 200)) {
      log("Attempting timeout remediation...");
      if (await checkTimeout()) {
        remediated = true;
      }
    }
    
    // D. Output analysis
    if (!remediated) {
      log("Analyzing SpiderFoot output types...");
      await analyzeSpiderFootOutput(testScanId);
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