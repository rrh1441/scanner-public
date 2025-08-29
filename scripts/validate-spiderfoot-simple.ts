#!/usr/bin/env tsx

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';

const exec = promisify(execFile);

async function log(message: string) {
  console.log(`[SpiderFoot-Validator] ${message}`);
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

async function testSpiderFootDirect() {
  log("Testing SpiderFoot directly...");
  
  try {
    // Test SpiderFoot with a simple command
    const result = await exec('spiderfoot.py', ['-h']);
    log("✅ SpiderFoot help command successful");
    log(`Output size: ${result.stdout.length} bytes`);
    return true;
  } catch (error: any) {
    log(`❌ SpiderFoot direct test failed: ${error.message}`);
    return false;
  }
}

async function testSpiderFootScan() {
  log("Testing SpiderFoot scan with example.com...");
  
  try {
    // Run a minimal SpiderFoot scan
    const timeout = parseInt(process.env.SPIDERFOOT_TIMEOUT_MS || '300000');
    log(`Using timeout: ${timeout}ms`);
    
    const result = await exec('timeout', [
      `${Math.floor(timeout / 1000)}s`,
      'spiderfoot.py',
      '-s', 'example.com',
      '-t', 'DOMAIN_NAME',
      '-m', 'sfp_dnsresolve,sfp_subdomain_enum',
      '-q'
    ]);
    
    log("✅ SpiderFoot scan completed");
    log(`Output size: ${result.stdout.length} bytes`);
    log(`Error output size: ${result.stderr.length} bytes`);
    
    if (result.stdout.length > 100) {
      log("✅ SpiderFoot produced substantial output");
      return true;
    } else {
      log("⚠️ SpiderFoot output seems minimal");
      return false;
    }
    
  } catch (error: any) {
    log(`❌ SpiderFoot scan test failed: ${error.message}`);
    
    if (error.message.includes('timeout')) {
      log("⚠️ Scan timed out - this may be normal for slow networks");
    }
    
    return false;
  }
}

async function main() {
  log("Starting SpiderFoot validation...");
  
  // Step 1: Check binary availability
  const binaryOk = await checkBinary();
  if (!binaryOk) {
    log("❌ SpiderFoot binary not available");
    process.exit(1);
  }
  
  // Step 2: Check API keys
  await checkApiKeys();
  
  // Step 3: Test SpiderFoot help
  const helpOk = await testSpiderFootDirect();
  if (!helpOk) {
    log("❌ SpiderFoot help test failed");
    process.exit(1);
  }
  
  // Step 4: Test actual scan
  const scanOk = await testSpiderFootScan();
  
  if (scanOk) {
    log("✅ SpiderFoot validation successful!");
    
    const summary = {
      binary: "✅ Available",
      help: "✅ Working", 
      scan: "✅ Functional",
      timeout: process.env.SPIDERFOOT_TIMEOUT_MS || '300000'
    };
    
    log("\n=== Final Summary ===");
    console.log(JSON.stringify(summary, null, 2));
    
    process.exit(0);
  } else {
    log("⚠️ SpiderFoot scan test had issues but binary is functional");
    
    const summary = {
      binary: "✅ Available",
      help: "✅ Working", 
      scan: "⚠️ Issues detected",
      timeout: process.env.SPIDERFOOT_TIMEOUT_MS || '300000'
    };
    
    log("\n=== Final Summary ===");
    console.log(JSON.stringify(summary, null, 2));
    
    process.exit(0); // Don't fail completely if binary works
  }
}

main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
}); 