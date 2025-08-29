// Test script for concurrent scanning of real client sites
import { spawn } from 'child_process';
import { setTimeout } from 'timers/promises';

let serverProcess;

async function startServer() {
  console.log('🚀 Starting scanner server...');
  serverProcess = spawn('node', ['dist/localServer.js'], {
    stdio: 'pipe',
    cwd: process.cwd()
  });
  
  let serverReady = false;
  
  serverProcess.stdout.on('data', (data) => {
    const output = data.toString().trim();
    console.log(`[SERVER] ${output}`);
    if (output.includes('Local Scanner Server with Queue running')) {
      serverReady = true;
    }
  });
  
  serverProcess.stderr.on('data', (data) => {
    console.error(`[SERVER ERROR] ${data.toString().trim()}`);
  });
  
  // Wait for server to be ready
  while (!serverReady) {
    await setTimeout(1000);
  }
  
  await setTimeout(2000); // Extra buffer
  console.log('✅ Server ready\n');
}

async function checkQueueStatus() {
  try {
    const response = await fetch('http://localhost:8080/queue/status');
    const data = await response.json();
    
    console.log('📊 Queue Status:');
    console.log(`  • Queued jobs: ${data.metrics.queued_jobs}`);
    console.log(`  • Running jobs: ${data.metrics.running_jobs}`);
    console.log(`  • Active workers: ${data.metrics.active_workers}/3`);
    console.log(`  • Completed today: ${data.metrics.completed_today}`);
    console.log('');
    
    return data;
  } catch (error) {
    console.error('❌ Failed to get queue status:', error.message);
    return null;
  }
}

async function startConcurrentScans() {
  console.log('🎯 Starting concurrent scans for your sites...\n');
  
  const sites = [
    { domain: 'firstserveseattle.com', description: 'First Serve Seattle' },
    { domain: 'seattleballmachine.com', description: 'Seattle Ball Machine' },
    { domain: 'simplcyber.io', description: 'SimplCyber' }
  ];
  
  const scanResults = [];
  
  // Start all scans concurrently
  for (const site of sites) {
    try {
      console.log(`🔍 Queuing scan for ${site.description} (${site.domain})...`);
      
      const response = await fetch('http://localhost:8080/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          domain: site.domain, 
          companyName: site.description,
          priority: 'normal' 
        })
      });
      
      const result = await response.json();
      
      if (response.ok) {
        console.log(`✅ ${site.description}: Queued as ${result.scan_id}`);
        console.log(`   Position in queue: ${result.position_in_queue}`);
        console.log(`   Status URL: ${result.status_url}\n`);
        
        scanResults.push({
          ...site,
          scan_id: result.scan_id,
          status_url: result.status_url,
          report_url: result.report_url
        });
      } else {
        console.error(`❌ Failed to queue ${site.description}: ${result.error}`);
      }
    } catch (error) {
      console.error(`❌ Error queuing ${site.description}:`, error.message);
    }
    
    // Small delay between requests to show queue building
    await setTimeout(1000);
  }
  
  return scanResults;
}

async function monitorScans(scanResults) {
  console.log('📈 Monitoring scan progress...\n');
  
  const allScanIds = scanResults.map(r => r.scan_id);
  const completedScans = new Set();
  
  while (completedScans.size < scanResults.length) {
    // Check queue status
    await checkQueueStatus();
    
    // Check individual scan statuses
    for (const scan of scanResults) {
      if (completedScans.has(scan.scan_id)) continue;
      
      try {
        const response = await fetch(`http://localhost:8080/scan/${scan.scan_id}/status`);
        const status = await response.json();
        
        console.log(`🔄 ${scan.description}: ${status.status.toUpperCase()}`);
        
        if (status.status === 'running' && status.worker_id) {
          console.log(`   Running on ${status.worker_id}`);
          if (status.progress) {
            console.log(`   Progress: ${status.progress.completed_modules}/${status.progress.total_modules} modules`);
            if (status.progress.current_module) {
              console.log(`   Current: ${status.progress.current_module}`);
            }
          }
        } else if (status.status === 'completed') {
          console.log(`   ✅ Completed! ${status.findings_count} findings, ${status.duration_ms}ms`);
          console.log(`   📄 Report: ${scan.report_url}`);
          completedScans.add(scan.scan_id);
        } else if (status.status === 'failed') {
          console.log(`   ❌ Failed: ${status.error_message}`);
          completedScans.add(scan.scan_id);
        } else if (status.position_in_queue) {
          console.log(`   Queued at position: ${status.position_in_queue}`);
        }
      } catch (error) {
        console.error(`   ❌ Error checking ${scan.description}: ${error.message}`);
      }
    }
    
    console.log(''); // Spacer
    
    // Wait before next check
    if (completedScans.size < scanResults.length) {
      await setTimeout(10000); // Check every 10 seconds
    }
  }
}

async function showFinalResults(scanResults) {
  console.log('📊 Final Results Summary:\n');
  
  for (const scan of scanResults) {
    try {
      const response = await fetch(`http://localhost:8080/scan/${scan.scan_id}/status`);
      const status = await response.json();
      
      console.log(`🏢 ${scan.description} (${scan.domain})`);
      console.log(`   Scan ID: ${scan.scan_id}`);
      console.log(`   Status: ${status.status.toUpperCase()}`);
      
      if (status.status === 'completed') {
        console.log(`   Duration: ${Math.round(status.duration_ms / 1000)}s`);
        console.log(`   Findings: ${status.findings_count}`);
        console.log(`   Artifacts: ${status.artifacts_count}`);
        console.log(`   📄 Report: http://localhost:8080${scan.report_url}`);
      }
      console.log('');
    } catch (error) {
      console.error(`   ❌ Error getting final status: ${error.message}\n`);
    }
  }
  
  // Show final queue metrics
  console.log('📈 Final Queue Metrics:');
  try {
    const response = await fetch('http://localhost:8080/queue/metrics');
    const metrics = await response.json();
    
    console.log(`   Completed today: ${metrics.completed_today}`);
    console.log(`   Failed today: ${metrics.failed_today}`);
    console.log(`   Average scan time: ${Math.round(metrics.average_scan_time_ms / 1000)}s`);
    console.log(`   Total workers: ${metrics.total_workers}`);
  } catch (error) {
    console.error(`   ❌ Error getting metrics: ${error.message}`);
  }
}

async function cleanup() {
  console.log('\n🛑 Shutting down server...');
  if (serverProcess) {
    serverProcess.kill('SIGTERM');
    await setTimeout(3000);
    if (!serverProcess.killed) {
      serverProcess.kill('SIGKILL');
    }
  }
  console.log('✅ Cleanup complete');
}

// Main execution
async function main() {
  try {
    await startServer();
    
    // Show initial queue state
    await checkQueueStatus();
    
    // Start concurrent scans
    const scanResults = await startConcurrentScans();
    
    if (scanResults.length === 0) {
      throw new Error('No scans were successfully queued');
    }
    
    // Monitor progress
    await monitorScans(scanResults);
    
    // Show final results
    await showFinalResults(scanResults);
    
    console.log('\n🎉 Concurrent scanning test completed successfully!');
    
  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
  } finally {
    await cleanup();
  }
}

// Handle interrupts
process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

main().catch(console.error);