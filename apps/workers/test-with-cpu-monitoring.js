// Test concurrent scanning with explicit CPU and resource monitoring
import { spawn } from 'child_process';
import { setTimeout } from 'timers/promises';
import os from 'os';

let serverProcess;
let monitoringInterval;
const resourceMetrics = [];

// System resource monitoring functions
function getCPUUsage() {
  const cpus = os.cpus();
  let user = 0, nice = 0, sys = 0, idle = 0, irq = 0;
  
  for (const cpu of cpus) {
    user += cpu.times.user;
    nice += cpu.times.nice;
    sys += cpu.times.sys;
    idle += cpu.times.idle;
    irq += cpu.times.irq;
  }
  
  const total = user + nice + sys + idle + irq;
  return {
    user: (user / total * 100).toFixed(2),
    system: (sys / total * 100).toFixed(2),
    idle: (idle / total * 100).toFixed(2),
    total_usage: ((total - idle) / total * 100).toFixed(2)
  };
}

function getMemoryUsage() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  
  return {
    total_gb: (totalMem / 1024 / 1024 / 1024).toFixed(2),
    used_gb: (usedMem / 1024 / 1024 / 1024).toFixed(2),
    free_gb: (freeMem / 1024 / 1024 / 1024).toFixed(2),
    usage_percent: (usedMem / totalMem * 100).toFixed(2)
  };
}

function getSystemLoad() {
  const load = os.loadavg();
  return {
    load_1min: load[0].toFixed(2),
    load_5min: load[1].toFixed(2),
    load_15min: load[2].toFixed(2)
  };
}

function startResourceMonitoring() {
  console.log('\n📊 Starting resource monitoring...');
  console.log(`💻 System Info: ${os.cpus().length} CPU cores, ${(os.totalmem() / 1024 / 1024 / 1024).toFixed(2)}GB RAM`);
  console.log('📈 Monitoring CPU, Memory, and System Load every 5 seconds\n');
  
  monitoringInterval = setInterval(() => {
    const timestamp = new Date().toLocaleTimeString();
    const cpu = getCPUUsage();
    const memory = getMemoryUsage();
    const load = getSystemLoad();
    
    const metrics = {
      timestamp,
      cpu_total: parseFloat(cpu.total_usage),
      cpu_user: parseFloat(cpu.user),
      cpu_system: parseFloat(cpu.system),
      memory_used_gb: parseFloat(memory.used_gb),
      memory_usage_percent: parseFloat(memory.usage_percent),
      load_1min: parseFloat(load.load_1min),
      load_5min: parseFloat(load.load_5min)
    };
    
    resourceMetrics.push(metrics);
    
    console.log(`[${timestamp}] 🖥️  CPU: ${cpu.total_usage}% (user: ${cpu.user}%, sys: ${cpu.system}%) | 🧠 RAM: ${memory.used_gb}GB (${memory.usage_percent}%) | ⚡ Load: ${load.load_1min}`);
  }, 5000);
}

function stopResourceMonitoring() {
  if (monitoringInterval) {
    clearInterval(monitoringInterval);
    console.log('\n📊 Resource monitoring stopped\n');
  }
}

function analyzeResourceUsage() {
  if (resourceMetrics.length === 0) return;
  
  console.log('\n📊 RESOURCE USAGE ANALYSIS');
  console.log('═'.repeat(50));
  
  // Calculate statistics
  const cpuUsages = resourceMetrics.map(m => m.cpu_total);
  const memUsages = resourceMetrics.map(m => m.memory_usage_percent);
  const loads = resourceMetrics.map(m => m.load_1min);
  
  const avgCPU = (cpuUsages.reduce((a, b) => a + b, 0) / cpuUsages.length).toFixed(2);
  const maxCPU = Math.max(...cpuUsages).toFixed(2);
  const minCPU = Math.min(...cpuUsages).toFixed(2);
  
  const avgMem = (memUsages.reduce((a, b) => a + b, 0) / memUsages.length).toFixed(2);
  const maxMem = Math.max(...memUsages).toFixed(2);
  
  const avgLoad = (loads.reduce((a, b) => a + b, 0) / loads.length).toFixed(2);
  const maxLoad = Math.max(...loads).toFixed(2);
  
  console.log(`🖥️  CPU Usage:`);
  console.log(`   Average: ${avgCPU}% | Peak: ${maxCPU}% | Minimum: ${minCPU}%`);
  
  console.log(`🧠 Memory Usage:`);
  console.log(`   Average: ${avgMem}% | Peak: ${maxMem}%`);
  
  console.log(`⚡ System Load:`);
  console.log(`   Average: ${avgLoad} | Peak: ${maxLoad} | CPU Cores: ${os.cpus().length}`);
  
  // Performance assessment
  console.log(`\n🎯 Performance Assessment:`);
  if (parseFloat(maxCPU) > 80) {
    console.log(`   ⚠️  High CPU usage detected (${maxCPU}% peak) - system under stress`);
  } else if (parseFloat(maxCPU) > 50) {
    console.log(`   📈 Moderate CPU usage (${maxCPU}% peak) - healthy concurrent processing`);
  } else {
    console.log(`   ✅ Low CPU usage (${maxCPU}% peak) - system handling load well`);
  }
  
  if (parseFloat(maxLoad) > os.cpus().length) {
    console.log(`   ⚠️  System overloaded (load: ${maxLoad} vs ${os.cpus().length} cores)`);
  } else {
    console.log(`   ✅ System load healthy (${maxLoad} vs ${os.cpus().length} cores available)`);
  }
  
  console.log(`\n📋 Total monitoring duration: ${Math.round(resourceMetrics.length * 5 / 60)} minutes`);
  console.log(`📊 Data points collected: ${resourceMetrics.length}`);
}

async function startServer() {
  console.log('🚀 Starting scanner server...');
  
  // Show initial system state
  const initialCPU = getCPUUsage();
  const initialMem = getMemoryUsage();
  const initialLoad = getSystemLoad();
  
  console.log('\n📊 BASELINE SYSTEM RESOURCES (Pre-Scan):');
  console.log(`🖥️  CPU: ${initialCPU.total_usage}% usage`);
  console.log(`🧠 Memory: ${initialMem.used_gb}GB / ${initialMem.total_gb}GB (${initialMem.usage_percent}%)`);
  console.log(`⚡ Load: ${initialLoad.load_1min} (1min average)`);
  
  serverProcess = spawn('node', ['dist/localServer.js'], {
    stdio: 'pipe',
    cwd: process.cwd()
  });
  
  let serverReady = false;
  
  serverProcess.stdout.on('data', (data) => {
    const output = data.toString().trim();
    if (output.includes('Local Scanner Server with Queue running')) {
      serverReady = true;
      console.log('\n✅ Scanner server ready');
    }
    // Suppress most server output for cleaner monitoring
    if (output.includes('Queue] Job') && !output.includes('queued')) {
      console.log(`[SERVER] ${output}`);
    }
  });
  
  serverProcess.stderr.on('data', (data) => {
    const error = data.toString().trim();
    if (!error.includes('Warning: Please use')) { // Suppress legacy warning
      console.error(`[SERVER ERROR] ${error}`);
    }
  });
  
  // Wait for server to be ready
  while (!serverReady) {
    await setTimeout(1000);
  }
  
  await setTimeout(2000); // Extra buffer
}

async function startConcurrentScans() {
  console.log('\n🎯 Starting concurrent scans with resource monitoring...\n');
  
  startResourceMonitoring();
  
  const sites = [
    { domain: 'firstserveseattle.com', description: 'First Serve Seattle' },
    { domain: 'seattleballmachine.com', description: 'Seattle Ball Machine' },
    { domain: 'simplcyber.io', description: 'SimplCyber' }
  ];
  
  const scanResults = [];
  
  // Start all scans rapidly to test concurrent queue handling
  console.log('⚡ Rapid-fire scan queuing (testing queue capacity)...\n');
  
  for (const site of sites) {
    try {
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
        console.log(`✅ ${site.description}: ${result.scan_id} (position: ${result.position_in_queue})`);
        scanResults.push({
          ...site,
          scan_id: result.scan_id,
          queued_at: new Date()
        });
      } else {
        console.error(`❌ Failed to queue ${site.description}: ${result.error}`);
      }
    } catch (error) {
      console.error(`❌ Error queuing ${site.description}:`, error.message);
    }
    
    // No delay - queue as fast as possible to test concurrency
  }
  
  return scanResults;
}

async function monitorScansWithResources(scanResults) {
  console.log('\n📈 Monitoring scan progress and resource usage...\n');
  
  const completedScans = new Set();
  let checkCount = 0;
  
  while (completedScans.size < scanResults.length) {
    checkCount++;
    
    // Get queue status every few checks to avoid spam
    if (checkCount % 3 === 1) {
      try {
        const queueResponse = await fetch('http://localhost:8080/queue/status');
        const queueData = await queueResponse.json();
        
        console.log(`\n[Check ${checkCount}] 📊 Queue Status: ${queueData.metrics.running_jobs} running, ${queueData.metrics.queued_jobs} queued`);
        
        // Show individual scan statuses
        for (const scan of scanResults) {
          if (completedScans.has(scan.scan_id)) continue;
          
          try {
            const statusResponse = await fetch(`http://localhost:8080/scan/${scan.scan_id}/status`);
            const status = await statusResponse.json();
            
            if (status.status === 'completed') {
              const duration = Math.round(status.duration_ms / 1000);
              console.log(`   ✅ ${scan.description}: COMPLETED in ${duration}s (${status.findings_count} findings)`);
              completedScans.add(scan.scan_id);
            } else if (status.status === 'running') {
              console.log(`   🔄 ${scan.description}: RUNNING on ${status.worker_id}`);
            } else if (status.status === 'failed') {
              console.log(`   ❌ ${scan.description}: FAILED - ${status.error_message}`);
              completedScans.add(scan.scan_id);
            }
          } catch (error) {
            console.log(`   ⚠️  ${scan.description}: Status check failed`);
          }
        }
      } catch (error) {
        console.error('Failed to get queue status:', error.message);
      }
    }
    
    // Wait before next check
    if (completedScans.size < scanResults.length) {
      await setTimeout(10000); // Check every 10 seconds
    }
  }
  
  stopResourceMonitoring();
}

async function showFinalResults(scanResults) {
  console.log('\n🏁 FINAL SCAN RESULTS');
  console.log('═'.repeat(60));
  
  for (const scan of scanResults) {
    try {
      const response = await fetch(`http://localhost:8080/scan/${scan.scan_id}/status`);
      const status = await response.json();
      
      console.log(`\n🏢 ${scan.description} (${scan.domain})`);
      console.log(`   Status: ${status.status.toUpperCase()}`);
      
      if (status.status === 'completed') {
        console.log(`   ⏱️  Duration: ${Math.round(status.duration_ms / 1000)}s`);
        console.log(`   🔍 Findings: ${status.findings_count}`);
        console.log(`   📦 Artifacts: ${status.artifacts_count}`);
        console.log(`   📄 Report: http://localhost:8080/reports/${scan.scan_id}/report.pdf`);
      }
    } catch (error) {
      console.log(`   ❌ Error getting final status: ${error.message}`);
    }
  }
  
  // Final queue metrics
  try {
    const response = await fetch('http://localhost:8080/queue/metrics');
    const metrics = await response.json();
    
    console.log(`\n📊 FINAL QUEUE METRICS:`);
    console.log(`   Completed today: ${metrics.completed_today}`);
    console.log(`   Failed today: ${metrics.failed_today}`);
    console.log(`   Average scan time: ${Math.round(metrics.average_scan_time_ms / 1000)}s`);
    console.log(`   Success rate: ${(metrics.completed_today / (metrics.completed_today + metrics.failed_today) * 100).toFixed(1)}%`);
  } catch (error) {
    console.error('Failed to get final metrics:', error.message);
  }
}

async function cleanup() {
  console.log('\n🛑 Cleaning up...');
  
  stopResourceMonitoring();
  
  if (serverProcess) {
    serverProcess.kill('SIGTERM');
    await setTimeout(3000);
    if (!serverProcess.killed) {
      serverProcess.kill('SIGKILL');
    }
  }
  
  console.log('✅ Server stopped');
}

// Main execution
async function main() {
  console.log('🔍 CONCURRENT SECURITY SCANNING WITH RESOURCE MONITORING');
  console.log('═'.repeat(70));
  
  try {
    await startServer();
    
    const scanResults = await startConcurrentScans();
    
    if (scanResults.length === 0) {
      throw new Error('No scans were successfully queued');
    }
    
    console.log(`\n⚡ ${scanResults.length} scans queued successfully - monitoring progress...\n`);
    
    await monitorScansWithResources(scanResults);
    
    analyzeResourceUsage();
    
    await showFinalResults(scanResults);
    
    console.log('\n🎉 Concurrent scanning with resource monitoring completed!');
    
  } catch (error) {
    console.error('\n❌ Test failed:', error.message);
  } finally {
    await cleanup();
  }
}

// Handle interrupts
process.on('SIGINT', async () => {
  console.log('\n⚠️  Interrupted by user');
  await cleanup();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n⚠️  Terminated');
  await cleanup();
  process.exit(0);
});

main().catch(console.error);