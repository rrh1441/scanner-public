// Test script for the new queue system
import { spawn } from 'child_process';
import { setTimeout } from 'timers/promises';

let serverProcess;

async function startServer() {
  console.log('🚀 Starting server...');
  serverProcess = spawn('node', ['dist/localServer.js'], {
    stdio: 'pipe',
    cwd: process.cwd()
  });
  
  serverProcess.stdout.on('data', (data) => {
    console.log(`[SERVER] ${data.toString().trim()}`);
  });
  
  serverProcess.stderr.on('data', (data) => {
    console.error(`[SERVER ERROR] ${data.toString().trim()}`);
  });
  
  // Wait for server to start
  await setTimeout(3000);
}

async function testEndpoints() {
  console.log('\n📊 Testing queue endpoints...');
  
  const tests = [
    { name: 'Health Check', url: 'http://localhost:8080/health' },
    { name: 'Queue Status', url: 'http://localhost:8080/queue/status' },
    { name: 'Queue Metrics', url: 'http://localhost:8080/queue/metrics' }
  ];
  
  for (const test of tests) {
    try {
      console.log(`\n🧪 Testing ${test.name}...`);
      const response = await fetch(test.url);
      const data = await response.json();
      console.log(`✅ ${test.name}: ${response.status}`);
      console.log(JSON.stringify(data, null, 2));
    } catch (error) {
      console.error(`❌ ${test.name} failed:`, error.message);
    }
  }
}

async function testConcurrentScans() {
  console.log('\n🔍 Testing concurrent scans...');
  
  const domains = ['example.com', 'httpbin.org', 'jsonplaceholder.typicode.com'];
  const scanPromises = [];
  
  for (const domain of domains) {
    const scanPromise = fetch('http://localhost:8080/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, priority: 'normal' })
    }).then(async (res) => {
      const data = await res.json();
      console.log(`📝 Scan queued for ${domain}: ${data.scan_id} (position: ${data.position_in_queue})`);
      return data;
    }).catch((err) => {
      console.error(`❌ Failed to queue scan for ${domain}:`, err.message);
      return null;
    });
    
    scanPromises.push(scanPromise);
    
    // Small delay between requests
    await setTimeout(500);
  }
  
  const results = await Promise.all(scanPromises);
  console.log('\n📊 Queued scans:', results.filter(r => r !== null).length);
  
  // Check queue status
  try {
    const queueResponse = await fetch('http://localhost:8080/queue/status');
    const queueData = await queueResponse.json();
    console.log('\n📈 Current queue status:');
    console.log(JSON.stringify(queueData, null, 2));
  } catch (error) {
    console.error('Failed to get queue status:', error.message);
  }
}

async function cleanup() {
  console.log('\n🛑 Cleaning up...');
  if (serverProcess) {
    serverProcess.kill('SIGTERM');
    await setTimeout(2000);
    if (!serverProcess.killed) {
      serverProcess.kill('SIGKILL');
    }
  }
  console.log('✅ Cleanup complete');
}

// Main test execution
async function main() {
  try {
    await startServer();
    await testEndpoints();
    await testConcurrentScans();
    
    // Let scans run for a bit to see queue activity
    console.log('\n⏳ Waiting 10 seconds to observe queue activity...');
    await setTimeout(10000);
    
    // Final queue status check
    try {
      const finalResponse = await fetch('http://localhost:8080/queue/metrics');
      const finalData = await finalResponse.json();
      console.log('\n📊 Final queue metrics:');
      console.log(JSON.stringify(finalData, null, 2));
    } catch (error) {
      console.error('Failed to get final metrics:', error.message);
    }
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await cleanup();
  }
}

// Handle interrupts
process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

main().catch(console.error);