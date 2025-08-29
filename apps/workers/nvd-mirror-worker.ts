import { config } from 'dotenv';
import { nvdMirror } from './util/nvdMirror.js';

config();

function log(...args: any[]) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [nvd-mirror-worker]`, ...args);
}

async function runNVDMirrorUpdate() {
  log('Starting daily NVD mirror update...');
  
  try {
    // Initialize the database
    await nvdMirror.initialize();
    log('NVD mirror database initialized');
    
    // Force a sync regardless of last update time
    await nvdMirror.syncNVDData();
    log('NVD mirror sync completed');
    
    // Get final stats
    const stats = await nvdMirror.getStats();
    log(`NVD mirror update completed: ${stats.totalCVEs} CVEs, ${stats.dbSizeMB}MB, last sync: ${stats.lastSync}`);
    
  } catch (error) {
    log('NVD mirror update failed:', (error as Error).message);
    throw error;
  }
}

async function main() {
  const startTime = Date.now();
  
  try {
    await runNVDMirrorUpdate();
    const duration = Date.now() - startTime;
    log(`NVD mirror worker completed successfully in ${duration}ms`);
    process.exit(0);
  } catch (error) {
    log('NVD mirror worker failed:', (error as Error).message);
    process.exit(1);
  }
}

main();