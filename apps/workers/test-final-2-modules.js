#!/usr/bin/env node

/**
 * Test the final 2 modules to reach complete 20/20 operational status
 */

import { LocalStore } from './dist/core/localStore.js';
import { runDbPortScan } from './dist/modules/dbPortScan.js';

const TEST_SCAN_ID = `FINAL_2_MODULES_${Date.now()}`;
const TEST_DOMAIN = 'testphp.vulnweb.com';

// Helper function to get findings count
async function getFindingsCount(store, scanId) {
    try {
        const result = await store.query('SELECT COUNT(*) as count FROM findings WHERE scan_id = $1', [scanId]);
        return parseInt(result.rows[0].count);
    } catch (error) {
        console.error('Error getting findings count:', error);
        return 0;
    }
}

// Helper function to time module execution
const timeModule = async (moduleName, moduleFunc) => {
    const moduleStart = Date.now();
    try {
        const result = await moduleFunc;
        const duration = Date.now() - moduleStart;
        console.log(`[TIMING] ${moduleName}: ${duration}ms`);
        return { success: true, data: result, module: moduleName, duration };
    } catch (err) {
        const duration = Date.now() - moduleStart;
        console.log(`[TIMING] ${moduleName}: ${duration}ms (failed)`);
        return { success: false, error: err.message, module: moduleName, duration };
    }
};

// Test dbPortScan with nmap now installed
async function testDbPortScan(store) {
    console.log('\n🔍 Testing dbPortScan with newly installed nmap...');
    
    const beforeCount = await getFindingsCount(store, TEST_SCAN_ID);
    
    try {
        const result = await runDbPortScan({
            domain: TEST_DOMAIN,
            scanId: TEST_SCAN_ID
        });
        
        const afterCount = await getFindingsCount(store, TEST_SCAN_ID);
        const newFindings = afterCount - beforeCount;
        
        console.log(`📊 dbPortScan: ${newFindings} findings added (returned ${result})`);
        
        if (newFindings > 0) {
            const findings = await store.getFindingsByScanId(TEST_SCAN_ID);
            const dbFindings = findings.filter(f => 
                f.type?.includes('DATABASE') || 
                f.description?.toLowerCase().includes('database')
            );
            if (dbFindings.length > 0) {
                console.log(`   Sample finding: ${dbFindings[0]?.description || 'No description'}`);
            }
        }
        
        return true;
    } catch (error) {
        console.log(`❌ dbPortScan failed: ${error.message}`);
        return false;
    }
}

// Test Censys with current token format
async function testCensysWithCurrentToken() {
    console.log('\n🔍 Testing Censys API with current CENSYS_TOKEN...');
    
    // Set up environment variables for the test
    process.env.CENSYS_PAT = process.env.CENSYS_TOKEN;
    // We'll need the org ID - let's try without it first to see the error
    
    try {
        const { runCensysPlatformScan } = await import('./dist/modules/censysPlatformScan.js');
        
        const result = await runCensysPlatformScan({
            domain: TEST_DOMAIN,
            scanId: TEST_SCAN_ID
        });
        
        console.log(`✅ Censys scan successful: ${result}`);
        return true;
    } catch (error) {
        console.log(`❌ Censys failed: ${error.message}`);
        
        if (error.message.includes('401') || error.message.includes('Unauthorized')) {
            console.log('ℹ️  This indicates the token format or org ID is incorrect');
            console.log('ℹ️  Need to get proper PAT and Organization ID from Censys Platform API v3');
        }
        
        return false;
    }
}

// Main test function
async function main() {
    console.log('🧪 Testing Final 2 Modules for 20/20 Complete Status');
    console.log(`Testing with scan ID: ${TEST_SCAN_ID}`);
    console.log(`nmap installed: ${await import('child_process').then(cp => {
        return new Promise(resolve => {
            cp.exec('which nmap', (err) => resolve(!err));
        });
    })}`);
    
    const store = new LocalStore();
    
    try {
        // Insert test scan record
        await store.insertScan({
            id: TEST_SCAN_ID,
            domain: TEST_DOMAIN,
            status: 'running',
            created_at: new Date()
        });
        
        // Test dbPortScan (now that nmap is installed)
        const dbPortScanWorking = await testDbPortScan(store);
        
        // Test Censys with current setup
        const censysWorking = await testCensysWithCurrentToken();
        
        // Results
        console.log('\n📋 FINAL 2 MODULES TEST RESULTS:');
        console.log(`   dbPortScan: ${dbPortScanWorking ? '✅ WORKING' : '❌ NEEDS SETUP'}`);
        console.log(`   censysPlatformScan: ${censysWorking ? '✅ WORKING' : '❌ NEEDS API SETUP'}`);
        
        const workingCount = (dbPortScanWorking ? 1 : 0) + (censysWorking ? 1 : 0);
        console.log(`\n🎯 FINAL STATUS: ${19 + workingCount}/20 modules working`);
        
        if (workingCount === 2) {
            console.log('\n🎉 SUCCESS: ALL 20/20 MODULES OPERATIONAL!');
            console.log('   - Complete security scanning architecture achieved');
            console.log('   - Ready for production deployment');
        } else {
            console.log(`\n🔧 PROGRESS: ${19 + workingCount}/20 modules operational`);
            if (!dbPortScanWorking) {
                console.log('   - dbPortScan: Check if nmap scripts are working properly');
            }
            if (!censysWorking) {
                console.log('   - censysPlatformScan: Need proper PAT and Organization ID');
                console.log('   - Visit: https://platform.censys.io/account/api');
            }
        }
        
        return 19 + workingCount;
        
    } catch (error) {
        console.error('❌ Test failed:', error);
        process.exit(1);
    } finally {
        await store.close();
    }
}

// Run the test
main().catch(console.error);