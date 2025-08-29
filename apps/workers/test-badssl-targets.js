#!/usr/bin/env node

/**
 * Quick test of tier2 dependency system using badssl.com targets
 * These targets have known SSL issues that should trigger findings
 */

import { LocalStore } from './dist/core/localStore.js';
import { runTlsScan } from './dist/modules/tlsScan.js';

const TEST_SCAN_ID = `BADSSL_TEST_${Date.now()}`;

// BadSSL targets with known issues
const BADSSL_TARGETS = [
    'expired.badssl.com',
    'self-signed.badssl.com',
    'wrong.host.badssl.com',
    'untrusted-root.badssl.com'
];

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

// Test TLS scan against BadSSL targets
async function testTlsAgainstBadSSL(store) {
    console.log('🧪 Testing TLS scan against BadSSL targets');
    
    const results = [];
    
    for (const domain of BADSSL_TARGETS) {
        console.log(`\\n🔍 Testing TLS against ${domain}...`);
        
        const beforeCount = await getFindingsCount(store, TEST_SCAN_ID);
        
        try {
            const result = await runTlsScan({
                domain: domain,
                scanId: TEST_SCAN_ID
            });
            
            const afterCount = await getFindingsCount(store, TEST_SCAN_ID);
            const newFindings = afterCount - beforeCount;
            
            console.log(`📊 TLS scan on ${domain}: ${newFindings} findings (returned ${result})`);
            
            if (newFindings > 0) {
                const findings = await store.getFindingsByScanId(TEST_SCAN_ID);
                const recentFindings = findings.slice(-newFindings);
                console.log(`   🚨 Found: ${recentFindings[0]?.type || 'No type'} - ${recentFindings[0]?.description?.substring(0, 80) || 'No description'}...`);
            }
            
            results.push({
                domain,
                success: true,
                findings: newFindings,
                result
            });
            
        } catch (error) {
            console.log(`❌ TLS scan failed on ${domain}: ${error.message}`);
            results.push({
                domain,
                success: false,
                findings: 0,
                error: error.message
            });
        }
    }
    
    return results;
}

// Main test function
async function main() {
    console.log('🧪 Testing Tier1 TLS module against BadSSL vulnerable targets');
    console.log(`Testing with scan ID: ${TEST_SCAN_ID}`);
    
    const store = new LocalStore();
    
    try {
        // Insert test scan record
        await store.insertScan({
            id: TEST_SCAN_ID,
            domain: 'badssl-targets',
            status: 'running',
            created_at: new Date()
        });
        
        // Test TLS scan
        const results = await testTlsAgainstBadSSL(store);
        
        // Summary
        console.log('\\n📋 BADSSL TEST RESULTS:');
        console.log('='.repeat(50));
        
        let totalFindings = 0;
        let successfulScans = 0;
        
        for (const result of results) {
            const status = result.success ? '✅' : '❌';
            console.log(`${status} ${result.domain}: ${result.findings} findings`);
            
            if (result.success) {
                successfulScans++;
                totalFindings += result.findings;
            }
        }
        
        console.log(`\\n🎉 SUMMARY:`);
        console.log(`   Successful scans: ${successfulScans}/${results.length}`);
        console.log(`   Total findings: ${totalFindings}`);
        
        if (totalFindings > 0) {
            console.log(`\\n🚨 SUCCESS: Found ${totalFindings} SSL/TLS issues across BadSSL targets!`);
            console.log(`   This proves the tier1 modules work against real vulnerable targets`);
        } else {
            console.log(`\\n⚠️  No findings: TLS module may need investigation`);
        }
        
        // Get final scan state
        const finalArtifacts = await store.query('SELECT COUNT(*) as count FROM artifacts WHERE scan_id = $1', [TEST_SCAN_ID]);
        const finalFindings = await getFindingsCount(store, TEST_SCAN_ID);
        
        console.log(`\\n📊 Final scan state: ${finalFindings} total findings, ${finalArtifacts.rows[0].count} artifacts`);
        
    } catch (error) {
        console.error('❌ Test failed:', error);
        process.exit(1);
    } finally {
        await store.close();
    }
}

// Run the test
main().catch(console.error);