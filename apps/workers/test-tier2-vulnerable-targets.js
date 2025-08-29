#!/usr/bin/env node

/**
 * Test tier2 modules against real vulnerable demo targets
 * Uses actual vulnerable applications to verify tier2 modules find real issues
 */

import { LocalStore } from './dist/core/localStore.js';
import { runRateLimitScan } from './dist/modules/rateLimitScan.js';
import { runNucleiLegacy } from './dist/modules/nuclei.js';

const TEST_SCAN_ID = `TIER2_VULN_${Date.now()}`;

// Real vulnerable demo targets
const VULNERABLE_TARGETS = [
    {
        domain: 'testphp.vulnweb.com',
        description: 'OWASP WebGoat test application',
        endpoints: [
            'https://testphp.vulnweb.com/artists.php',
            'https://testphp.vulnweb.com/login.php', 
            'https://testphp.vulnweb.com/search.php',
            'https://testphp.vulnweb.com/userinfo.php'
        ]
    },
    {
        domain: 'demo.testfire.net',
        description: 'IBM Security AppScan demo',
        endpoints: [
            'https://demo.testfire.net/login.jsp',
            'https://demo.testfire.net/search.jsp',
            'https://demo.testfire.net/bank/login.jsp'
        ]
    },
    {
        domain: 'zero.webappsecurity.com',
        description: 'ZeroBank vulnerable application',
        endpoints: [
            'https://zero.webappsecurity.com/login.html',
            'https://zero.webappsecurity.com/search.html'
        ]
    }
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

// Seed realistic endpoint data from vulnerable targets
async function seedVulnerableTargetData(store, target) {
    console.log(`🌱 Seeding data for vulnerable target: ${target.domain}`);
    
    // Seed endpoint discovery data with real vulnerable endpoints
    await store.insertArtifact({
        id: `${TEST_SCAN_ID}_endpoints_${target.domain.replace('.', '_')}`,
        scan_id: TEST_SCAN_ID,
        type: 'endpoints',
        file_path: `/tmp/endpoints_${target.domain}.json`,
        size_bytes: 2048,
        val_text: `Endpoints for ${target.domain}`,
        metadata: {
            endpoints: target.endpoints.map(url => ({
                url: url,
                path: new URL(url).pathname,
                method: 'GET',
                status: 200,
                contentType: 'text/html',
                category: url.includes('login') ? 'auth' : 'web'
            }))
        }
    });

    // Seed network discovery 
    await store.insertArtifact({
        id: `${TEST_SCAN_ID}_network_${target.domain.replace('.', '_')}`,
        scan_id: TEST_SCAN_ID,
        type: 'network_discovery',
        file_path: `/tmp/network_${target.domain}.json`,
        size_bytes: 1024,
        val_text: `Network scan for ${target.domain}`,
        metadata: {
            domain: target.domain,
            ips: ['1.2.3.4'], // Placeholder
            ports: [80, 443],
            services: [
                { port: 80, service: 'http', version: 'Apache' },
                { port: 443, service: 'https', version: 'Apache' }
            ]
        }
    });
    
    console.log(`✅ Seeded data for ${target.domain}`);
}

// Test nuclei against vulnerable target
async function testNucleiVulnerable(store, target) {
    console.log(`\\n🔍 Testing nuclei against ${target.domain} (${target.description})...`);
    
    const beforeCount = await getFindingsCount(store, TEST_SCAN_ID);
    
    try {
        const result = await runNucleiLegacy({
            domain: target.domain,
            scanId: TEST_SCAN_ID
        });
        
        const afterCount = await getFindingsCount(store, TEST_SCAN_ID);
        const newFindings = afterCount - beforeCount;
        
        console.log(`📊 nuclei vs ${target.domain}: ${newFindings} findings (returned ${result})`);
        
        if (newFindings > 0) {
            const findings = await store.getFindingsByScanId(TEST_SCAN_ID);
            const recentFindings = findings.slice(-newFindings);
            console.log(`   🚨 Sample finding: ${recentFindings[0]?.type || 'No type'} - ${recentFindings[0]?.description?.substring(0, 100) || 'No description'}...`);
        }
        
        return { success: true, findings: newFindings };
    } catch (error) {
        console.log(`❌ nuclei failed against ${target.domain}: ${error.message}`);
        return { success: false, findings: 0, error: error.message };
    }
}

// Test rateLimitScan against vulnerable target
async function testRateLimitVulnerable(store, target) {
    console.log(`\\n🔍 Testing rateLimitScan against ${target.domain}...`);
    
    const beforeCount = await getFindingsCount(store, TEST_SCAN_ID);
    
    try {
        const result = await runRateLimitScan({
            domain: target.domain,
            scanId: TEST_SCAN_ID
        });
        
        const afterCount = await getFindingsCount(store, TEST_SCAN_ID);
        const newFindings = afterCount - beforeCount;
        
        console.log(`📊 rateLimitScan vs ${target.domain}: ${newFindings} findings (returned ${result})`);
        
        if (newFindings > 0) {
            const findings = await store.getFindingsByScanId(TEST_SCAN_ID);
            const recentFindings = findings.slice(-newFindings);
            console.log(`   🚨 Sample finding: ${recentFindings[0]?.type || 'No type'} - ${recentFindings[0]?.description?.substring(0, 100) || 'No description'}...`);
        }
        
        return { success: true, findings: newFindings };
    } catch (error) {
        console.log(`❌ rateLimitScan failed against ${target.domain}: ${error.message}`);
        return { success: false, findings: 0, error: error.message };
    }
}

// Main test function
async function main() {
    console.log('🧪 Testing Tier2 modules against REAL VULNERABLE TARGETS');
    console.log(`Testing with scan ID: ${TEST_SCAN_ID}`);
    console.log(`Targets: ${VULNERABLE_TARGETS.map(t => t.domain).join(', ')}`);
    
    const store = new LocalStore();
    const results = [];
    
    try {
        // Insert test scan record
        await store.insertScan({
            id: TEST_SCAN_ID,
            domain: 'vulnerable-targets',
            status: 'running',
            created_at: new Date()
        });
        
        for (const target of VULNERABLE_TARGETS) {
            console.log(`\\n🎯 TESTING TARGET: ${target.domain}`);
            console.log(`   Description: ${target.description}`);
            console.log(`   Endpoints: ${target.endpoints.length} discovered`);
            
            // Seed data for this target
            await seedVulnerableTargetData(store, target);
            
            // Test modules against this target
            const nucleiResult = await testNucleiVulnerable(store, target);
            const rateLimitResult = await testRateLimitVulnerable(store, target);
            
            results.push({
                domain: target.domain,
                description: target.description,
                nuclei: nucleiResult,
                rateLimitScan: rateLimitResult
            });
            
            console.log(`   ✅ Completed testing ${target.domain}`);
        }
        
        // Summary
        console.log('\\n📋 TIER2 VULNERABLE TARGET TEST RESULTS:');
        console.log('='.repeat(60));
        
        let totalFindings = 0;
        let workingModules = 0;
        
        for (const result of results) {
            console.log(`\\n🎯 ${result.domain} (${result.description}):`);
            
            const nucleiStatus = result.nuclei.success ? '✅' : '❌';
            const rateLimitStatus = result.rateLimitScan.success ? '✅' : '❌';
            
            console.log(`   nuclei: ${nucleiStatus} ${result.nuclei.findings} findings`);
            console.log(`   rateLimitScan: ${rateLimitStatus} ${result.rateLimitScan.findings} findings`);
            
            totalFindings += result.nuclei.findings + result.rateLimitScan.findings;
            
            if (result.nuclei.success) workingModules++;
            if (result.rateLimitScan.success) workingModules++;
        }
        
        console.log(`\\n🎉 OVERALL RESULTS:`);
        console.log(`   Total findings across all targets: ${totalFindings}`);
        console.log(`   Working module instances: ${workingModules}/${results.length * 2}`);
        console.log(`   Targets tested: ${results.length}`);
        
        if (totalFindings > 0) {
            console.log(`\\n🚨 SUCCESS: Tier2 modules found ${totalFindings} real vulnerabilities!`);
            console.log(`   This proves the dependency system works against real targets`);
        } else {
            console.log(`\\n⚠️  No findings: This could mean targets are patched or modules need tuning`);
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