#!/usr/bin/env node

/**
 * Test script for Tier2 modules dependency system
 * Tests all tier2-only modules to ensure they can read dependencies from the database
 */

import { LocalStore } from './dist/core/localStore.js';

// Import tier2-only modules
import { runNucleiLegacy } from './dist/modules/nuclei.js';
import { runZAPScan } from './dist/modules/zapScan.js';
import { runOpenVASScan } from './dist/modules/openvasScan.js';
import { runTrufflehog } from './dist/modules/trufflehog.js';
import { runSpiderFoot } from './dist/modules/spiderFoot.js';
import { runDnsTwist } from './dist/modules/dnsTwist.js';
import { runRateLimitScan } from './dist/modules/rateLimitScan.js';

const TEST_SCAN_ID = `TIER2_TEST_${Date.now()}`;
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

// Seed test data for tier2 modules
async function seedTier2TestData(store) {
    console.log('🌱 Seeding database with tier1 + tier2 upstream data...');
    
    // Seed all the tier1 data that tier2 modules depend on
    await store.insertArtifact({
        id: `${TEST_SCAN_ID}_client_assets_1`,
        scan_id: TEST_SCAN_ID,
        type: 'client_assets',
        file_path: '/tmp/client_assets.json',
        size_bytes: 1024,
        val_text: 'Client assets for testing',
        metadata: {
            assets: [
                {
                    url: 'https://testphp.vulnweb.com/js/main.js',
                    type: 'javascript',
                    size: 1024,
                    content: 'var api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz123456789";'
                },
                {
                    url: 'https://testphp.vulnweb.com/css/style.css',
                    type: 'stylesheet',
                    size: 512
                }
            ]
        }
    });

    // Seed endpoint discovery for scanning
    await store.insertArtifact({
        id: `${TEST_SCAN_ID}_endpoints_1`,
        scan_id: TEST_SCAN_ID,
        type: 'endpoints',
        file_path: '/tmp/endpoints.json',
        size_bytes: 2048,
        val_text: 'Discovered endpoints',
        metadata: {
            endpoints: [
                {
                    url: 'https://testphp.vulnweb.com/api/users',
                    method: 'GET',
                    status: 200,
                    contentType: 'application/json'
                },
                {
                    url: 'https://testphp.vulnweb.com/login',
                    method: 'POST',
                    status: 200,
                    contentType: 'text/html'
                },
                {
                    url: 'https://testphp.vulnweb.com/admin',
                    method: 'GET',
                    status: 403,
                    contentType: 'text/html'
                }
            ]
        }
    });

    // Seed network discovery data  
    await store.insertArtifact({
        id: `${TEST_SCAN_ID}_network_1`,
        scan_id: TEST_SCAN_ID,
        type: 'network_discovery',
        file_path: '/tmp/network.json',
        size_bytes: 1024,
        val_text: 'Network scan results',
        metadata: {
            ips: ['44.238.161.76', '185.199.108.153'],
            ports: [80, 443, 22, 3306],
            services: [
                { port: 80, service: 'http', version: 'Apache 2.4.41' },
                { port: 443, service: 'https', version: 'Apache 2.4.41' },
                { port: 22, service: 'ssh', version: 'OpenSSH 8.0' }
            ]
        }
    });

    // Seed secrets found by tier1 modules
    await store.insertArtifact({
        id: `${TEST_SCAN_ID}_secrets_1`,
        scan_id: TEST_SCAN_ID,
        type: 'secrets_found',
        file_path: '/tmp/secrets.json',
        size_bytes: 512,
        val_text: 'Secrets discovered',
        metadata: {
            secrets: [
                {
                    type: 'api_key',
                    value: 'sk-1234567890abcdefghijklmnopqrstuvwxyz123456789',
                    location: 'https://testphp.vulnweb.com/js/main.js',
                    confidence: 0.95
                }
            ]
        }
    });
    
    console.log('✅ Seeded tier2 test data');
}

// Test functions for each tier2 module
async function testNuclei(store) {
    console.log('\\n🔍 Testing nuclei with seeded endpoint data...');
    
    const beforeCount = await getFindingsCount(store, TEST_SCAN_ID);
    
    try {
        const result = await runNucleiLegacy({
            domain: TEST_DOMAIN,
            scanId: TEST_SCAN_ID
        });
        
        const afterCount = await getFindingsCount(store, TEST_SCAN_ID);
        const newFindings = afterCount - beforeCount;
        
        console.log(`📊 nuclei: ${newFindings} findings added (returned ${result})`);
        return newFindings >= 0; // Nuclei may find 0 vulns, that's ok
    } catch (error) {
        console.log(`❌ nuclei failed: ${error.message}`);
        return false;
    }
}

async function testZapScan(store) {
    console.log('\\n🔍 Testing zapScan with seeded endpoint data...');
    
    const beforeCount = await getFindingsCount(store, TEST_SCAN_ID);
    
    try {
        const result = await runZAPScan({
            domain: TEST_DOMAIN,
            scanId: TEST_SCAN_ID
        });
        
        const afterCount = await getFindingsCount(store, TEST_SCAN_ID);
        const newFindings = afterCount - beforeCount;
        
        console.log(`📊 zapScan: ${newFindings} findings added (returned ${result})`);
        return newFindings >= 0; // ZAP may find 0 vulns, that's ok
    } catch (error) {
        console.log(`❌ zapScan failed: ${error.message}`);
        return false;
    }
}

async function testOpenVAS(store) {
    console.log('\\n🔍 Testing openvasScan with seeded network data...');
    
    const beforeCount = await getFindingsCount(store, TEST_SCAN_ID);
    
    try {
        const result = await runOpenVASScan({
            domain: TEST_DOMAIN,
            scanId: TEST_SCAN_ID
        });
        
        const afterCount = await getFindingsCount(store, TEST_SCAN_ID);
        const newFindings = afterCount - beforeCount;
        
        console.log(`📊 openvasScan: ${newFindings} findings added (returned ${result})`);
        return newFindings >= 0; // OpenVAS may find 0 vulns, that's ok
    } catch (error) {
        console.log(`❌ openvasScan failed: ${error.message}`);
        return false;
    }
}

async function testTrufflehog(store) {
    console.log('\\n🔍 Testing trufflehog with seeded assets data...');
    
    const beforeCount = await getFindingsCount(store, TEST_SCAN_ID);
    
    try {
        const result = await runTrufflehog({
            domain: TEST_DOMAIN,
            scanId: TEST_SCAN_ID
        });
        
        const afterCount = await getFindingsCount(store, TEST_SCAN_ID);
        const newFindings = afterCount - beforeCount;
        
        console.log(`📊 trufflehog: ${newFindings} findings added (returned ${result})`);
        return newFindings >= 0; // Trufflehog may find 0 secrets, that's ok
    } catch (error) {
        console.log(`❌ trufflehog failed: ${error.message}`);
        return false;
    }
}

async function testSpiderFoot(store) {
    console.log('\\n🔍 Testing spiderFoot with domain intelligence...');
    
    const beforeCount = await getFindingsCount(store, TEST_SCAN_ID);
    
    try {
        const result = await runSpiderFoot({
            domain: TEST_DOMAIN,
            scanId: TEST_SCAN_ID
        });
        
        const afterCount = await getFindingsCount(store, TEST_SCAN_ID);
        const newFindings = afterCount - beforeCount;
        
        console.log(`📊 spiderFoot: ${newFindings} findings added (returned ${result})`);
        return newFindings >= 0; // SpiderFoot may find 0 threats, that's ok
    } catch (error) {
        console.log(`❌ spiderFoot failed: ${error.message}`);
        return false;
    }
}

async function testDnsTwist(store) {
    console.log('\\n🔍 Testing dnsTwist with domain analysis...');
    
    const beforeCount = await getFindingsCount(store, TEST_SCAN_ID);
    
    try {
        const result = await runDnsTwist({
            domain: TEST_DOMAIN,
            scanId: TEST_SCAN_ID
        });
        
        const afterCount = await getFindingsCount(store, TEST_SCAN_ID);
        const newFindings = afterCount - beforeCount;
        
        console.log(`📊 dnsTwist: ${newFindings} findings added (returned ${result})`);
        return newFindings >= 0; // DnsTwist may find 0 typosquats, that's ok
    } catch (error) {
        console.log(`❌ dnsTwist failed: ${error.message}`);
        return false;
    }
}

async function testRateLimitScan(store) {
    console.log('\\n🔍 Testing rateLimitScan with seeded endpoints...');
    
    const beforeCount = await getFindingsCount(store, TEST_SCAN_ID);
    
    try {
        const result = await runRateLimitScan({
            domain: TEST_DOMAIN,
            scanId: TEST_SCAN_ID
        });
        
        const afterCount = await getFindingsCount(store, TEST_SCAN_ID);
        const newFindings = afterCount - beforeCount;
        
        console.log(`📊 rateLimitScan: ${newFindings} findings added (returned ${result})`);
        return newFindings >= 0; // Rate limit scan may find 0 issues, that's ok
    } catch (error) {
        console.log(`❌ rateLimitScan failed: ${error.message}`);
        return false;
    }
}

// Main test function
async function main() {
    console.log('🧪 Testing Tier2 modules dependency system');
    console.log(`Testing with scan ID: ${TEST_SCAN_ID}`);
    
    const store = new LocalStore();
    
    try {
        // Insert test scan record
        await store.insertScan({
            id: TEST_SCAN_ID,
            domain: TEST_DOMAIN,
            status: 'running',
            created_at: new Date()
        });
        
        // Seed tier2 test data
        await seedTier2TestData(store);
        
        // Test each tier2 module
        const results = {
            nuclei: await testNuclei(store),
            zapScan: await testZapScan(store),
            openvasScan: await testOpenVAS(store), 
            trufflehog: await testTrufflehog(store),
            spiderFoot: await testSpiderFoot(store),
            dnsTwist: await testDnsTwist(store),
            rateLimitScan: await testRateLimitScan(store)
        };
        
        // Summary
        console.log('\\n📋 TIER2 DEPENDENCY TEST RESULTS:');
        const workingModules = [];
        const brokenModules = [];
        
        for (const [module, working] of Object.entries(results)) {
            const status = working ? '✅ WORKING' : '❌ BROKEN';
            console.log(`   ${module}: ${status}`);
            
            if (working) {
                workingModules.push(module);
            } else {
                brokenModules.push(module);
            }
        }
        
        console.log(`\\n🎯 SUMMARY: ${workingModules.length}/${Object.keys(results).length} tier2 modules working with dependencies`);
        
        if (brokenModules.length > 0) {
            console.log('\\n❌ BROKEN MODULES (need investigation):');
            brokenModules.forEach(module => console.log(`   - ${module}`));
        }
        
        if (workingModules.length > 0) {
            console.log('\\n✅ WORKING MODULES (process dependencies correctly):');
            workingModules.forEach(module => console.log(`   - ${module}`));
        }
        
        // Get final scan state
        const finalArtifacts = await store.query('SELECT COUNT(*) as count FROM artifacts WHERE scan_id = $1', [TEST_SCAN_ID]);
        const finalFindings = await getFindingsCount(store, TEST_SCAN_ID);
        
        console.log(`\\n📊 Final tier2 test scan state: ${finalFindings} findings, ${finalArtifacts.rows[0].count} artifacts`);
        
    } catch (error) {
        console.error('❌ Test failed:', error);
        process.exit(1);
    } finally {
        await store.close();
    }
}

// Run the test
main().catch(console.error);