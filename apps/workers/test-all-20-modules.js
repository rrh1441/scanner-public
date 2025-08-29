#!/usr/bin/env node

/**
 * Comprehensive test for all 20 target security modules (16 Tier1 + 4 additional)
 * Verifies the complete 20/20 module architecture
 */

import { LocalStore } from './dist/core/localStore.js';

// Import all 16 existing Tier1 modules
import { runEndpointDiscovery } from './dist/modules/endpointDiscovery.js';
import { runTlsScan } from './dist/modules/tlsScan.js';
import { runSpfDmarc } from './dist/modules/spfDmarc.js';
import { runConfigExposureScanner } from './dist/modules/configExposureScanner.js';
import { runInfostealerProbe } from './dist/modules/infostealerProbe.js';
import { runShodanScan } from './dist/modules/shodan.js';
import { runDocumentExposure } from './dist/modules/documentExposure.js';
import { runWhoisWrapper } from './dist/modules/whoisWrapper.js';
import { runTechStackScan } from './dist/modules/techStackScan.js';
import { runAbuseIntelScan } from './dist/modules/abuseIntelScan.js';
import { runAccessibilityLightweight } from './dist/modules/accessibilityLightweight.js';
import { executeModule as runLightweightCveCheck } from './dist/modules/lightweightCveCheck.js';
import { runClientSecretScanner } from './dist/modules/clientSecretScanner.js';
import { runBackendExposureScanner } from './dist/modules/backendExposureScanner.js';
import { runDenialWalletScan } from './dist/modules/denialWalletScan.js';
import { runAssetCorrelator } from './dist/modules/assetCorrelator.js';

// Import 4 additional modules to reach 20/20
import { runWebArchiveScanner } from './dist/modules/webArchiveScanner.js';
import { runAiPathFinder } from './dist/modules/aiPathFinder.js';
import { runCensysPlatformScan } from './dist/modules/censysPlatformScan.js';
import { runDbPortScan } from './dist/modules/dbPortScan.js';

const TEST_SCAN_ID = `ALL_20_MODULES_${Date.now()}`;
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

// Seed comprehensive test data
async function seedAllModulesTestData(store) {
    console.log('🌱 Seeding database for all 20 modules...');
    
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

    // Seed client assets
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
                }
            ]
        }
    });

    // Seed endpoints
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
                }
            ]
        }
    });

    // Seed technologies
    await store.insertArtifact({
        id: `${TEST_SCAN_ID}_technologies_1`,
        scan_id: TEST_SCAN_ID,
        type: 'technologies',
        file_path: '/tmp/technologies.json',
        size_bytes: 512,
        val_text: 'Detected technologies',
        metadata: {
            technologies: [
                { name: 'Apache', version: '2.4.41', confidence: 0.95 },
                { name: 'PHP', version: '7.4', confidence: 0.90 },
                { name: 'MySQL', version: '5.7', confidence: 0.85 }
            ]
        }
    });

    // Seed backend identifiers
    await store.insertArtifact({
        id: `${TEST_SCAN_ID}_backend_identifiers_1`,
        scan_id: TEST_SCAN_ID,
        type: 'backend_identifiers',
        file_path: '/tmp/backend_ids.json',
        size_bytes: 256,
        val_text: 'Backend service identifiers',
        metadata: {
            identifiers: [
                { type: 'websocket', endpoint: 'wss://testphp.vulnweb.com/ws' },
                { type: 'api', endpoint: 'https://testphp.vulnweb.com/api' },
                { type: 'admin', endpoint: 'https://testphp.vulnweb.com/admin' }
            ]
        }
    });
    
    console.log('✅ Seeded test data for all 20 modules');
}

// Main test function
async function main() {
    console.log('🧪 Testing ALL 20 Security Modules (16 Tier1 + 4 Additional)');
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
        
        // Seed comprehensive test data
        await seedAllModulesTestData(store);
        
        const startTime = Date.now();
        
        // Test all 16 existing Tier1 modules
        console.log('\n📋 TESTING 16 TIER1 MODULES:');
        const tier1Results = await Promise.all([
            timeModule('shodan_scan', runShodanScan({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID, companyName: TEST_DOMAIN.split('.')[0] })),
            timeModule('whois_wrapper', runWhoisWrapper({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('spf_dmarc', runSpfDmarc({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('abuse_intel_scan', runAbuseIntelScan({ scanId: TEST_SCAN_ID })),
            timeModule('client_secret_scanner', runClientSecretScanner({ scanId: TEST_SCAN_ID })),
            timeModule('backend_exposure_scanner', runBackendExposureScanner({ scanId: TEST_SCAN_ID })),
            timeModule('denial_wallet_scan', runDenialWalletScan({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('accessibility_lightweight', runAccessibilityLightweight({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('lightweight_cve_check', (async () => {
                const result = await runLightweightCveCheck({ scanId: TEST_SCAN_ID, domain: TEST_DOMAIN, artifacts: [] });
                return result.findings ? result.findings.length : 0;
            })()),
            timeModule('infostealer_probe', runInfostealerProbe({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('document_exposure', runDocumentExposure({ companyName: TEST_DOMAIN.split('.')[0], domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('config_exposure', runConfigExposureScanner({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('tls_scan', runTlsScan({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('endpoint_discovery', runEndpointDiscovery({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('tech_stack_scan', runTechStackScan({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('asset_correlator', runAssetCorrelator({ scanId: TEST_SCAN_ID, domain: TEST_DOMAIN, tier: 'tier1' }))
        ]);

        // Test 4 additional modules
        console.log('\n📋 TESTING 4 ADDITIONAL MODULES:');
        const additionalResults = await Promise.all([
            timeModule('web_archive_scanner', runWebArchiveScanner({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('ai_path_finder', runAiPathFinder({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('censys_platform_scan', runCensysPlatformScan({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID })),
            timeModule('db_port_scan', runDbPortScan({ domain: TEST_DOMAIN, scanId: TEST_SCAN_ID }))
        ]);

        // Combine results
        const allResults = [...tier1Results, ...additionalResults];
        const totalTime = Date.now() - startTime;
        
        // Analyze results
        const workingModules = allResults.filter(r => r.success);
        const failedModules = allResults.filter(r => !r.success);
        
        console.log('\n🎯 FINAL RESULTS - ALL 20 MODULES:');
        console.log(`✅ WORKING: ${workingModules.length}/20 modules`);
        console.log(`❌ FAILED: ${failedModules.length}/20 modules`);
        console.log(`⏱️ TOTAL TIME: ${Math.round(totalTime/1000)}s`);
        
        if (failedModules.length > 0) {
            console.log('\n❌ FAILED MODULES:');
            failedModules.forEach(r => {
                console.log(`   ${r.module}: ${r.error}`);
            });
        }
        
        if (workingModules.length === 20) {
            console.log('\n🎉 SUCCESS: ALL 20/20 MODULES WORKING!');
            console.log('   - 16 Tier1 modules operational');
            console.log('   - 4 additional modules functional'); 
            console.log('   - Complete security scanning architecture achieved');
        } else {
            console.log(`\n⚠️  PARTIAL SUCCESS: ${workingModules.length}/20 modules working`);
        }
        
        // Get final scan state
        const finalFindings = await getFindingsCount(store, TEST_SCAN_ID);
        const finalArtifacts = await store.query('SELECT COUNT(*) as count FROM artifacts WHERE scan_id = $1', [TEST_SCAN_ID]);
        
        console.log(`\n📊 Final scan state: ${finalFindings} findings, ${finalArtifacts.rows[0].count} artifacts`);
        
        return workingModules.length;
        
    } catch (error) {
        console.error('❌ Test failed:', error);
        process.exit(1);
    } finally {
        await store.close();
    }
}

// Run the test
main().then(workingCount => {
    if (workingCount === 20) {
        console.log('\n🚀 DEPLOYMENT READY: 20/20 modules operational!');
        process.exit(0);
    } else {
        console.log(`\n🔧 NEEDS WORK: Only ${workingCount}/20 modules working`);
        process.exit(1);
    }
}).catch(console.error);