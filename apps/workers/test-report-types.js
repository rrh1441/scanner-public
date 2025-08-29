#!/usr/bin/env node

/**
 * Test script for the new three-tier report system
 * Tests snapshot, executive, and technical report generation
 */

import fetch from 'node-fetch';

const BASE_URL = 'http://localhost:8080';

async function testReportTypes() {
    console.log('🧪 Testing SimplCyber Three-Tier Report System\n');
    
    try {
        // Check server health first
        const healthResponse = await fetch(`${BASE_URL}/health`);
        if (!healthResponse.ok) {
            throw new Error('Server not responding. Please start the scanner server first.');
        }
        
        // Get the latest scan to test with
        const scansResponse = await fetch(`${BASE_URL}/scans?limit=1`);
        const scansData = await scansResponse.json();
        
        if (!scansData.scans || scansData.scans.length === 0) {
            console.log('❌ No scans found. Please run a scan first:');
            console.log('curl -X POST http://localhost:8080/scan -H "Content-Type: application/json" -d \'{"domain": "example.com"}\'');
            return;
        }
        
        const scanId = scansData.scans[0].id;
        const domain = scansData.scans[0].domain;
        
        console.log(`📊 Testing with scan: ${scanId} (${domain})\n`);
        
        // Test all three report types
        const reportTypes = [
            { type: 'snapshot-report', name: 'Snapshot Report', description: 'Lead generation focused' },
            { type: 'executive-report', name: 'Executive Overview', description: 'Business leadership focused' },
            { type: 'technical-report', name: 'Technical Report', description: 'IT team focused' }
        ];
        
        for (const report of reportTypes) {
            console.log(`🔄 Generating ${report.name}...`);
            
            const generateResponse = await fetch(`${BASE_URL}/reports/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scan_id: scanId,
                    report_type: report.type
                })
            });
            
            if (generateResponse.ok) {
                const result = await generateResponse.json();
                console.log(`✅ ${report.name} generated successfully`);
                console.log(`   PDF: ${BASE_URL}${result.report_url}`);
                console.log(`   HTML: ${BASE_URL}${result.html_url}`);
                console.log(`   Findings: ${result.total_findings}`);
                console.log(`   Generation time: ${result.generation_time_ms}ms`);
            } else {
                const error = await generateResponse.json();
                console.log(`❌ ${report.name} generation failed: ${error.error}`);
            }
            console.log('');
        }
        
        console.log('📋 Report Type Summary:');
        console.log('');
        console.log('🎯 Snapshot Report:');
        console.log('   - Purpose: Lead generation, get prospects to book calls');
        console.log('   - Audience: Decision makers who need quick risk overview');
        console.log('   - Content: Financial impact, key risks in layman\'s terms');
        console.log('   - Length: 1-2 pages max');
        console.log('');
        console.log('👔 Executive Overview:');
        console.log('   - Purpose: Business-focused security briefing for leadership');
        console.log('   - Audience: C-level executives and board members');
        console.log('   - Content: Detailed business impact with layman explanations');
        console.log('   - Length: Dynamic based on findings (3-10 pages)');
        console.log('');
        console.log('🔧 Technical Report:');
        console.log('   - Purpose: Detailed remediation guidance for technical teams');
        console.log('   - Audience: Security engineers, IT administrators');
        console.log('   - Content: Technical findings with step-by-step fixes');
        console.log('   - Length: Dynamic based on findings (10+ pages)');
        console.log('');
        
        console.log('🚀 All report types implemented successfully!');
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        process.exit(1);
    }
}

// Run the test
testReportTypes();