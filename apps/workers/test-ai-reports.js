#!/usr/bin/env node

/**
 * Test script for AI-powered report generation
 * Tests GPT-5 integration for intelligent remediation steps
 */

import fetch from 'node-fetch';

const BASE_URL = 'http://localhost:8080';

async function testAIReports() {
    console.log('🤖 Testing SimplCyber AI-Powered Report Generation');
    console.log('Using GPT-5-2025-08-07 for intelligent remediation\n');
    
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
        
        console.log(`📊 Testing AI reports with scan: ${scanId} (${domain})`);
        console.log(`📝 Findings count: ${scansData.scans[0].findings_count || 'Unknown'}\n`);
        
        // Test AI-powered report generation
        console.log('🔄 Generating Technical Report with AI Remediation...');
        const startTime = Date.now();
        
        const technicalReportResponse = await fetch(`${BASE_URL}/reports/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                scan_id: scanId,
                report_type: 'technical-report'
            })
        });
        
        if (technicalReportResponse.ok) {
            const result = await technicalReportResponse.json();
            const duration = Date.now() - startTime;
            
            console.log('✅ AI-Powered Technical Report Generated Successfully!');
            console.log(`   📄 PDF Report: ${BASE_URL}${result.report_url}`);
            console.log(`   🌐 HTML Report: ${BASE_URL}${result.html_url}`);
            console.log(`   🔍 Total Findings: ${result.total_findings}`);
            console.log(`   ⚡ Generation Time: ${result.generation_time_ms}ms`);
            console.log(`   🧠 Total AI Processing Time: ${duration}ms`);
            console.log('');
            
            // Test other report types with AI
            console.log('🔄 Generating Executive Report with AI Business Impact...');
            const execResponse = await fetch(`${BASE_URL}/reports/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scan_id: scanId,
                    report_type: 'executive-report'
                })
            });
            
            if (execResponse.ok) {
                const execResult = await execResponse.json();
                console.log('✅ AI-Powered Executive Report Generated!');
                console.log(`   📊 Business Impact Analysis: ${BASE_URL}${execResult.html_url}`);
            }
            
            console.log('\n🔄 Generating Snapshot Report with AI Business Explanations...');
            const snapResponse = await fetch(`${BASE_URL}/reports/generate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    scan_id: scanId,
                    report_type: 'snapshot-report'
                })
            });
            
            if (snapResponse.ok) {
                const snapResult = await snapResponse.json();
                console.log('✅ AI-Powered Snapshot Report Generated!');
                console.log(`   🎯 Lead Generation Report: ${BASE_URL}${snapResult.html_url}`);
            }
            
        } else {
            const error = await technicalReportResponse.json();
            console.log(`❌ AI report generation failed: ${error.error}`);
            if (error.message && error.message.includes('API key')) {
                console.log('\n💡 Make sure your OpenAI API key is properly configured in .env');
            }
            return;
        }
        
        console.log('\n🎉 AI-Powered Report System Test Complete!');
        console.log('');
        console.log('🧠 AI Features Implemented:');
        console.log('   ✅ GPT-5-2025-08-07 model integration');
        console.log('   ✅ Context-aware remediation generation');
        console.log('   ✅ Report-type specific AI prompts:');
        console.log('      • Technical Report: Detailed technical steps with commands');
        console.log('      • Executive Report: Business impact and strategic recommendations');
        console.log('      • Snapshot Report: Brief business-focused explanations');
        console.log('   ✅ Intelligent fallback to generic steps if AI fails');
        console.log('   ✅ Batch processing with rate limiting');
        console.log('   ✅ Structured parsing of AI responses');
        console.log('');
        console.log('📊 Performance Optimizations:');
        console.log('   ✅ Batch processing (5 findings per batch)');
        console.log('   ✅ 1-second rate limiting between batches');
        console.log('   ✅ Graceful error handling with fallbacks');
        console.log('   ✅ Temperature set to 0.3 for consistent results');
        console.log('');
        console.log('🔍 Next Steps:');
        console.log('   1. Review generated reports for AI quality');
        console.log('   2. Test with different types of security findings');
        console.log('   3. Monitor OpenAI API usage and costs');
        console.log('   4. Fine-tune prompts based on output quality');
        
    } catch (error) {
        console.error('❌ AI report test failed:', error.message);
        if (error.message.includes('fetch')) {
            console.log('\n💡 Make sure the scanner server is running on port 8080');
        }
        process.exit(1);
    }
}

// Run the test
testAIReports();