#!/usr/bin/env node
/**
 * Tier 1 PE Companies Scanner - Local Infrastructure Only
 * Scans 10 PE-backed companies with Tier 1 modules (68s scan time)
 * No cloud calls - purely local SQLite infrastructure
 */

import axios from 'axios';
import { performance } from 'perf_hooks';

const SCANNER_URL = 'http://localhost:8080';

// PE Companies for Tier 1 scanning
const PE_COMPANIES = [
  { name: 'Flexi Medical Cloud (Flexi-Dent)', domain: 'flexi-dent.hu', tags: 'Banyan; PE' },
  { name: 'Eclipse EHR Solutions', domain: 'eclipsepracticemanagementsoftware.com', tags: 'Banyan; PE' },
  { name: 'WebOps', domain: 'webops.com', tags: 'Banyan; PE' },
  { name: 'HR4 Ltd.', domain: 'hr4.com', tags: 'Banyan; PE' },
  { name: 'Berkeley Myles Solutions', domain: 'progress-plus.co.uk', tags: 'Banyan; PE' },
  { name: 'Agile Fleet', domain: 'agilefleet.com', tags: 'Banyan; PE' },
  { name: 'star/trac supply chain solutions', domain: 'star-trac.de', tags: 'Banyan; PE' },
  { name: 'Coded Inc. (CodeOne)', domain: 'codeoneportal.com', tags: 'Banyan; PE' },
  { name: 'BuRPS', domain: 'burps.com.au', tags: 'Banyan; PE' },
  { name: 'Intuitive Systems', domain: 'intuitivesystems.com', tags: 'Banyan; PE' }
];

class Tier1PEScanner {
  constructor() {
    this.results = [];
    this.startTime = null;
    this.endTime = null;
  }

  async runTier1Scan(company, index) {
    const scanId = `PE_TIER1_${company.domain.replace(/[^a-zA-Z0-9]/g, '_')}_${Date.now()}`;
    const startTime = performance.now();
    
    console.log(`🚀 [${index + 1}/10] Starting Tier 1 scan: ${company.name}`);
    console.log(`   Domain: ${company.domain} | Tags: ${company.tags}`);
    
    try {
      const response = await axios.post(`${SCANNER_URL}/scan`, {
        domain: company.domain,
        scan_id: scanId,
        tier: 'tier1', // Tier 1 only - 16 modules, 68s scan time
        company_name: company.name,
        tags: company.tags
      }, {
        timeout: 180000 // 3 minute timeout for Tier 1 (expected 68s)
      });
      
      const endTime = performance.now();
      const duration = Math.round(endTime - startTime);
      
      const result = {
        index: index + 1,
        company: company.name,
        domain: company.domain,
        tags: company.tags,
        scanId,
        duration,
        status: 'success',
        findings: response.data.findings_count || 0,
        modules: response.data.modules_run || 16,
        response: response.data
      };
      
      console.log(`✅ [${index + 1}/10] Tier 1 scan completed: ${company.name}`);
      console.log(`   Time: ${(duration/1000).toFixed(1)}s | Findings: ${result.findings} | Modules: ${result.modules}`);
      
      return result;
      
    } catch (error) {
      const endTime = performance.now();
      const duration = Math.round(endTime - startTime);
      
      const result = {
        index: index + 1,
        company: company.name,
        domain: company.domain,
        tags: company.tags,
        scanId,
        duration,
        status: 'error',
        error: error.message,
        findings: 0,
        modules: 0
      };
      
      console.log(`❌ [${index + 1}/10] Tier 1 scan failed: ${company.name} - ${error.message}`);
      return result;
    }
  }

  async runAllScans() {
    console.log(`\n🎯 TIER 1 PE COMPANIES SCANNER`);
    console.log(`══════════════════════════════════════════════`);
    console.log(`Companies: ${PE_COMPANIES.length}`);
    console.log(`Tier: 1 (16 modules, ~68s per scan)`);
    console.log(`Infrastructure: Local PostgreSQL only (no cloud calls)`);
    console.log(`Expected Total Time: ~11-12 minutes\n`);
    
    this.startTime = performance.now();
    
    // Run scans sequentially to avoid overwhelming the target systems
    // This is more respectful than concurrent scanning of business domains
    for (let i = 0; i < PE_COMPANIES.length; i++) {
      const result = await this.runTier1Scan(PE_COMPANIES[i], i);
      this.results.push(result);
      
      // Small delay between scans for courtesy
      if (i < PE_COMPANIES.length - 1) {
        console.log(`   ⏳ 5s delay before next scan...\n`);
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
    
    this.endTime = performance.now();
    return this.results;
  }

  generateReport() {
    const totalDuration = Math.round(this.endTime - this.startTime);
    const successfulScans = this.results.filter(r => r.status === 'success');
    const failedScans = this.results.filter(r => r.status === 'error');
    
    const totalFindings = successfulScans.reduce((sum, r) => sum + r.findings, 0);
    const avgScanTime = successfulScans.length > 0 
      ? Math.round(successfulScans.reduce((sum, r) => sum + r.duration, 0) / successfulScans.length)
      : 0;
    
    console.log(`\n📊 TIER 1 PE COMPANIES SCAN RESULTS`);
    console.log(`════════════════════════════════════════════════════`);
    console.log(`Total Scanning Time: ${(totalDuration/1000/60).toFixed(1)} minutes`);
    console.log(`Companies Scanned: ${PE_COMPANIES.length}`);
    console.log(`Successful: ${successfulScans.length}/${PE_COMPANIES.length} (${((successfulScans.length/PE_COMPANIES.length)*100).toFixed(1)}%)`);
    console.log(`Failed: ${failedScans.length}/${PE_COMPANIES.length}`);
    console.log(`Average Scan Time: ${(avgScanTime/1000).toFixed(1)}s (Target: 68s)`);
    console.log(`Total Security Findings: ${totalFindings}`);
    
    console.log(`\n🏢 COMPANY SCAN RESULTS:`);
    this.results.forEach(result => {
      const status = result.status === 'success' ? '✅' : '❌';
      const time = `${(result.duration/1000).toFixed(1)}s`;
      const findings = result.status === 'success' ? `${result.findings} findings` : result.error;
      console.log(`${status} ${result.company}`);
      console.log(`   ${result.domain} | ${time} | ${findings}`);
    });
    
    if (successfulScans.length > 0) {
      console.log(`\n💾 DATABASE VERIFICATION:`);
      console.log(`psql scanner_local -c "SELECT scan_id, domain, status, findings_count FROM scans WHERE scan_id LIKE 'PE_TIER1_%' ORDER BY created_at DESC;"`);
      
      console.log(`\n📄 GENERATE REPORTS:`);
      successfulScans.forEach(scan => {
        console.log(`curl -s http://localhost:8080/reports/${scan.scanId}/report.pdf > ${scan.domain}_report.pdf`);
      });
    }

    return {
      totalDuration,
      totalCompanies: PE_COMPANIES.length,
      successRate: (successfulScans.length / PE_COMPANIES.length) * 100,
      avgScanTime,
      totalFindings,
      results: this.results
    };
  }
}

// Health check
async function checkHealth() {
  try {
    const response = await axios.get(`${SCANNER_URL}/health`);
    console.log(`✅ Scanner health check passed`);
    console.log(`Database: ${response.data.database || 'Connected'}`);
    console.log(`Tier 1 Modules: ${response.data.tier1_modules || '16'} available`);
    return true;
  } catch (error) {
    console.error(`❌ Health check failed: ${error.message}`);
    console.error(`Make sure scanner is running: node dist/localServer.js`);
    return false;
  }
}

// Main execution
async function main() {
  console.log(`🔬 TIER 1 PE COMPANIES SCANNER`);
  console.log(`Local Infrastructure Only - No Cloud Calls`);
  
  // Health check
  const isHealthy = await checkHealth();
  if (!isHealthy) {
    process.exit(1);
  }
  
  // Run all Tier 1 scans
  const scanner = new Tier1PEScanner();
  await scanner.runAllScans();
  
  // Generate and display report
  const report = scanner.generateReport();
  
  console.log(`\n🎉 Tier 1 PE scanning completed!`);
  console.log(`Success rate: ${report.successRate.toFixed(1)}% | Total findings: ${report.totalFindings}`);
  
  // Exit with appropriate code
  process.exit(report.successRate > 80 ? 0 : 1);
}

main().catch(console.error);