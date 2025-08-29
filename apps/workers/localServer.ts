import { config } from 'dotenv';
config({ path: '../../.env' }); // Load .env file from project root

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { executeScan, ScanJob } from './scan/executeScan.js';
import { database } from './core/database.js';
import { QueueService } from './core/queueService.js';
import handlebars from 'handlebars';
import puppeteer from 'puppeteer';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { nanoid } from 'nanoid';

const app = express();

// Initialize database and queue with configurable concurrency
const MAX_CONCURRENT_SCANS = parseInt(process.env.MAX_CONCURRENT_SCANS || '8');
const queueService = new QueueService(MAX_CONCURRENT_SCANS);

// Initialize database connection
await database.initialize();

// Queue event listeners are handled internally by QueueService

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Static file serving for reports and artifacts
app.use('/reports', express.static('./scan-reports'));
app.use('/artifacts', express.static('./scan-artifacts'));

// Handlebars helpers
handlebars.registerHelper('toLowerCase', (str: string) => str.toLowerCase());
handlebars.registerHelper('eq', (a: any, b: any) => a === b);
handlebars.registerHelper('format_currency', (amount: number) => {
  if (!amount || isNaN(amount)) return '0';
  return new Intl.NumberFormat('en-US', {
    minimumFractionDigits: 0,
    maximumFractionDigits: 0
  }).format(amount);
});
handlebars.registerHelper('format_abbrev', (value: any) => {
  const n = Number(value) || 0;
  const abs = Math.abs(n);
  const fmt = (v: number, suffix: string) => `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)}${suffix}`;
  if (abs >= 1e12) return fmt(n / 1e12, 'T');
  if (abs >= 1e9)  return fmt(n / 1e9,  'B');
  if (abs >= 1e6)  return fmt(n / 1e6,  'M');
  if (abs >= 1e3)  return fmt(n / 1e3,  'k');
  return n.toLocaleString();
});

// Report generation functions
async function loadTemplate(): Promise<handlebars.TemplateDelegate> {
  try {
    const templatePath = join(process.cwd(), 'templates', 'report.hbs');
    const templateContent = await readFile(templatePath, 'utf-8');
    return handlebars.compile(templateContent);
  } catch (error) {
    console.error('[Report] Failed to load template:', error);
    throw new Error('Report template not found');
  }
}

async function generatePDF(html: string): Promise<Uint8Array> {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
  });
  
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    
    const pdf = await page.pdf({
      format: 'Letter',
      margin: {
        top: '20px',
        bottom: '20px',
        left: '20px',
        right: '20px'
      },
      printBackground: true
    });
    
    return pdf;
  } finally {
    await browser.close();
  }
}

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const [dbHealth, queueHealth, queueMetrics] = await Promise.all([
      database.healthCheck(),
      queueService.healthCheck(),
      queueService.getMetrics()
    ]);
    
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: '2.0.0-redis-postgres',
      database: dbHealth,
      queue: {
        status: queueHealth.status,
        max_concurrent_scans: MAX_CONCURRENT_SCANS,
        waiting: queueMetrics.waiting,
        active: queueMetrics.active,
        completed: queueMetrics.completed,
        failed: queueMetrics.failed,
        delayed: queueMetrics.delayed,
        paused: queueMetrics.paused
      },
      postgres: database.poolStats
    });
  } catch (error: any) {
    res.status(500).json({
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Queue-based scan endpoint  
app.post('/scan', async (req, res) => {
  const { domain, companyName, priority } = req.body;
  
  if (!domain) {
    return res.status(400).json({ error: 'domain is required' });
  }

  // Basic domain validation
  const domainRegex = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i;
  if (!domainRegex.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }

  // Validate priority if provided
  if (priority && !['low', 'normal', 'high'].includes(priority)) {
    return res.status(400).json({ error: 'Invalid priority. Must be one of: low, normal, high' });
  }

  try {
    // Enqueue the scan job
    const scan_id = await queueService.enqueue({
      domain: domain.toLowerCase(),
      companyName,
      priority: priority || 'normal'
    });

    // Get initial queue status
    const jobStatus = await queueService.getJobStatus(scan_id);
    
    console.log(`[Scan] Enqueued scan ${scan_id} for domain: ${domain}`);
    
    res.json({ 
      scan_id,
      status: jobStatus?.status || 'queued',
      domain: domain.toLowerCase(),
      position_in_queue: jobStatus?.position_in_queue || 0,
      message: 'Scan queued successfully. Use GET /scan/{scan_id}/status to monitor progress.',
      status_url: `/scan/${scan_id}/status`,
      report_url: `/reports/${scan_id}/report.pdf`
    });
  } catch (error: any) {
    console.error(`[Scan] Failed to enqueue scan:`, error.message);
    
    res.status(500).json({ 
      error: 'Failed to queue scan', 
      message: error.message
    });
  }
});

// Get scan status endpoint
app.get('/scan/:scanId/status', async (req, res) => {
  try {
    const { scanId } = req.params;
    const jobStatus = await queueService.getJobStatus(scanId);
    
    if (!jobStatus) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    // If it's a completed scan, also include database details
    if (jobStatus.status === 'completed' || jobStatus.status === 'failed') {
      const scan = await database.getScan(scanId);
      if (scan) {
        return res.json({
          ...jobStatus,
          domain: scan.domain,
          created_at: scan.created_at,
          completed_at: scan.completed_at,
          findings_count: scan.findings_count,
          artifacts_count: scan.artifacts_count,
          duration_ms: scan.duration_ms
        });
      }
    }
    
    res.json(jobStatus);
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to get scan status', message: error.message });
  }
});

// Cancel scan endpoint
app.delete('/scan/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    const cancelled = await queueService.cancelJob(scanId);
    
    if (cancelled) {
      res.json({ 
        scan_id: scanId, 
        status: 'cancelled',
        message: 'Scan cancelled successfully'
      });
    } else {
      res.status(404).json({ 
        error: 'Scan not found or cannot be cancelled',
        scan_id: scanId
      });
    }
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to cancel scan', message: error.message });
  }
});

// Queue metrics endpoint
app.get('/queue/metrics', async (req, res) => {
  try {
    const metrics = await queueService.getMetrics();
    res.json({
      ...metrics,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to get queue metrics', message: error.message });
  }
});

// Queue status endpoint
app.get('/queue/status', async (req, res) => {
  try {
    const [allJobs, metrics] = await Promise.all([
      queueService.getAllJobs(),
      queueService.getMetrics()
    ]);
    
    res.json({
      jobs: allJobs,
      metrics,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to get queue status', message: error.message });
  }
});

// List scans endpoint (enhanced)
app.get('/scans', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit as string) || 50;
    const [scans, queueMetrics] = await Promise.all([
      database.getRecentScans(limit),
      queueService.getMetrics()
    ]);
    
    res.json({
      scans,
      queue_info: {
        waiting: queueMetrics.waiting,
        active: queueMetrics.active,
        completed: queueMetrics.completed,
        failed: queueMetrics.failed
      },
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to fetch scans', message: error.message });
  }
});

// Get specific scan details
app.get('/scans/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    const [scan, findings] = await Promise.all([
      database.getScan(scanId),
      database.getFindingsByScanId(scanId)
    ]);
    
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    res.json({
      ...scan,
      findings
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to fetch scan details', message: error.message });
  }
});

// Generate report endpoint
app.post('/reports/generate', async (req, res) => {
  const { scan_id } = req.body;
  
  if (!scan_id) {
    return res.status(400).json({ error: 'scan_id is required' });
  }
  
  const startTime = Date.now();
  
  try {
    console.log(`[Report] Generating report for scan: ${scan_id}`);
    
    // Fetch scan data
    const scanData = await database.getScan(scan_id);
    if (!scanData) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    // Fetch findings
    const findings = await database.getFindingsByScanId(scan_id);
    
    // Process data for template
    const severityCounts = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    };
    
    findings.forEach((finding: any) => {
      const severity = finding.severity || 'INFO';
      if (severity in severityCounts) {
        severityCounts[severity as keyof typeof severityCounts]++;
      }
    });
    
    // Fetch EAL summary
    const ealSummaryResult = await database.query(
      'SELECT * FROM scan_eal_summary WHERE scan_id = $1',
      [scan_id]
    );
    const ealSummary = ealSummaryResult.rows[0] || null;
    
    const templateData = {
      scan_id,
      domain: scanData.domain || 'unknown',
      scan_date: scanData.created_at.toLocaleDateString(),
      report_date: new Date().toLocaleDateString(),
      duration_seconds: Math.round((scanData.duration_ms || 0) / 1000),
      modules_completed: scanData.metadata?.modules_completed || 0,
      total_findings: findings.length,
      findings: findings.slice(0, 50), // Limit to 50 findings for PDF size
      severity_counts: severityCounts,
      has_critical_findings: severityCounts.CRITICAL > 0,
      eal_summary: ealSummary
    };
    
    // Generate HTML from template
    const template = await loadTemplate();
    const html = template(templateData);
    
    // Generate PDF
    const pdfBuffer = await generatePDF(html);
    
    // Save report locally
    const reportPath = await database.saveReport(scan_id, Buffer.from(pdfBuffer), 'pdf');
    await database.saveReport(scan_id, Buffer.from(html), 'html');
    
    const duration = Date.now() - startTime;
    
    console.log(`[Report] Report generated in ${duration}ms: ${reportPath}`);
    
    res.json({
      report_url: `/reports/${scan_id}/report.pdf`,
      html_url: `/reports/${scan_id}/report.html`,
      scan_id,
      domain: templateData.domain,
      total_findings: templateData.total_findings,
      severity_counts: templateData.severity_counts,
      generated_at: new Date().toISOString(),
      generation_time_ms: duration,
      status: 'Report generated successfully'
    });
    
  } catch (error: any) {
    const duration = Date.now() - startTime;
    console.error('[Report] Report generation failed:', error);
    
    res.status(500).json({
      error: 'Report generation failed',
      message: error.message,
      scan_id,
      duration_ms: duration
    });
  }
});

// Direct report access routes
app.get('/reports/:scanId/report.pdf', async (req, res) => {
  try {
    const { scanId } = req.params;
    
    // Check if scan exists
    const scan = await database.getScan(scanId);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    // Try to get existing report
    const reportPath = `./scan-reports/${scanId}/report.pdf`;
    
    // Use sendFile with callback to handle file not found
    res.sendFile(reportPath, { root: process.cwd() }, async (err) => {
      if (err) {
        console.log(`[Report] PDF not found, generating for scan: ${scanId}`);
        
        // Generate report
        const generateResult = await generateReportForScan(scanId);
        if (generateResult.success) {
          // Try to send the generated file
          res.sendFile(reportPath, { root: process.cwd() }, (secondErr) => {
            if (secondErr) {
              console.error('[Report] Failed to serve generated PDF:', secondErr);
              res.status(500).json({ error: 'Failed to serve generated report' });
            }
          });
        } else {
          res.status(500).json({ error: 'Failed to generate report', message: generateResult.error });
        }
      }
    });
  } catch (error: any) {
    console.error('[Report] Error serving PDF:', error);
    res.status(500).json({ error: 'Failed to serve report', message: error.message });
  }
});

app.get('/reports/:scanId/report.html', async (req, res) => {
  try {
    const { scanId } = req.params;
    
    // Check if scan exists
    const scan = await database.getScan(scanId);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    // Try to get existing report
    const reportPath = `./scan-reports/${scanId}/report.html`;
    
    // Use sendFile with callback to handle file not found
    res.sendFile(reportPath, { root: process.cwd() }, async (err) => {
      if (err) {
        console.log(`[Report] HTML not found, generating for scan: ${scanId}`);
        
        // Generate report
        const generateResult = await generateReportForScan(scanId);
        if (generateResult.success) {
          // Try to send the generated file
          res.sendFile(reportPath, { root: process.cwd() }, (secondErr) => {
            if (secondErr) {
              console.error('[Report] Failed to serve generated HTML:', secondErr);
              res.status(500).json({ error: 'Failed to serve generated report' });
            }
          });
        } else {
          res.status(500).json({ error: 'Failed to generate report', message: generateResult.error });
        }
      }
    });
  } catch (error: any) {
    console.error('[Report] Error serving HTML:', error);
    res.status(500).json({ error: 'Failed to serve report', message: error.message });
  }
});

// Helper function to generate report for a scan
async function generateReportForScan(scan_id: string): Promise<{ success: boolean; error?: string }> {
  try {
    console.log(`[Report] Generating report for scan: ${scan_id}`);
    
    // Fetch scan data
    const scanData = await database.getScan(scan_id);
    if (!scanData) {
      return { success: false, error: 'Scan not found' };
    }
    
    // Fetch findings
    const findings = await database.getFindingsByScanId(scan_id);
    
    // Process data for template
    const severityCounts = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    };
    
    findings.forEach((finding: any) => {
      const severity = finding.severity || 'INFO';
      if (severity in severityCounts) {
        severityCounts[severity as keyof typeof severityCounts]++;
      }
    });
    
    // Fetch EAL summary
    const ealSummaryResult = await database.query(
      'SELECT * FROM scan_eal_summary WHERE scan_id = $1',
      [scan_id]
    );
    const ealSummary = ealSummaryResult.rows[0] || null;
    
    const templateData = {
      scan_id,
      domain: scanData.domain || 'unknown',
      scan_date: scanData.created_at.toLocaleDateString(),
      report_date: new Date().toLocaleDateString(),
      duration_seconds: Math.round((scanData.duration_ms || 0) / 1000),
      modules_completed: scanData.metadata?.modules_completed || 0,
      total_findings: findings.length,
      findings: findings.slice(0, 50), // Limit to 50 findings for PDF size
      severity_counts: severityCounts,
      has_critical_findings: severityCounts.CRITICAL > 0,
      eal_summary: ealSummary
    };
    
    // Generate HTML from template
    const template = await loadTemplate();
    const html = template(templateData);
    
    // Generate PDF
    const pdfBuffer = await generatePDF(html);
    
    // Save reports locally
    await database.saveReport(scan_id, Buffer.from(pdfBuffer), 'pdf');
    await database.saveReport(scan_id, Buffer.from(html), 'html');
    
    console.log(`[Report] Report generated successfully for scan: ${scan_id}`);
    return { success: true };
    
  } catch (error: any) {
    console.error('[Report] Report generation failed:', error);
    return { success: false, error: error.message };
  }
}

// Debug endpoint for testing (same as GCP version but simpler)
app.post('/debug/test-endpoints', async (req, res) => {
  const domain = req.body?.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  
  try {
    const result = await executeScan({ scan_id: `debug-${nanoid()}`, domain });
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
const port = Number(process.env.PORT ?? 8080);
app.listen(port, '0.0.0.0', () => {
  console.log(`🚀 Local Scanner Server with Queue running on http://localhost:${port}`);
  console.log(`📊 Health check: http://localhost:${port}/health`);
  console.log(`🔍 Start scan: POST http://localhost:${port}/scan`);
  console.log(`📈 Queue status: GET http://localhost:${port}/queue/status`);
  console.log(`📋 List scans: GET http://localhost:${port}/scans`);
  console.log(`📄 Reports: http://localhost:${port}/reports/{scan_id}/report.pdf`);
  console.log(`⚙️  Max concurrent scans: ${MAX_CONCURRENT_SCANS}`);
});

// Add error handlers for debugging
process.on('uncaughtException', async (error) => {
  console.error('💥 UNCAUGHT EXCEPTION:', error);
  console.error('Stack:', error.stack);
  await gracefulShutdown();
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 UNHANDLED REJECTION at:', promise, 'reason:', reason);
  console.error('Stack:', reason instanceof Error ? reason.stack : 'No stack trace');
});

// Graceful shutdown function
async function gracefulShutdown() {
  console.log('\n🛑 Shutting down gracefully...');
  
  try {
    // Shutdown queue first (waits for running scans to complete)
    await queueService.shutdown();
    console.log('✅ Queue shutdown complete');
  } catch (error) {
    console.error('❌ Queue shutdown error:', error);
  }
  
  // Close database connections
  await database.close();
  console.log('✅ Database connections closed');
}

// Graceful shutdown handlers
process.on('SIGINT', async () => {
  await gracefulShutdown();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Received SIGTERM, shutting down...');
  await gracefulShutdown();
  process.exit(0);
});