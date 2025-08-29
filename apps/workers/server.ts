import Fastify from 'fastify';
import { executeScan, ScanJob } from './scan/executeScan.js';
import { CloudTasksClient } from '@google-cloud/tasks';
import * as crypto from 'node:crypto';
import { Firestore } from '@google-cloud/firestore';
import { Storage } from '@google-cloud/storage';
import handlebars from 'handlebars';
import puppeteer from 'puppeteer';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

// Initialize services
const PROJECT_ID = process.env.GOOGLE_CLOUD_PROJECT || 'precise-victory-467219-s4';
const GCS_BUCKET = `${PROJECT_ID}-scan-artifacts`;
const firestore = new Firestore({ projectId: PROJECT_ID });
const storage = new Storage({ projectId: PROJECT_ID });

console.log(`[server] Firestore initialized with project: ${PROJECT_ID}`);
console.log(`[server] GCS bucket: ${GCS_BUCKET}`);

type PubSubMessage = {
  message?: { data?: string };
  subscription?: string;
};

function parseBase64Json<T>(b64?: string): T | null {
  if (!b64) return null;
  try {
    const decoded = Buffer.from(b64, 'base64').toString('utf8');
    return JSON.parse(decoded) as T;
  } catch {
    return null;
  }
}

async function enqueueScanTask(job: ScanJob): Promise<void> {
  const project = process.env.GCP_PROJECT ?? '';
  const location = process.env.GCP_LOCATION ?? 'us-central1';
  const queue = process.env.TASKS_QUEUE ?? 'scan-queue';
  const url = process.env.TASKS_WORKER_URL ?? ''; // e.g., https://<service-url>/tasks/scan
  const serviceAccount = process.env.SCAN_WORKER_SA ?? '';

  if (!project || !url) {
    throw new Error('Missing GCP_PROJECT or TASKS_WORKER_URL');
  }

  const client = new CloudTasksClient();
  const parent = client.queuePath(project, location, queue);

  const payload = JSON.stringify(job);

  // Create idempotent task name using scan_id
  const taskName = `${parent}/tasks/${job.scan_id}-${Date.now()}`;

  const task = {
    name: taskName,
    httpRequest: {
      httpMethod: 'POST' as const,
      url,
      headers: { 'Content-Type': 'application/json' },
      body: Buffer.from(payload),
      // Add OIDC token for authentication
      ...(serviceAccount && {
        oidcToken: { 
          serviceAccountEmail: serviceAccount,
          audience: url.split('/').slice(0, 3).join('/')  // Extract base URL as audience
        }
      }),
    },
    scheduleTime: { seconds: Math.floor(Date.now() / 1000) }, // immediate
  };

  try {
    await client.createTask({
      parent,
      task,
    });
  } catch (err: any) {
    // If task already exists (idempotency), that's OK
    if (err.code === 6) { // ALREADY_EXISTS
      console.log(`Task ${taskName} already exists, skipping`);
    } else {
      throw err;
    }
  }
}

// Handlebars helpers
handlebars.registerHelper('toLowerCase', (str: string) => str.toLowerCase());
handlebars.registerHelper('eq', (a: any, b: any) => a === b);

// Report generation functions
async function loadTemplate(): Promise<handlebars.TemplateDelegate> {
  try {
    const templatePath = join(process.cwd(), 'apps', 'workers', 'templates', 'report.hbs');
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
      format: 'Letter', // US Letter (8.5" x 11")
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

export function buildServer() {
  const app = Fastify({ 
    logger: {
      level: 'info'
    }
  });

  // Health — NO external calls
  app.get('/', async () => ({ status: 'ok', ts: Date.now() }));

  // Debug endpoint to test IPv6 hypothesis
  app.get('/debug/network-test', async (request, reply) => {
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);
    
    const domain = (request.query as any)?.domain || 'openai.com';
    
    const curlTest = async (ipVersion: string) => {
      try {
        const { stdout, stderr } = await execAsync(
          `curl -${ipVersion} --connect-timeout 5 -s -o /dev/null -w '%{http_code} | %{time_total}s | %{remote_ip}' https://${domain}`,
          { timeout: 6000 }
        );
        return { success: true, result: stdout, stderr };
      } catch (error: any) {
        return { success: false, error: error.message, stderr: error.stderr };
      }
    };

    const [ipv4, ipv6] = await Promise.all([curlTest('4'), curlTest('6')]);
    
    return { 
      domain,
      ipv4_result: ipv4, 
      ipv6_result: ipv6,
      timestamp: new Date().toISOString()
    };
  });

  // --- Eventarc/PubSub push endpoint: FAST-ACK ---
  // Eventarc delivers a Pub/Sub-style envelope with { message: { data: base64(json) } }
  app.post<{ Body: PubSubMessage }>('/events', async (req, reply) => {
    const body = req.body;
    
    // Validate Pub/Sub message structure
    if (!body || typeof body !== 'object' || !body.message) {
      console.warn('Invalid Pub/Sub envelope structure:', body);
      return reply.code(204).send(); // ack to avoid redelivery
    }
    
    // Parse the base64-encoded message data
    const msg = parseBase64Json<ScanJob>(body.message.data);
    
    // Validate the scan job payload
    if (!msg || typeof msg !== 'object' || !msg.domain || typeof msg.domain !== 'string') {
      console.warn('Invalid scan job payload:', {
        subscription: body.subscription,
        messageData: body.message.data,
        parsed: msg 
      });
      return reply.code(204).send(); // ack to avoid redelivery loop
    }
    
    // Validate domain format (basic check)
    const domainRegex = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i;
    if (!domainRegex.test(msg.domain)) {
      console.warn('Invalid domain format:', msg.domain);
      return reply.code(204).send();
    }

    // Ensure scan_id is valid
    const scan_id = msg.scan_id && msg.scan_id.length > 0 ? msg.scan_id : crypto.randomUUID();
    const job: ScanJob = { 
      scan_id, 
      domain: msg.domain.toLowerCase(), // normalize domain
      companyName: msg.companyName 
    };

    // Log the incoming event
    console.log('[events] Received Pub/Sub event:', {
      scan_id: job.scan_id,
      domain: job.domain,
      subscription: body.subscription,
      messageId: (body.message as any)?.messageId
    });

    // Enqueue to Cloud Tasks and ack immediately
    try {
      await enqueueScanTask(job);
      console.log('[events] Successfully enqueued scan task:', job.scan_id);
      return reply.code(204).send(); // 2xx == ack
    } catch (err) {
      console.error('[events] Failed to enqueue task:', {
        error: err, 
        scan_id: job.scan_id,
        domain: job.domain 
      });
      // Still 204 to avoid redelivery loops; alternatively 500 if you prefer redelivery
      return reply.code(204).send();
    }
  });

  // --- Cloud Tasks worker endpoint ---
  app.post<{ Body: ScanJob }>('/tasks/scan', async (req, reply) => {
    console.log('🔥 /tasks/scan HANDLER REACHED! Headers:', req.headers);
    const startTime = Date.now();
    const body = req.body as ScanJob;
    const { scan_id, domain } = body ?? {};
    
    console.log('📦 Body received:', body);
    
    if (!scan_id || !domain) {
      console.error('❌ Missing required fields:', { scan_id, domain });
      return reply.code(400).send({ error: 'scan_id and domain are required' });
    }

    // Verify OIDC token if configured
    const authHeader = req.headers.authorization;
    const requireAuth = process.env.REQUIRE_AUTH === 'true';
    console.log('🔐 Auth check:', { requireAuth, hasAuthHeader: !!authHeader });
    
    if (requireAuth && !authHeader?.startsWith('Bearer ')) {
      console.warn('[worker] Missing or invalid authorization header for scan:', scan_id);
      return reply.code(401).send({ error: 'Unauthorized' });
    }

    console.log('[worker] starting scan:', {
      scan_id, 
      domain,
      task_queue_name: req.headers['x-cloudtasks-queuename'],
      task_retry_count: req.headers['x-cloudtasks-taskretrycount'],
      task_execution_count: req.headers['x-cloudtasks-taskexecutioncount']
    });
    
    try {
      const result = await executeScan({ scan_id, domain });
      
      const duration = Date.now() - startTime;
      console.log('[worker] scan completed successfully:', {
        scan_id,
        duration_ms: duration,
        modules_completed: Object.keys(result.results).length
      });

      // Persist scan result to Firestore
      try {
        console.log(`[Firestore] Persisting scan result for ${scan_id}`);
        
        // Count findings and artifacts
        let totalFindings = 0;
        let totalArtifacts = 0;
        const moduleStatus: Record<string, any> = {};
        
        for (const [moduleName, moduleResult] of Object.entries(result.results)) {
          const res = moduleResult as any;
          if (res.findings_count) totalFindings += res.findings_count;
          if (res.artifacts_count) totalArtifacts += res.artifacts_count;
          
          moduleStatus[moduleName] = {
            status: res.status || 'completed',
            findings: res.findings_count || 0,
            artifacts: res.artifacts_count || 0,
            duration_ms: res.duration_ms || 0
          };
        }
        
        const scanDoc = {
          scan_id,
          domain,
          status: 'completed',
          created_at: new Date(),
          completed_at: new Date(),
          duration_ms: duration,
          modules_completed: Object.keys(result.results).length,
          modules_failed: result.metadata?.modules_failed || 0,
          findings_count: totalFindings,
          artifacts_count: totalArtifacts,
          module_status: moduleStatus,
          metadata: result.metadata
        };
        
        await firestore.collection('scans').doc(scan_id).set(scanDoc);
        console.log(`[Firestore] Successfully persisted scan ${scan_id} with ${totalFindings} findings`);
      } catch (error: any) {
        console.error('[Firestore] Failed to persist scan result:', {
          scan_id,
          error: error.message,
          code: error.code,
          details: error.details
        });
        // Don't fail the request if persistence fails
      }
      
      return reply.code(200).send(result);
    } catch (err) {
      const duration = Date.now() - startTime;
      console.error('[worker] scan failed:', {
        scan_id,
        domain,
        duration_ms: duration,
        error: err instanceof Error ? err.message : String(err),
        stack: err instanceof Error ? err.stack : undefined
      });
      
      // Persist failed scan to Firestore
      try {
        const failedScanDoc = {
          scan_id,
          domain,
          status: 'failed',
          created_at: new Date(),
          failed_at: new Date(),
          duration_ms: duration,
          error_message: err instanceof Error ? err.message : String(err),
          error_stack: err instanceof Error ? err.stack : undefined
        };
        
        await firestore.collection('scans').doc(scan_id).set(failedScanDoc);
        console.log(`[Firestore] Persisted failed scan ${scan_id}`);
      } catch (firestoreError: any) {
        console.error('[Firestore] Failed to persist failed scan:', {
          scan_id,
          error: firestoreError.message
        });
      }
      
      // Return 500 to trigger Cloud Tasks retry
      return reply.code(500).send({ 
        error: 'Scan failed', 
        message: err instanceof Error ? err.message : String(err) 
      });
    }
  });

  // --- Report Generation Endpoint ---
  app.post<{ Body: { scan_id: string } }>('/reports/generate', async (req, reply) => {
    console.log('🔥 /reports/generate HANDLER REACHED!');
    const { scan_id } = req.body;
    
    if (!scan_id) {
      console.error('❌ Missing scan_id in report request');
      return reply.code(400).send({ error: 'scan_id is required' });
    }
    
    const startTime = Date.now();
    
    try {
      console.log(`[Report] Generating report for scan: ${scan_id}`);
      
      // 1. Fetch scan document from Firestore
      console.log('[Report] Fetching scan document from Firestore...');
      const scanDoc = await firestore.collection('scans').doc(scan_id).get();
      
      if (!scanDoc.exists) {
        console.warn(`[Report] Scan ${scan_id} not found in Firestore`);
        return reply.code(404).send({ error: 'Scan not found' });
      }
      
      const scanData = scanDoc.data();
      console.log(`[Report] Found scan: ${scanData?.domain} - ${scanData?.status}`);
      
      // 2. Fetch findings for this scan
      console.log('[Report] Fetching findings from Firestore...');
      const findingsSnapshot = await firestore.collection('findings')
        .where('scan_id', '==', scan_id)
        .orderBy('created_at', 'desc')
        .get();
      
      const findings = findingsSnapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));
      
      console.log(`[Report] Found ${findings.length} findings`);
      
      // 3. Process data for template
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
      
      const templateData = {
        scan_id,
        domain: scanData?.domain || 'unknown',
        scan_date: scanData?.created_at ? new Date(scanData.created_at.toDate()).toLocaleDateString() : new Date().toLocaleDateString(),
        report_date: new Date().toLocaleDateString(),
        duration_seconds: Math.round((scanData?.duration_ms || 0) / 1000),
        modules_completed: scanData?.modules_completed || 0,
        total_findings: findings.length,
        findings: findings.slice(0, 50), // Limit to 50 findings for PDF size
        severity_counts: severityCounts,
        has_critical_findings: severityCounts.CRITICAL > 0
      };
      
      console.log('[Report] Template data prepared:', {
        domain: templateData.domain,
        total_findings: templateData.total_findings,
        severity_counts: templateData.severity_counts
      });
      
      // 4. Generate HTML from template
      console.log('[Report] Loading template and generating HTML...');
      const template = await loadTemplate();
      const html = template(templateData);
      
      // 5. Generate PDF
      console.log('[Report] Converting HTML to PDF...');
      const pdfBuffer = await generatePDF(html);
      console.log(`[Report] PDF generated: ${pdfBuffer.length} bytes`);
      
      // 6. Upload to GCS
      console.log('[Report] Uploading PDF to GCS...');
      const bucket = storage.bucket(GCS_BUCKET);
      const fileName = `reports/${scan_id}/report-${Date.now()}.pdf`;
      const file = bucket.file(fileName);
      
      await file.save(pdfBuffer, {
        metadata: {
          contentType: 'application/pdf',
          metadata: {
            scanId: scan_id,
            domain: templateData.domain,
            generatedAt: new Date().toISOString()
          }
        }
      });
      
      console.log(`[Report] PDF uploaded to GCS: ${fileName}`);
      
      // 7. Return GCS path for now (signed URLs need additional setup)
      const reportUrl = `gs://${GCS_BUCKET}/${fileName}`;
      console.log(`[Report] Report saved to GCS: ${reportUrl}`);
      
      const duration = Date.now() - startTime;
      console.log(`[Report] Report generation completed in ${duration}ms`);
      
      return reply.code(200).send({
        report_url: reportUrl,
        gcs_path: fileName,
        scan_id,
        domain: templateData.domain,
        total_findings: templateData.total_findings,
        severity_counts: templateData.severity_counts,
        generated_at: new Date().toISOString(),
        generation_time_ms: duration,
        status: 'Report generated successfully - download via GCS console'
      });
      
    } catch (error: any) {
      const duration = Date.now() - startTime;
      console.error('[Report] Report generation failed:', {
        scan_id,
        error: error.message,
        stack: error.stack,
        duration_ms: duration
      });
      
      return reply.code(500).send({
        error: 'Report generation failed',
        message: error.message,
        scan_id
      });
    }
  });

  // --- Optional: synchronous test route (for manual validation only) ---
  app.post<{ Body: { domain: string } }>('/debug/test-endpoints', async (req, reply) => {
    const domain = req.body?.domain;
    if (!domain) return reply.code(400).send({ error: 'domain required' });
    const result = await executeScan({ scan_id: crypto.randomUUID(), domain });
    return reply.code(200).send(result);
  });

  return app;
}

// Start server if this is the main module
if (import.meta.url === `file://${process.argv[1]}`) {
  const app = buildServer();
  const port = Number(process.env.PORT ?? 8080);
  app
    .listen({ port, host: '0.0.0.0' })
    .catch((err) => {
      // eslint-disable-next-line no-console
      console.error(err);
      process.exit(1);
    });
}