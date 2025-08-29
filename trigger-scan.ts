#!/usr/bin/env tsx

// Simple script to properly trigger a scan with Firestore record creation
import { PubSub } from '@google-cloud/pubsub';
import { Firestore } from '@google-cloud/firestore';
import { nanoid } from 'nanoid';

const pubsub = new PubSub();
const firestore = new Firestore();

const SCAN_JOBS_TOPIC = 'scan-jobs';

async function createScanRecord(job: any): Promise<void> {
  try {
    await firestore.collection('scans').doc(job.scanId).set({
      scan_id: job.scanId,
      company_name: job.companyName,
      domain: job.domain,
      original_domain: job.originalDomain,
      tags: job.tags || [],
      status: 'queued',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });
    
    console.log(`[firestore] Created scan record for ${job.scanId}`);
  } catch (error) {
    console.log('[firestore] Error creating scan record:', (error as Error).message);
    throw error;
  }
}

async function publishScanJob(job: any): Promise<void> {
  try {
    const topic = pubsub.topic(SCAN_JOBS_TOPIC);
    const messageBuffer = Buffer.from(JSON.stringify(job));
    
    const messageId = await topic.publishMessage({
      data: messageBuffer,
      attributes: {
        scanId: job.scanId,
        domain: job.domain
      }
    });
    
    console.log(`[pubsub] Published scan job ${job.scanId} with message ID: ${messageId}`);
  } catch (error) {
    console.log('[pubsub] Error publishing scan job:', (error as Error).message);
    throw error;
  }
}

async function triggerScan() {
  const scanId = nanoid(11);
  const domain = 'vulnerable-test-site.vercel.app';
  
  const job = {
    scanId,
    companyName: 'Vulnerable Test Site',
    domain,
    originalDomain: domain,
    tags: ['vulnerable-test', 'manual-trigger'],
    createdAt: new Date().toISOString()
  };

  console.log(`Creating scan job ${scanId} for ${domain}...`);
  
  try {
    // First create Firestore record
    await createScanRecord(job);
    
    // Then publish to Pub/Sub
    await publishScanJob(job);
    
    console.log(`✅ Successfully triggered scan: ${scanId}`);
    console.log(`Monitor with: gcloud alpha logging tail 'resource.type="cloud_run_revision" resource.labels.service_name="scanner-service"' --project=precise-victory-467219-s4 --filter='jsonPayload.scanId="${scanId}"'`);
    
    return scanId;
  } catch (error) {
    console.error('❌ Failed to trigger scan:', (error as Error).message);
    throw error;
  }
}

triggerScan().catch(console.error);