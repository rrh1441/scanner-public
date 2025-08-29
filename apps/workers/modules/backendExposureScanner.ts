/* eslint-disable @typescript-eslint/explicit-function-return-type */
import crypto from 'crypto';
import fetch, { Response } from 'node-fetch';
import pThrottle from 'p-throttle';
import { AbortController } from 'abort-controller';
import WebSocket from 'ws';

import { BackendIdentifier } from './endpointDiscovery.js';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as log } from '../core/logger.js';

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */

const LIMIT = pThrottle({ limit: 2, interval: 1_000 });
const BODY_CAP = 512 * 1024;                 // 512 KB
const TIMEOUT = 8_000;                       // probe ms
const WS_TIMEOUT = 3_000;
const BACKOFF_THRESHOLD = 3;                 // errors → give up

type ProbeState = Record<string, { errors: number; ts: number }>;

/* ------------------------------------------------------------------ */
/* URL builders                                                        */
/* ------------------------------------------------------------------ */

function urls(id: BackendIdentifier): string[] {
  switch (id.provider) {
    case 'firebase':
      return [
        `https://${id.id}.firebaseio.com/.json?print=silent`,
        `https://${id.id}.firebasedatabase.app/.json?print=silent`,
        `https://firestore.googleapis.com/v1/projects/${id.id}/databases/(default)/documents`
      ];
    case 's3':
      return [`https://${id.id}.s3.amazonaws.com/?list-type=2`];
    case 'gcs':
      return [
        `https://${id.id}.storage.googleapis.com/?delimiter=/`,
        `https://storage.googleapis.com/${id.id}/?delimiter=/`
      ];
    case 'azure':
      return [
        `https://${id.id}.blob.core.windows.net/?comp=list`,
        `https://${id.id}.file.core.windows.net/?comp=list`
      ];
    case 'supabase':
      return [
        `https://${id.id}.supabase.co/rest/v1/`,
        `https://${id.id}.supabase.co/storage/v1/bucket/`
      ];
    case 'realm':
      return [`https://${id.id}.realm.mongodb.com`];
    default:
      return [];
  }
}

function wsUrls(id: BackendIdentifier): string[] {
  if (id.provider === 'firebase')
    return [`wss://${id.id}.firebaseio.com/.ws?v=5`];
  if (id.provider === 'supabase')
    return [`wss://${id.id}.supabase.co/realtime/v1/websocket`];
  return [];
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

async function throttledFetch(url: string): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT);
  
  try {
    const throttledFn = LIMIT(async () => {
      return await fetch(url, { 
        method: 'GET', 
        redirect: 'follow', 
        size: BODY_CAP, 
        signal: controller.signal 
      });
    });
    const result = await throttledFn();
    clearTimeout(timeoutId);
    return result;
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
}

async function probeWS(url: string): Promise<boolean> {
  return new Promise((resolve) => {
    const ws = new WebSocket(url, { handshakeTimeout: WS_TIMEOUT });
    ws.on('open', () => { ws.terminate(); resolve(true); });
    ws.on('error', () => resolve(false));
  });
}

function sha256Body(body: string): string {
  return crypto.createHash('sha256').update(body).digest('hex');
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */

export async function runBackendExposureScanner(job: { scanId: string }): Promise<number> {
  log('[backendExposureScanner] ▶ start', job.scanId);
  
  // Get backend identifiers from database
  const { LocalStore } = await import('../core/localStore.js');
  const store = new LocalStore();
  
  let ids: BackendIdentifier[] = [];
  
  try {
    const result = await store.query(
      'SELECT metadata FROM artifacts WHERE scan_id = $1 AND type = $2',
      [job.scanId, 'backend_identifiers']
    );
    
    for (const row of result.rows) {
      if (row.metadata?.backend_ids) {
        ids = ids.concat(row.metadata.backend_ids);
      } else if (row.metadata?.ids) {
        // Handle test data format
        ids = ids.concat(row.metadata.ids);
      }
    }
  } finally {
    await store.close();
  }
  
  if (!ids.length) { 
    log('no backend identifiers'); 
    return 0; 
  }
  const backoff: ProbeState = Object.create(null);
  let findings = 0;

  for (const id of ids) {
    if (!urls(id).length) continue;

    // Skip provider if repeatedly errored
    if (backoff[id.provider]?.errors >= BACKOFF_THRESHOLD) continue;

    for (const u of urls(id)) {
      try {
        const res = await throttledFetch(u);
        if (res.status === 200 && res.headers.get('content-type')?.startsWith('application/json')) {
          const text = await res.text();
          if (text.trim().length) {
            const proof = sha256Body(text.slice(0, 1024));
            await insertFinding(
              await insertArtifact({
                type: 'exposed_backend',
                severity: 'CRITICAL',
                val_text: `[${id.provider}] Public data at ${u}`,
                src_url : u,
                meta    : { scan_id: job.scanId, id, proof, bytes: text.length }
              }),
              'BACKEND_EXPOSED',
              'Unauthenticated read access detected.',
              `SHA‑256(1 KiB sample) = ${proof}`
            );
            findings++;
          }
        } else if ([401, 403].includes(res.status)) {
          // private – do nothing
        } else if (res.status === 429 || res.status >= 500) {
          backoff[id.provider] = { errors: (backoff[id.provider]?.errors || 0) + 1, ts: Date.now() };
        }
      } catch {
        backoff[id.provider] = { errors: (backoff[id.provider]?.errors || 0) + 1, ts: Date.now() };
      }
    }

    // Optional WebSocket probe
    for (const w of wsUrls(id)) {
      const open = await probeWS(w);
      if (open) {
        await insertFinding(
          await insertArtifact({
            type     : 'exposed_backend',
            severity : 'HIGH',
            val_text : `[${id.provider}] WebSocket open at ${w}`,
            src_url  : w,
            meta     : { scan_id: job.scanId, id }
          }),
          'BACKEND_WEBSOCKET_OPEN',
          'Unauthenticated WebSocket accepted TCP handshake.',
          'Consider ACLs / service rules.'
        );
        findings++;
      }
    }
  }

  await insertArtifact({
    type     : 'scan_summary',
    severity : findings ? 'HIGH' : 'INFO',
    val_text : `Backend exposure scan complete – ${findings} finding(s)`,
    meta     : { scan_id: job.scanId, module: 'backendExposureScanner', findings }
  });

  log('[backendExposureScanner] ▶ done', findings);
  return findings;
}