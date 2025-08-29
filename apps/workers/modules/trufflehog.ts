import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs/promises';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { logLegacy as log } from '../core/logger.js';
import { scanGitRepos } from './scanGitRepos.js';

const exec = promisify(execFile);
const EXPECTED_TRUFFLEHOG_VER = '3.83.7';
const GITHUB_RE = /^https:\/\/github\.com\/([\w.-]+\/[\w.-]+)(\.git)?$/i;
const GITLAB_RE = /^https:\/\/gitlab\.com\/([\w.-]+\/[\w.-]+)(\.git)?$/i;
const BITBUCKET_RE = /^https:\/\/bitbucket\.org\/([\w.-]+\/[\w.-]+)(\.git)?$/i;
const MAX_GIT_REPOS = 10;

type SourceType = 'git' | 'file' | 'http';

async function guardTrufflehog(): Promise<void> {
  try {
    const { stdout } = await exec('trufflehog', ['--version'], { timeout: 5000 });
    const version = stdout.match(/(\d+\.\d+\.\d+)/)?.[1];
    if (version !== EXPECTED_TRUFFLEHOG_VER) {
      log(`[trufflehog] Version mismatch: expected ${EXPECTED_TRUFFLEHOG_VER}, found ${version}`);
    }
  } catch (error) {
    throw new Error(`TruffleHog binary not available: ${(error as Error).message}`);
  }
}

/** Process TruffleHog JSON-lines output and emit findings */
function processTruffleHogOutput(output: string): { DetectorName: string; Raw: string; Verified: boolean; SourceMetadata: any }[] {
  if (!output || !output.trim()) {
    log('[trufflehog] TruffleHog returned empty output');
    return [];
  }
  
  const results: { DetectorName: string; Raw: string; Verified: boolean; SourceMetadata: any }[] = [];
  
  for (const line of output.split(/\r?\n/).filter(Boolean)) {
    try {
      const obj = JSON.parse(line);
      if (obj.DetectorName && obj.Raw) {
        results.push(obj);
      }
    } catch (e) {
      log('[trufflehog] Failed to parse TruffleHog JSON line:', (e as Error).message);
      log('[trufflehog] Raw line:', line.slice(0, 200));
    }
  }
  
  return results;
}

async function emitFindings(results: { DetectorName: string; Raw: string; Verified: boolean; SourceMetadata: any }[], src: SourceType, url: string) {
  let count = 0;
  for (const obj of results) {
    count++;
    const aid = await insertArtifact({
      type: 'secret',
      val_text: `${obj.DetectorName}: ${obj.Raw.slice(0, 40)}…`,
      severity: obj.Verified ? 'CRITICAL' : 'HIGH',
      src_url: url,
      meta: { detector: obj.DetectorName, source_type: src }
    });
    await insertFinding(
      aid,
      obj.Verified ? 'VERIFIED_SECRET' : 'POTENTIAL_SECRET',
      'Rotate/ revoke immediately.',
      obj.Raw
    );
  }
  return count;
}

// Get Git repositories from discovered web assets and endpoint discovery artifacts
async function getGitRepos(scanId: string): Promise<string[]> {
  try {
    const gitUrls = new Set<string>();
    
    // 1. Check discovered web assets for Git repository URLs
    // Pool query removed for GCP migration - starting fresh
    const webAssetsRows: any[] = [];
    const webAssetsResult = { rows: webAssetsRows };    
    if (webAssetsResult.rows.length > 0) {
      const assets = webAssetsResult.rows[0].meta?.assets || [];
      for (const asset of assets) {
        if (asset.url && (
          GITHUB_RE.test(asset.url) || 
          GITLAB_RE.test(asset.url) || 
          BITBUCKET_RE.test(asset.url) ||
          asset.url.includes('.git')
        )) {
          gitUrls.add(asset.url);
          log(`[trufflehog] Found Git repo in web assets: ${asset.url}`);
        }
      }
    }
    
    // 2. Check discovered endpoints for Git-related paths
    // Pool query removed for GCP migration - starting fresh
    const endpointsRows: any[] = [];
    const endpointsResult = { rows: endpointsRows };    
    if (endpointsResult.rows.length > 0) {
      const endpoints = endpointsResult.rows[0].meta?.endpoints || [];
      for (const endpoint of endpoints) {
        if (endpoint.path && (
          endpoint.path.includes('.git') ||
          endpoint.path.includes('/git/') ||
          endpoint.path.includes('/.git/')
        )) {
          // Construct full URL from endpoint
          const baseUrl = endpoint.baseUrl || `https://${scanId.split('-')[0]}.com`; // fallback
          const fullUrl = new URL(endpoint.path, baseUrl).toString();
          gitUrls.add(fullUrl);
          log(`[trufflehog] Found Git repo in endpoints: ${fullUrl}`);
        }
      }
    }
    
    // 3. Check for any linked_url artifacts that might contain Git repos
    // Pool query removed for GCP migration - starting fresh
    const linkedUrlsRows: any[] = [];
    const linkedUrlsResult = { rows: linkedUrlsRows };    
    for (const row of linkedUrlsResult.rows) {
      const url = row.val_text;
      if (GITHUB_RE.test(url) || GITLAB_RE.test(url) || BITBUCKET_RE.test(url)) {
        gitUrls.add(url);
        log(`[trufflehog] Found Git repo in linked URLs: ${url}`);
      }
    }
    
    const repos = Array.from(gitUrls).slice(0, MAX_GIT_REPOS);
    log(`[trufflehog] Discovered ${repos.length} Git repositories from artifacts`);
    return repos;
    
  } catch (error) {
    log(`[trufflehog] Error retrieving Git repositories from artifacts: ${(error as Error).message}`);
    return [];
  }
}

export async function runTrufflehog(job: { domain: string; scanId: string }) {
  await guardTrufflehog();

  let findings = 0;
  
  // Get Git repositories from discovered artifacts instead of spiderfoot file
  const repos = await getGitRepos(job.scanId);
  if (repos.length) {
    log(`[trufflehog] Scanning ${repos.length} Git repositories for secrets`);
    findings += await scanGitRepos(repos, job.scanId, async (output: string, src: SourceType, url: string) => {
      const secrets = processTruffleHogOutput(output);
      return await emitFindings(secrets, src, url);
    });
  } else {
    log('[trufflehog] No Git repositories found to scan from discovered artifacts');
    
    // Create an informational artifact about the lack of Git repositories
    await insertArtifact({
      type: 'scan_summary',
      val_text: `TruffleHog scan completed but no Git repositories were discovered for ${job.domain}`,
      severity: 'INFO',
      meta: { 
        scan_id: job.scanId, 
        total_findings: 0, 
        scope: 'git_discovery_failed',
        note: 'No Git repositories found in web assets, endpoints, or linked URLs'
      }
    });
  }

  await insertArtifact({
    type: 'scan_summary',
    val_text: `TruffleHog Git scan finished – ${findings} secret(s) found across ${repos.length} repositories`,
    severity: findings > 0 ? 'MEDIUM' : 'INFO',
    meta: { 
      scan_id: job.scanId, 
      total_findings: findings, 
      scope: 'git_only',
      repositories_scanned: repos.length,
      repositories_found: repos
    }
  });
  log(`[trufflehog] finished Git scan – findings=${findings}, repos=${repos.length}`);
  return findings;
}