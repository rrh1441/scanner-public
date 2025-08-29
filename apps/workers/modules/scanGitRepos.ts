/**
 * Git repository scanning module using TruffleHog
 * Separated from web asset scanning for better resource management
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { logLegacy as log } from '../core/logger.js';
import { TRUFFLEHOG_GIT_DEPTH } from '../core/env.js';

const exec = promisify(execFile);

// Import processTrufflehogOutput from the main module
// This function will be passed as a parameter to avoid circular imports
type ProcessTrufflehogOutputFn = (stdout: string, source_type: 'git' | 'http' | 'file', src_url: string, scanId?: string) => Promise<number>;

/**
 * Scan a single Git repository with TruffleHog
 * @param url - Git repository URL
 * @param scanId - Scan identifier
 * @param processTrufflehogOutput - Function to process TruffleHog output
 * @param depth - Maximum depth for Git history scan
 * @returns Number of findings
 */
export async function scanGitRepo(
    url: string, 
    scanId: string, 
    processTrufflehogOutput: ProcessTrufflehogOutputFn,
    depth: number = TRUFFLEHOG_GIT_DEPTH
): Promise<number> {
    log(`[trufflehog] [Git Scan] Starting scan for repository: ${url} (depth: ${depth})`);
    
    try {
        const { stdout, stderr } = await exec('trufflehog', [
            'git',
            url,
            '--json',
            '--no-verification',
            `--max-depth=${depth}`
        ], { 
            maxBuffer: 20 * 1024 * 1024, // 20MB buffer for Git history
            timeout: 120000 // 2 minute timeout for Git operations
        });

        if (stderr) {
            log(`[trufflehog] [Git Scan] [STDERR] for ${url}:`, stderr);
        }
        
        const findings = await processTrufflehogOutput(stdout, 'git', url, scanId);
        log(`[trufflehog] [Git Scan] Completed scan for ${url}: ${findings} findings`);
        
        return findings;
    } catch (err) {
        log(`[trufflehog] [Git Scan] Error scanning repository ${url}:`, (err as Error).message);
        return 0;
    }
}

/**
 * Scan multiple Git repositories sequentially to control memory usage
 * @param urls - Array of Git repository URLs
 * @param scanId - Scan identifier
 * @param processTrufflehogOutput - Function to process TruffleHog output
 * @param maxRepos - Maximum number of repositories to scan
 * @returns Total number of findings across all repositories
 */
export async function scanGitRepos(
    urls: string[], 
    scanId: string, 
    processTrufflehogOutput: ProcessTrufflehogOutputFn,
    maxRepos: number = 10
): Promise<number> {
    const reposToScan = urls.slice(0, maxRepos);
    log(`[trufflehog] [Git Scan] Starting scan of ${reposToScan.length} repositories (max: ${maxRepos})`);
    
    let totalFindings = 0;
    
    // Process repositories sequentially to avoid memory issues
    for (const url of reposToScan) {
        try {
            const findings = await scanGitRepo(url, scanId, processTrufflehogOutput);
            totalFindings += findings;
            
            // Small delay between repositories to prevent resource exhaustion
            await new Promise(resolve => setTimeout(resolve, 1000));
        } catch (error) {
            log(`[trufflehog] [Git Scan] Failed to scan repository ${url}:`, (error as Error).message);
        }
    }
    
    log(`[trufflehog] [Git Scan] Completed scan of ${reposToScan.length} repositories: ${totalFindings} total findings`);
    return totalFindings;
}

export default scanGitRepo;