/**
 * TypeScript wrapper for the Python WHOIS resolver (RDAP + Whoxy)
 * Provides 87% cost savings vs WhoisXML
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { logLegacy as log } from '../core/logger.js';

const exec = promisify(execFile);

interface WhoisRecord {
  domain: string;
  registrant_name?: string;
  registrant_org?: string;
  registrar?: string;
  creation_date?: string;
  source: 'rdap' | 'whoxy';
  fetched_at: string;
}

interface WhoisStats {
  rdap_calls: number;
  whoxy_calls: number;
  estimated_cost: number;
  saved_vs_whoisxml: number;
}

/**
 * Resolve WHOIS data for multiple domains using hybrid RDAP+Whoxy approach
 * Cost: ~$0.002/call (vs $0.015/call for WhoisXML) = 87% savings
 */
export async function resolveWhoisBatch(domains: string[]): Promise<{ records: WhoisRecord[]; stats: WhoisStats }> {
  if (!process.env.WHOXY_API_KEY) {
    log('[whoisWrapper] WHOXY_API_KEY not set - WHOIS resolution disabled');
    return { 
      records: domains.map(d => ({
        domain: d,
        source: 'rdap' as const,
        fetched_at: new Date().toISOString()
      })),
      stats: { rdap_calls: 0, whoxy_calls: 0, estimated_cost: 0, saved_vs_whoisxml: 0 }
    };
  }

  const tempFile = join('/tmp', `whois_domains_${Date.now()}.json`);
  
  try {
    // Write domains to temp file
    await writeFile(tempFile, JSON.stringify(domains));
    
    // Call Python resolver with domains as arguments
    // Point to source file since Python files aren't copied to dist
    const pythonScript = join(process.cwd(), 'modules', 'whoisResolver.py');
    const { stdout, stderr } = await exec('python3', [pythonScript, ...domains], { 
        timeout: 60_000,
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer to prevent hanging
        env: { 
          ...process.env, 
          WHOXY_API_KEY: process.env.WHOXY_API_KEY || ''
        }
      });

    if (stderr) {
      log('[whoisWrapper] Python stderr:', stderr);
    }

    // Parse line-by-line JSON output from Python script
    const lines = stdout.trim().split('\n').filter(line => line.trim());
    const records: WhoisRecord[] = [];
    
    for (const line of lines) {
      try {
        const record = JSON.parse(line);
        records.push({
          domain: record.domain,
          registrant_name: record.registrant_name,
          registrant_org: record.registrant_org,
          registrar: record.registrar,
          creation_date: record.creation_date,
          source: record.source,
          fetched_at: record.fetched_at
        });
      } catch (parseError) {
        log('[whoisWrapper] Failed to parse WHOIS record line:', line);
      }
    }
    
    // Calculate stats
    const rdapCalls = records.filter(r => r.source === 'rdap').length;
    const whoxyCalls = records.filter(r => r.source === 'whoxy').length;
    const estimatedCost = whoxyCalls * 0.002;
    const savedVsWhoisxml = domains.length * 0.015 - estimatedCost;
    
    const result = {
      records,
      stats: {
        rdap_calls: rdapCalls,
        whoxy_calls: whoxyCalls,
        estimated_cost: estimatedCost,
        saved_vs_whoisxml: savedVsWhoisxml
      }
    };
    
    // Cost tracking removed from logs - data still available in returned stats
    
    return result;
    
  } catch (error) {
    log('[whoisWrapper] Error resolving WHOIS data:', (error as Error).message);
    
    // Fallback to empty records
    return {
      records: domains.map(d => ({
        domain: d,
        source: 'rdap' as const,
        fetched_at: new Date().toISOString()
      })),
      stats: { rdap_calls: 0, whoxy_calls: 0, estimated_cost: 0, saved_vs_whoisxml: 0 }
    };
    
  } finally {
    // Cleanup temp file
    await unlink(tempFile).catch(() => {});
  }
}

/**
 * Legacy single domain resolver for backward compatibility
 */
export async function resolveWhoisSingle(domain: string): Promise<WhoisRecord | null> {
  const result = await resolveWhoisBatch([domain]);
  return result.records[0] || null;
}

/**
 * Run function for worker integration
 */
export async function runWhoisWrapper(job: { domain: string; scanId?: string }): Promise<number> {
  const { domain, scanId } = job;
  log(`[whoisWrapper] Starting WHOIS lookup for ${domain}`);
  
  try {
    const result = await resolveWhoisBatch([domain]);
    
    if (result.records.length > 0) {
      const record = result.records[0];
      
      // Store WHOIS data as artifact
      if (scanId) {
        const { insertArtifact } = await import('../core/artifactStore.js');
        await insertArtifact({
          type: 'whois_record',
          val_text: JSON.stringify(record),
          severity: 'INFO',
          meta: {
            scan_id: scanId,
            domain: record.domain,
            registrant_name: record.registrant_name,
            registrant_org: record.registrant_org,
            registrar: record.registrar,
            creation_date: record.creation_date,
            source: record.source,
            cost_saved: result.stats.saved_vs_whoisxml
          }
        });
      }
      
      console.log(`[whoisWrapper] COMPLETED at ${new Date().toISOString()}. Source: ${record.source}, Cost saved: $${result.stats.saved_vs_whoisxml.toFixed(3)}`);
      log(`[whoisWrapper] WHOIS lookup completed. Source: ${record.source}, Cost saved: $${result.stats.saved_vs_whoisxml.toFixed(3)}`);
      return 1; // One finding
    }
    
    return 0;
  } catch (error) {
    log(`[whoisWrapper] Error: ${(error as Error).message}`);
    return 0;
  }
}