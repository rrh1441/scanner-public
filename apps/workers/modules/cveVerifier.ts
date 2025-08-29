/* ============================================================================
 * MODULE: cveVerifier.ts (v1.1 – fixes & batching)
 * ============================================================================= */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { httpClient } from '../net/httpClient.js';
import { glob } from 'glob';
import semver from 'semver';
import { logLegacy as rootLog } from '../core/logger.js';

const exec = promisify(execFile);
const log = (...args: unknown[]) => rootLog('[cveVerifier]', ...args);

export interface CVECheckInput {
  host: string;          // https://74.208.42.246:443
  serverBanner: string;  // "Apache/2.4.62 (Ubuntu)"
  cves: string[];        // [ 'CVE-2020-11023', 'CVE-2021-40438' ]
}

export interface CVECheckResult {
  id: string;
  fixedIn?: string;      // e.g. "2.4.64-1ubuntu2.4"
  verified: boolean;     // exploit actually worked
  suppressed: boolean;   // ruled out by version mapping
  error?: string;        // execution / template error
}

// Cache for vendor fix data
const ubuntuFixCache = new Map<string, string | undefined>();
const nucleiTemplateCache = new Map<string, string | undefined>();

/* ------------------------------------------------------------------------ */
/* 1.  Distribution-level version mapping                                   */
/* ------------------------------------------------------------------------ */

async function getUbuntuFixedVersion(cve: string): Promise<string | undefined> {
  // Check cache first
  if (ubuntuFixCache.has(cve)) {
    return ubuntuFixCache.get(cve);
  }

  try {
    log(`Checking Ubuntu fix data for ${cve}`);
    const { data } = await httpClient.get(
      `https://ubuntu.com/security/${cve}.json`,
      { timeout: 8000 }
    );
    // API returns { packages:[{fixed_version:'2.4.52-1ubuntu4.4', ...}] }
    const httpd = data.packages?.find((p: any) => p.name === 'apache2');
    const fixedVersion = httpd?.fixed_version;
    
    // Cache the result
    ubuntuFixCache.set(cve, fixedVersion);
    
    if (fixedVersion) {
      log(`Ubuntu fix found for ${cve}: ${fixedVersion}`);
    } else {
      log(`No Ubuntu fix data found for ${cve}`);
    }
    
    return fixedVersion;
  } catch (error) {
    log(`Error fetching Ubuntu fix data for ${cve}: ${(error as Error).message}`);
    ubuntuFixCache.set(cve, undefined);
    return undefined;
  }
}

async function getRHELFixedVersion(cve: string): Promise<string | undefined> {
  try {
    // RHEL/CentOS security data - simplified approach
    const { data } = await httpClient.get(
      `https://access.redhat.com/hydra/rest/securitydata/cve/${cve}.json`,
      { timeout: 8000 }
    );
    
    // Look for httpd package fixes
    const httpdFix = data.affected_packages?.find((pkg: any) => 
      pkg.package_name?.includes('httpd')
    );
    
    return httpdFix?.fixed_in_version;
  } catch {
    return undefined;
  }
}

async function isVersionPatched(
  bannerVersion: string | undefined,
  fixed: string | undefined
): Promise<boolean> {
  if (!bannerVersion || !fixed) return false;
  
  // Very light semver comparison – works for x.y.z-ubuntuN
  const norm = (v: string) => {
    const cleaned = v.split('-')[0].split('~')[0]; // strip "-ubuntu..." and "~" 
    const parts = cleaned.split('.').map(Number);
    return { major: parts[0] || 0, minor: parts[1] || 0, patch: parts[2] || 0 };
  };
  
  const current = norm(bannerVersion);
  const fixedVer = norm(fixed);
  
  // Compare versions
  if (current.major > fixedVer.major) return true;
  if (current.major < fixedVer.major) return false;
  
  if (current.minor > fixedVer.minor) return true;
  if (current.minor < fixedVer.minor) return false;
  
  return current.patch >= fixedVer.patch;
}

/* ------------------------------------------------------------------------ */
/* 2.  Active exploit probe via Nuclei                                      */
/* ------------------------------------------------------------------------ */

async function nucleiSupports(cve: string): Promise<string | undefined> {
  // Check cache first
  if (nucleiTemplateCache.has(cve)) {
    return nucleiTemplateCache.get(cve);
  }

  try {
    // Look for nuclei templates in common locations
    const patterns = await glob(`**/${cve}.yaml`, {
      cwd: process.env.HOME || '.',
      ignore: ['node_modules/**', '.git/**']
    });
    
    // Prefer nuclei-templates directory structure
    const preferred = patterns.find((p: string) => 
      p.includes('nuclei-templates') && (
        p.includes('/cves/') || 
        p.includes('/http/') ||
        p.includes('/vulnerabilities/')
      )
    );
    
    const templatePath = preferred || patterns[0];
    
    // Cache the result
    nucleiTemplateCache.set(cve, templatePath);
    
    if (templatePath) {
      log(`Found Nuclei template for ${cve}: ${templatePath}`);
    } else {
      log(`No Nuclei template found for ${cve}`);
    }
    
    return templatePath;
  } catch (error) {
    log(`Error searching for Nuclei template ${cve}: ${(error as Error).message}`);
    nucleiTemplateCache.set(cve, undefined);
    return undefined;
  }
}

async function runNuclei(
  host: string,
  template: string
): Promise<boolean> {
  try {
    log(`Running Nuclei template ${template} against ${host}`);
    
    const { stdout } = await exec(
      'nuclei',
      ['-t', template, '-target', host, '-json', '-silent', '-rate-limit', '5'],
      { timeout: 15_000 }
    );
    
    const hasMatch = stdout.trim().length > 0;
    
    if (hasMatch) {
      log(`Nuclei confirmed vulnerability: ${template} matched ${host}`);
    } else {
      log(`Nuclei found no vulnerability: ${template} did not match ${host}`);
    }
    
    return hasMatch;
  } catch (error) {
    log(`Nuclei execution failed for ${template}: ${(error as Error).message}`);
    return false;
  }
}

/* ------------------------------------------------------------------------ */
/* 3.  Enhanced version parsing and service detection                       */
/* ------------------------------------------------------------------------ */

function extractServiceInfo(banner: string): { service: string; version: string } | null {
  // Apache patterns
  const apacheMatch = banner.match(/Apache\/(\d+\.\d+\.\d+)/i);
  if (apacheMatch) {
    return { service: 'apache', version: apacheMatch[1] };
  }
  
  // Nginx patterns
  const nginxMatch = banner.match(/nginx\/(\d+\.\d+\.\d+)/i);
  if (nginxMatch) {
    return { service: 'nginx', version: nginxMatch[1] };
  }
  
  // IIS patterns
  const iisMatch = banner.match(/IIS\/(\d+\.\d+)/i);
  if (iisMatch) {
    return { service: 'iis', version: iisMatch[1] };
  }
  
  return null;
}

/* ------------------------------------------------------------------------ */
/* 4.  Public API                                                           */
/* ------------------------------------------------------------------------ */

async function batchEPSS(ids: string[]): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  if (!ids.length) return out;
  try {
    const { data } = await httpClient.get(`https://api.first.org/data/v1/epss?cve=${ids.join(',')}`, { timeout: 10_000 });
    (data.data as any[]).forEach((d: any) => { out[d.cve] = Number(d.epss) || 0; });
  } catch { ids.forEach(id => (out[id] = 0)); }
  return out;
}

export async function verifyCVEs(opts: CVECheckInput): Promise<CVECheckResult[]> {
  const results: CVECheckResult[] = [];
  const srvInfo = extractServiceInfo(opts.serverBanner);
  const bannerVersion = srvInfo?.version;
  const epssScores = await batchEPSS(opts.cves);
  for (const id of opts.cves) {
    const res: CVECheckResult = { id, verified: false, suppressed: false };
    try {
      const [ubuntuFix, rhelFix] = await Promise.all([getUbuntuFixedVersion(id), getRHELFixedVersion(id)]);
      const fixed = ubuntuFix || rhelFix;
      res.fixedIn = fixed;
      if (fixed && bannerVersion && (await isVersionPatched(bannerVersion, fixed))) {
        res.suppressed = true;
        results.push(res);
        continue;
      }
      const template = await nucleiSupports(id);
      if (template) res.verified = await runNuclei(opts.host, template);
      res.suppressed ||= epssScores[id] < 0.005 && !template; // informational only
    } catch (e) { res.error = (e as Error).message; }
    results.push(res);
  }
  return results;
}

// CVE database with version ranges and publication dates
interface CVEInfo {
  id: string;
  description: string;
  affectedVersions: string; // semver range
  publishedYear: number;
}

const serviceCVEDatabase: Record<string, CVEInfo[]> = {
  apache: [
    {
      id: 'CVE-2021-40438',
      description: 'Apache HTTP Server 2.4.48 and earlier SSRF',
      affectedVersions: '>=2.4.7 <=2.4.48',
      publishedYear: 2021
    },
    {
      id: 'CVE-2021-41773',
      description: 'Apache HTTP Server 2.4.49 Path Traversal',
      affectedVersions: '=2.4.49',
      publishedYear: 2021
    },
    {
      id: 'CVE-2021-42013',
      description: 'Apache HTTP Server 2.4.50 Path Traversal',
      affectedVersions: '<=2.4.50',
      publishedYear: 2021
    },
    {
      id: 'CVE-2020-11993',
      description: 'Apache HTTP Server 2.4.43 and earlier',
      affectedVersions: '<=2.4.43',
      publishedYear: 2020
    },
    {
      id: 'CVE-2019-0190',
      description: 'Apache HTTP Server 2.4.17 to 2.4.38',
      affectedVersions: '>=2.4.17 <=2.4.38',
      publishedYear: 2019
    },
    {
      id: 'CVE-2020-11023',
      description: 'jQuery (if mod_proxy_html enabled)',
      affectedVersions: '*', // Version-independent
      publishedYear: 2020
    }
  ],
  nginx: [
    {
      id: 'CVE-2021-23017',
      description: 'Nginx resolver off-by-one',
      affectedVersions: '>=0.6.18 <1.20.1',
      publishedYear: 2021
    },
    {
      id: 'CVE-2019-20372',
      description: 'Nginx HTTP/2 implementation',
      affectedVersions: '>=1.9.5 <=1.17.7',
      publishedYear: 2019
    },
    {
      id: 'CVE-2017-7529',
      description: 'Nginx range filter integer overflow',
      affectedVersions: '>=0.5.6 <=1.13.2',
      publishedYear: 2017
    }
  ],
  iis: [
    {
      id: 'CVE-2021-31207',
      description: 'Microsoft IIS Server Elevation of Privilege',
      affectedVersions: '*', // Version-independent for IIS
      publishedYear: 2021
    },
    {
      id: 'CVE-2020-0618',
      description: 'Microsoft IIS Server Remote Code Execution',
      affectedVersions: '*',
      publishedYear: 2020
    },
    {
      id: 'CVE-2017-7269',
      description: 'Microsoft IIS 6.0 WebDAV ScStoragePathFromUrl',
      affectedVersions: '=6.0',
      publishedYear: 2017
    }
  ]
};

// Helper function to estimate software release year
function estimateSoftwareReleaseYear(service: string, version: string): number | null {
  const versionMatch = version.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!versionMatch) return null;
  
  const [, major, minor, patch] = versionMatch.map(Number);
  
  // Service-specific release year estimates
  if (service === 'apache' && major === 2 && minor === 4) {
    if (patch >= 60) return 2024;
    if (patch >= 50) return 2021;
    if (patch >= 40) return 2019;
    if (patch >= 30) return 2017;
    if (patch >= 20) return 2015;
    if (patch >= 10) return 2013;
    return 2012;
  }
  
  if (service === 'nginx') {
    if (major >= 2) return 2023;
    if (major === 1 && minor >= 20) return 2021;
    if (major === 1 && minor >= 15) return 2019;
    if (major === 1 && minor >= 10) return 2016;
    return 2012;
  }
  
  return null; // Can't estimate
}

/**
 * Enhanced function to get CVEs for services with proper version and timeline filtering
 */
export function getCommonCVEsForService(service: string, version: string): string[] {
  const serviceLower = service.toLowerCase();
  const cveList = serviceCVEDatabase[serviceLower];
  
  if (!cveList) {
    log(`No CVE database found for service: ${service}`);
    return [];
  }

  // Clean and normalize version
  const cleanVersion = semver.coerce(version);
  if (!cleanVersion) {
    log(`Could not parse version: ${version}, returning all CVEs for ${service}`);
    return cveList.map(cve => cve.id);
  }

  // Estimate release year of this software version
  const releaseYear = estimateSoftwareReleaseYear(serviceLower, version);
  
  const applicableCVEs: string[] = [];
  
  for (const cve of cveList) {
    // Timeline validation: CVE can't affect software released after CVE publication
    if (releaseYear && releaseYear > cve.publishedYear + 1) { // +1 year buffer
      log(`CVE ${cve.id} excluded: software version ${version} (${releaseYear}) released after CVE (${cve.publishedYear})`);
      continue;
    }
    
    // Version range validation
    try {
      if (cve.affectedVersions === '*') {
        // Version-independent vulnerability
        applicableCVEs.push(cve.id);
        continue;
      }
      
      if (semver.satisfies(cleanVersion, cve.affectedVersions)) {
        applicableCVEs.push(cve.id);
        log(`CVE ${cve.id} applicable to ${service} ${version}`);
      } else {
        log(`CVE ${cve.id} not applicable: version ${version} outside range ${cve.affectedVersions}`);
      }
    } catch (error) {
      log(`Error checking version range for ${cve.id}: ${(error as Error).message}`);
      // Include on error for safety, but log the issue
      applicableCVEs.push(cve.id);
    }
  }
  
  log(`Service ${service} v${version}: ${applicableCVEs.length}/${cveList.length} CVEs applicable`);
  return applicableCVEs;
}

/**
 * Extract CVE IDs from Nuclei JSON output  
 */
export function extractCVEsFromNucleiOutput(nucleiJson: string): string[] {
  const cves = new Set<string>();
  
  try {
    const lines = nucleiJson.split('\n').filter(line => line.trim());
    
    for (const line of lines) {
      const result = JSON.parse(line);
      
      // Extract CVE from template-id or info.reference
      const templateId = result['template-id'] || result.templateID;
      const references = result.info?.reference || [];
      
      // Check template ID for CVE pattern
      const cveMatch = templateId?.match(/CVE-\d{4}-\d{4,}/);
      if (cveMatch) {
        cves.add(cveMatch[0]);
      }
      
      // Check references array
      if (Array.isArray(references)) {
        references.forEach((ref: string) => {
          const refCveMatch = ref.match(/CVE-\d{4}-\d{4,}/);
          if (refCveMatch) {
            cves.add(refCveMatch[0]);
          }
        });
      }
    }
  } catch (error) {
    log(`Error parsing Nuclei output for CVE extraction: ${(error as Error).message}`);
  }
  
  return Array.from(cves);
}

export default { verifyCVEs, getCommonCVEsForService, extractCVEsFromNucleiOutput };