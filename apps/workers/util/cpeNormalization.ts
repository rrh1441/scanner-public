/**
 * CPE/PURL Normalization Layer
 * 
 * Converts detected technologies into machine-readable CPE and PURL identifiers
 * for accurate vulnerability matching against NVD, OSV.dev, and other databases.
 */

import { logLegacy as rootLog } from '../core/logger.js';

const log = (...args: unknown[]) => rootLog('[cpeNormalization]', ...args);

export interface NormalizedComponent {
  name: string;
  version?: string;
  vendor?: string;
  cpe?: string;          // Common Platform Enumeration
  purl?: string;         // Package URL
  ecosystem?: string;    // npm, pypi, maven, etc.
  confidence: number;    // 0-100
  source: string;        // webtech, whatweb, headers, etc.
}

export interface CPEComponents {
  part: 'a' | 'h' | 'o';  // application, hardware, operating system
  vendor: string;
  product: string;
  version: string;
  update?: string;
  edition?: string;
  language?: string;
}

// Technology to CPE/PURL mapping database
const TECH_MAPPING: Record<string, {
  vendor?: string;
  cpe_template?: string;
  purl_template?: string;
  ecosystem?: string;
  aliases?: string[];
}> = {
  // Web Servers
  'apache': {
    vendor: 'apache',
    cpe_template: 'cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*',
  },
  'nginx': {
    vendor: 'nginx',
    cpe_template: 'cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*',
  },
  'iis': {
    vendor: 'microsoft',
    cpe_template: 'cpe:2.3:a:microsoft:internet_information_services:{version}:*:*:*:*:*:*:*',
    aliases: ['microsoft-iis', 'microsoft_iis']
  },

  // Programming Languages
  'php': {
    vendor: 'php',
    cpe_template: 'cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*',
  },
  'python': {
    vendor: 'python',
    cpe_template: 'cpe:2.3:a:python:python:{version}:*:*:*:*:*:*:*',
  },
  'nodejs': {
    vendor: 'nodejs',
    cpe_template: 'cpe:2.3:a:nodejs:node.js:{version}:*:*:*:*:*:*:*',
    ecosystem: 'npm',
    aliases: ['node.js', 'node-js', 'node_js']
  },
  'ruby': {
    vendor: 'ruby-lang',
    cpe_template: 'cpe:2.3:a:ruby-lang:ruby:{version}:*:*:*:*:*:*:*',
    ecosystem: 'gem'
  },

  // Web Frameworks
  'express': {
    vendor: 'expressjs',
    cpe_template: 'cpe:2.3:a:expressjs:express:{version}:*:*:*:*:nodejs:*:*',
    purl_template: 'pkg:npm/express@{version}',
    ecosystem: 'npm'
  },
  'django': {
    vendor: 'djangoproject',
    cpe_template: 'cpe:2.3:a:djangoproject:django:{version}:*:*:*:*:python:*:*',
    purl_template: 'pkg:pypi/django@{version}',
    ecosystem: 'pypi'
  },
  'rails': {
    vendor: 'rubyonrails',
    cpe_template: 'cpe:2.3:a:rubyonrails:ruby_on_rails:{version}:*:*:*:*:*:*:*',
    purl_template: 'pkg:gem/rails@{version}',
    ecosystem: 'gem',
    aliases: ['ruby-on-rails', 'rubyonrails']
  },
  'spring': {
    vendor: 'vmware',
    cpe_template: 'cpe:2.3:a:vmware:spring_framework:{version}:*:*:*:*:*:*:*',
    purl_template: 'pkg:maven/org.springframework/spring-core@{version}',
    ecosystem: 'maven',
    aliases: ['spring-framework', 'springframework']
  },
  'laravel': {
    vendor: 'laravel',
    cpe_template: 'cpe:2.3:a:laravel:laravel:{version}:*:*:*:*:*:*:*',
    purl_template: 'pkg:composer/laravel/framework@{version}',
    ecosystem: 'composer'
  },

  // CMS & Applications
  'wordpress': {
    vendor: 'wordpress',
    cpe_template: 'cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*',
  },
  'drupal': {
    vendor: 'drupal',
    cpe_template: 'cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*',
  },
  'joomla': {
    vendor: 'joomla',
    cpe_template: 'cpe:2.3:a:joomla:joomla\\!:{version}:*:*:*:*:*:*:*',
  },
  'magento': {
    vendor: 'magento',
    cpe_template: 'cpe:2.3:a:magento:magento:{version}:*:*:*:*:*:*:*',
  },
  'shopify': {
    vendor: 'shopify',
    cpe_template: 'cpe:2.3:a:shopify:shopify:{version}:*:*:*:*:*:*:*',
  },

  // Databases
  'mysql': {
    vendor: 'oracle',
    cpe_template: 'cpe:2.3:a:oracle:mysql:{version}:*:*:*:*:*:*:*',
  },
  'postgresql': {
    vendor: 'postgresql',
    cpe_template: 'cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*',
    aliases: ['postgres']
  },
  'mongodb': {
    vendor: 'mongodb',
    cpe_template: 'cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*',
  },
  'redis': {
    vendor: 'redis',
    cpe_template: 'cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*',
  },

  // JavaScript Libraries
  'jquery': {
    vendor: 'jquery',
    cpe_template: 'cpe:2.3:a:jquery:jquery:{version}:*:*:*:*:*:*:*',
    purl_template: 'pkg:npm/jquery@{version}',
    ecosystem: 'npm'
  },
  'react': {
    vendor: 'facebook',
    cpe_template: 'cpe:2.3:a:facebook:react:{version}:*:*:*:*:*:*:*',
    purl_template: 'pkg:npm/react@{version}',
    ecosystem: 'npm'
  },
  'angular': {
    vendor: 'google',
    cpe_template: 'cpe:2.3:a:google:angular:{version}:*:*:*:*:*:*:*',
    purl_template: 'pkg:npm/@angular/core@{version}',
    ecosystem: 'npm',
    aliases: ['angularjs']
  },
  'vue': {
    vendor: 'vuejs',
    cpe_template: 'cpe:2.3:a:vuejs:vue.js:{version}:*:*:*:*:*:*:*',
    purl_template: 'pkg:npm/vue@{version}',
    ecosystem: 'npm',
    aliases: ['vue.js', 'vuejs']
  },

  // CDN & Infrastructure
  'cloudflare': {
    vendor: 'cloudflare',
    cpe_template: 'cpe:2.3:a:cloudflare:cloudflare:{version}:*:*:*:*:*:*:*',
  },
  'aws': {
    vendor: 'amazon',
    cpe_template: 'cpe:2.3:a:amazon:web_services:{version}:*:*:*:*:*:*:*',
    aliases: ['amazon-web-services', 'amazon_web_services']
  },
  'gcp': {
    vendor: 'google',
    cpe_template: 'cpe:2.3:a:google:cloud_platform:{version}:*:*:*:*:*:*:*',
    aliases: ['google-cloud-platform', 'google_cloud_platform']
  }
};

/**
 * Normalize a detected technology into CPE and PURL identifiers
 */
export function normalizeTechnology(
  name: string, 
  version?: string, 
  confidence: number = 100,
  source: string = 'unknown'
): NormalizedComponent {
  const normalizedName = name.toLowerCase().trim();
  
  // Try exact match first
  let mapping = TECH_MAPPING[normalizedName];
  
  // Try alias matching if no exact match
  if (!mapping) {
    for (const [key, value] of Object.entries(TECH_MAPPING)) {
      if (value.aliases?.some(alias => alias.toLowerCase() === normalizedName)) {
        mapping = value;
        break;
      }
    }
  }
  
  // Try partial matching for common patterns
  if (!mapping) {
    for (const [key, value] of Object.entries(TECH_MAPPING)) {
      if (normalizedName.includes(key) || key.includes(normalizedName)) {
        mapping = value;
        confidence = Math.max(50, confidence - 20); // Reduce confidence for partial matches
        break;
      }
    }
  }
  
  const result: NormalizedComponent = {
    name: name,
    version: version,
    confidence,
    source
  };
  
  if (mapping) {
    result.vendor = mapping.vendor;
    result.ecosystem = mapping.ecosystem;
    
    // Generate CPE if template exists
    if (mapping.cpe_template && version) {
      result.cpe = mapping.cpe_template.replace('{version}', version);
    }
    
    // Generate PURL if template exists
    if (mapping.purl_template && version) {
      result.purl = mapping.purl_template.replace('{version}', version);
    }
  }
  
  // If no mapping found, create a basic structure
  if (!mapping) {
    result.vendor = inferVendor(name);
    result.ecosystem = inferEcosystem(name);
    
    // Create a generic CPE for unmapped technologies
    if (version && result.vendor) {
      result.cpe = `cpe:2.3:a:${result.vendor}:${normalizedName.replace(/[^a-z0-9]/g, '_')}:${version}:*:*:*:*:*:*:*`;
    }
  }
  
  log(`normalized tech="${name}" version="${version}" cpe="${result.cpe}" purl="${result.purl}" confidence=${result.confidence}`);
  
  return result;
}

/**
 * Parse a CPE string into components
 */
export function parseCPE(cpe: string): CPEComponents | null {
  // CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
  const parts = cpe.split(':');
  
  if (parts.length < 6 || parts[0] !== 'cpe' || parts[1] !== '2.3') {
    return null;
  }
  
  return {
    part: parts[2] as 'a' | 'h' | 'o',
    vendor: parts[3] === '*' ? '' : parts[3],
    product: parts[4] === '*' ? '' : parts[4],
    version: parts[5] === '*' ? '' : parts[5],
    update: parts[6] === '*' ? undefined : parts[6],
    edition: parts[7] === '*' ? undefined : parts[7],
    language: parts[8] === '*' ? undefined : parts[8]
  };
}

/**
 * Generate a CPE string from components
 */
export function generateCPE(components: CPEComponents): string {
  return `cpe:2.3:${components.part}:${components.vendor}:${components.product}:${components.version}:${components.update || '*'}:${components.edition || '*'}:${components.language || '*'}:*:*:*:*`;
}

/**
 * Parse a PURL string into components
 */
export function parsePURL(purl: string): { ecosystem: string; name: string; version?: string; namespace?: string } | null {
  // PURL format: pkg:type/namespace/name@version?qualifiers#subpath
  const purlRegex = /^pkg:([^\/]+)\/(?:([^\/]+)\/)?([^@\?#]+)(?:@([^?\#]+))?/;
  const match = purl.match(purlRegex);
  
  if (!match) {
    return null;
  }
  
  return {
    ecosystem: match[1],
    namespace: match[2],
    name: match[3],
    version: match[4]
  };
}

/**
 * Infer vendor from technology name
 */
function inferVendor(name: string): string {
  const lowerName = name.toLowerCase();
  
  // Common vendor patterns
  if (lowerName.includes('microsoft') || lowerName.includes('ms-')) return 'microsoft';
  if (lowerName.includes('google') || lowerName.includes('goog-')) return 'google';
  if (lowerName.includes('amazon') || lowerName.includes('aws')) return 'amazon';
  if (lowerName.includes('apache')) return 'apache';
  if (lowerName.includes('nginx')) return 'nginx';
  if (lowerName.includes('oracle')) return 'oracle';
  if (lowerName.includes('ibm')) return 'ibm';
  if (lowerName.includes('facebook') || lowerName.includes('meta')) return 'facebook';
  
  // If no known vendor pattern, use the first part of the name as vendor
  const parts = lowerName.split(/[-_\s]/);
  return parts[0] || lowerName;
}

/**
 * Infer ecosystem from technology name and category
 */
function inferEcosystem(name: string): string | undefined {
  const lowerName = name.toLowerCase();
  
  if (lowerName.includes('npm') || lowerName.includes('node')) return 'npm';
  if (lowerName.includes('pip') || lowerName.includes('python') || lowerName.includes('django')) return 'pypi';
  if (lowerName.includes('gem') || lowerName.includes('ruby') || lowerName.includes('rails')) return 'gem';
  if (lowerName.includes('maven') || lowerName.includes('gradle') || lowerName.includes('java')) return 'maven';
  if (lowerName.includes('composer') || lowerName.includes('php')) return 'composer';
  if (lowerName.includes('nuget') || lowerName.includes('.net') || lowerName.includes('csharp')) return 'nuget';
  if (lowerName.includes('cargo') || lowerName.includes('rust')) return 'cargo';
  if (lowerName.includes('go') || lowerName.includes('golang')) return 'golang';
  
  return undefined;
}

/**
 * Batch normalize multiple technologies
 */
export function batchNormalizeTechnologies(
  technologies: Array<{ name: string; version?: string; confidence?: number; source?: string }>
): NormalizedComponent[] {
  const startTime = Date.now();
  
  const normalized = technologies.map(tech => 
    normalizeTechnology(
      tech.name, 
      tech.version, 
      tech.confidence || 100, 
      tech.source || 'unknown'
    )
  );
  
  const duration = Date.now() - startTime;
  log(`batch_normalize completed: ${normalized.length} technologies in ${duration}ms`);
  
  return normalized;
}

/**
 * Deduplicate normalized components by CPE/PURL
 */
export function deduplicateComponents(components: NormalizedComponent[]): NormalizedComponent[] {
  const seen = new Set<string>();
  const deduplicated: NormalizedComponent[] = [];
  
  for (const component of components) {
    // Create a unique key based on CPE or PURL or name+version
    const key = component.cpe || component.purl || `${component.name}:${component.version || 'unknown'}`;
    
    if (!seen.has(key)) {
      seen.add(key);
      deduplicated.push(component);
    } else {
      // If duplicate found, keep the one with higher confidence
      const existingIndex = deduplicated.findIndex(c => 
        (c.cpe && c.cpe === component.cpe) || 
        (c.purl && c.purl === component.purl) || 
        (c.name === component.name && c.version === component.version)
      );
      
      if (existingIndex >= 0 && deduplicated[existingIndex].confidence < component.confidence) {
        deduplicated[existingIndex] = component;
      }
    }
  }
  
  log(`deduplicate: ${components.length} -> ${deduplicated.length} components`);
  return deduplicated;
}