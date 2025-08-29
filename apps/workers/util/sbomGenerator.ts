/**
 * SBOM (Software Bill of Materials) Generator
 * 
 * Creates CycloneDX 1.5 SBOM documents for detected technologies and their versions,
 * including vulnerability data from NVD and OSV.dev for comprehensive supply chain tracking.
 */

import { logLegacy as rootLog } from '../core/logger.js';
import { type NormalizedComponent } from './cpeNormalization.js';

const log = (...args: unknown[]) => rootLog('[sbomGenerator]', ...args);

interface VulnerabilityMatch {
  id: string;
  cveId: string;
  source: string;
  severity: string;
  score?: number;
  summary?: string;
  description?: string;
  publishedDate?: string;
  matchConfidence?: string;
  matchReason?: string;
  cvssScore?: number;
  cisaKev?: boolean;
  epssScore?: number;
}

interface ComponentVulnerabilityReport {
  component: NormalizedComponent;
  vulnerabilities: VulnerabilityMatch[];
}

export interface CycloneDXComponent {
  'bom-ref': string;
  type: 'library' | 'framework' | 'application' | 'container' | 'operating-system' | 'device' | 'firmware' | 'file';
  supplier?: {
    name: string;
    url?: string[];
  };
  author?: string;
  publisher?: string;
  group?: string;
  name: string;
  version?: string;
  description?: string;
  scope?: 'required' | 'optional' | 'excluded';
  hashes?: Array<{
    alg: string;
    content: string;
  }>;
  licenses?: Array<{
    license: {
      id?: string;
      name?: string;
      text?: {
        contentType: string;
        content: string;
      };
      url?: string;
    };
  }>;
  copyright?: string;
  cpe?: string;
  purl?: string;
  swid?: {
    tagId: string;
    name: string;
  };
  pedigree?: {
    ancestors?: CycloneDXComponent[];
    descendants?: CycloneDXComponent[];
    variants?: CycloneDXComponent[];
    commits?: Array<{
      uid: string;
      url?: string;
      author?: {
        timestamp: string;
        name?: string;
        email?: string;
      };
      committer?: {
        timestamp: string;
        name?: string;
        email?: string;
      };
      message?: string;
    }>;
    patches?: Array<{
      type: 'unofficial' | 'monkey' | 'backport' | 'cherry-pick';
      diff?: {
        text?: {
          contentType: string;
          content: string;
        };
        url?: string;
      };
      resolves?: Array<{
        type: 'defect' | 'enhancement' | 'security';
        id?: string;
        name?: string;
        description?: string;
        source?: {
          name?: string;
          url?: string;
        };
        references?: string[];
      }>;
    }>;
  };
  externalReferences?: Array<{
    type: 'vcs' | 'issue-tracker' | 'website' | 'advisories' | 'bom' | 'mailing-list' | 'social' | 'chat' | 'documentation' | 'support' | 'source-distribution' | 'distribution' | 'distribution-intake' | 'license' | 'build-meta' | 'build-system' | 'release-notes' | 'security-contact' | 'model-card' | 'log' | 'configuration' | 'evidence' | 'formulation' | 'attestation' | 'threat-model' | 'adversary-model' | 'risk-assessment' | 'vulnerability-assertion' | 'exploitability-statement' | 'pentest-report' | 'static-analysis-report' | 'dynamic-analysis-report' | 'runtime-analysis-report' | 'component-analysis-report' | 'maturity-report' | 'certification-report' | 'codified-infrastructure' | 'quality-metrics' | 'poam' | 'other';
    url: string;
    comment?: string;
    hashes?: Array<{
      alg: string;
      content: string;
    }>;
  }>;
  properties?: Array<{
    name: string;
    value: string;
  }>;
}

export interface CycloneDXVulnerability {
  'bom-ref'?: string;
  id?: string;
  source?: {
    name: string;
    url?: string;
  };
  references?: Array<{
    id: string;
    source?: {
      name: string;
      url?: string;
    };
  }>;
  ratings?: Array<{
    source?: {
      name: string;
      url?: string;
    };
    score?: number;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none' | 'unknown';
    method?: 'CVSSv2' | 'CVSSv3' | 'CVSSv31' | 'CVSSv4' | 'OWASP' | 'SSVC' | 'other';
    vector?: string;
    justification?: string;
  }>;
  cwes?: number[];
  description?: string;
  detail?: string;
  recommendation?: string;
  advisories?: Array<{
    title?: string;
    url: string;
  }>;
  created?: string;
  published?: string;
  updated?: string;
  credits?: {
    organizations?: Array<{
      name: string;
      contact?: string[];
    }>;
    individuals?: Array<{
      name: string;
      contact?: string[];
    }>;
  };
  tools?: Array<{
    vendor?: string;
    name: string;
    version?: string;
    hashes?: Array<{
      alg: string;
      content: string;
    }>;
  }>;
  analysis?: {
    state?: 'resolved' | 'resolved_with_pedigree' | 'exploitable' | 'in_triage' | 'false_positive' | 'not_affected';
    justification?: 'code_not_present' | 'code_not_reachable' | 'requires_configuration' | 'requires_dependency' | 'requires_environment' | 'protected_by_compiler' | 'protected_at_runtime' | 'protected_at_perimeter' | 'protected_by_mitigating_control';
    response?: ('can_not_fix' | 'will_not_fix' | 'update' | 'rollback' | 'workaround_available')[];
    detail?: string;
  };
  affects?: Array<{
    ref: string;
    versions?: Array<{
      version?: string;
      range?: string;
      status?: 'affected' | 'unaffected' | 'unknown';
    }>;
  }>;
  properties?: Array<{
    name: string;
    value: string;
  }>;
}

export interface CycloneDXSBOM {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{
      vendor?: string;
      name: string;
      version?: string;
      hashes?: Array<{
        alg: string;
        content: string;
      }>;
      externalReferences?: Array<{
        type: string;
        url: string;
      }>;
    }>;
    authors?: Array<{
      name: string;
      email?: string;
      phone?: string;
    }>;
    component?: {
      'bom-ref': string;
      type: 'application' | 'framework' | 'library' | 'container' | 'operating-system' | 'device' | 'firmware' | 'file';
      supplier?: {
        name: string;
        url?: string[];
      };
      author?: string;
      publisher?: string;
      group?: string;
      name: string;
      version?: string;
      description?: string;
      scope?: 'required' | 'optional' | 'excluded';
      hashes?: Array<{
        alg: string;
        content: string;
      }>;
      licenses?: Array<{
        license: {
          id?: string;
          name?: string;
          text?: {
            contentType: string;
            content: string;
          };
          url?: string;
        };
      }>;
      copyright?: string;
      cpe?: string;
      purl?: string;
      externalReferences?: Array<{
        type: string;
        url: string;
        comment?: string;
      }>;
      properties?: Array<{
        name: string;
        value: string;
      }>;
    };
    manufacture?: {
      name: string;
      url?: string[];
      contact?: Array<{
        name?: string;
        email?: string;
        phone?: string;
      }>;
    };
    supplier?: {
      name: string;
      url?: string[];
      contact?: Array<{
        name?: string;
        email?: string;
        phone?: string;
      }>;
    };
    licenses?: Array<{
      license: {
        id?: string;
        name?: string;
      };
    }>;
    properties?: Array<{
      name: string;
      value: string;
    }>;
  };
  components?: CycloneDXComponent[];
  services?: Array<{
    'bom-ref': string;
    provider?: {
      name: string;
      url?: string[];
    };
    group?: string;
    name: string;
    version?: string;
    description?: string;
    endpoints?: string[];
    authenticated?: boolean;
    'x-trust-boundary'?: boolean;
    data?: Array<{
      flow: 'inbound' | 'outbound' | 'bi-directional' | 'unknown';
      classification: string;
    }>;
    licenses?: Array<{
      license: {
        id?: string;
        name?: string;
      };
    }>;
    externalReferences?: Array<{
      type: string;
      url: string;
      comment?: string;
    }>;
    properties?: Array<{
      name: string;
      value: string;
    }>;
  }>;
  externalReferences?: Array<{
    type: string;
    url: string;
    comment?: string;
    hashes?: Array<{
      alg: string;
      content: string;
    }>;
  }>;
  dependencies?: Array<{
    ref: string;
    dependsOn?: string[];
  }>;
  compositions?: Array<{
    aggregate: 'complete' | 'incomplete' | 'incomplete_first_party_only' | 'incomplete_first_party_proprietary_only' | 'incomplete_first_party_opensource_only' | 'incomplete_third_party_only' | 'incomplete_third_party_proprietary_only' | 'incomplete_third_party_opensource_only' | 'unknown' | 'not_specified';
    assemblies?: string[];
    dependencies?: string[];
  }>;
  vulnerabilities?: CycloneDXVulnerability[];
  annotations?: Array<{
    'bom-ref'?: string;
    subjects: string[];
    annotator: {
      organization?: {
        name: string;
        url?: string[];
      };
      individual?: {
        name: string;
        email?: string;
      };
      component?: {
        'bom-ref': string;
      };
      service?: {
        'bom-ref': string;
      };
    };
    timestamp: string;
    text: string;
  }>;
  formulation?: Array<{
    'bom-ref'?: string;
    components?: string[];
    services?: string[];
    workflows?: Array<{
      'bom-ref'?: string;
      uid?: string;
      name?: string;
      description?: string;
      resourceReferences?: Array<{
        ref: string;
      }>;
      tasks?: Array<{
        'bom-ref'?: string;
        uid?: string;
        name?: string;
        description?: string;
        resourceReferences?: Array<{
          ref: string;
        }>;
        taskTypes?: string[];
        trigger?: {
          'bom-ref'?: string;
          uid?: string;
          name?: string;
          description?: string;
          resourceReferences?: Array<{
            ref: string;
          }>;
          conditions?: Array<{
            description?: string;
            expression: string;
          }>;
          timeActivated?: string;
          inputs?: Array<{
            resource?: {
              'bom-ref': string;
            };
            parameters?: Array<{
              name: string;
              value: string;
            }>;
            environmentVars?: Array<{
              name: string;
              value: string;
            }>;
            data?: any;
          }>;
          outputs?: Array<{
            type?: 'artifact' | 'attestation' | 'log' | 'evidence' | 'metrics' | 'other';
            source?: {
              'bom-ref': string;
            };
            target?: {
              'bom-ref': string;
            };
            resource?: {
              'bom-ref': string;
            };
            data?: any;
          }>;
        };
        steps?: Array<{
          name?: string;
          description?: string;
          commands?: Array<{
            executed?: string;
            properties?: Array<{
              name: string;
              value: string;
            }>;
          }>;
          properties?: Array<{
            name: string;
            value: string;
          }>;
        }>;
        properties?: Array<{
          name: string;
          value: string;
        }>;
      }>;
      taskDependencies?: Array<{
        ref: string;
        dependsOn?: string[];
      }>;
      properties?: Array<{
        name: string;
        value: string;
      }>;
    }>;
    properties?: Array<{
      name: string;
      value: string;
    }>;
  }>;
  properties?: Array<{
    name: string;
    value: string;
  }>;
}

/**
 * Generate a CycloneDX 1.5 SBOM from component vulnerability reports
 */
export function generateSBOM(
  reports: ComponentVulnerabilityReport[],
  metadata: {
    targetName: string;
    targetVersion?: string;
    targetDescription?: string;
    scanId: string;
    domain: string;
  }
): CycloneDXSBOM {
  
  const timestamp = new Date().toISOString();
  const serialNumber = `urn:uuid:${generateUUID()}`;
  
  log(`Generating SBOM for ${metadata.targetName} with ${reports.length} components`);
  
  // Generate components
  const components: CycloneDXComponent[] = reports.map(report => 
    convertComponentToSBOM(report.component)
  );
  
  // Generate vulnerabilities
  const vulnerabilities: CycloneDXVulnerability[] = [];
  const componentRefs = new Set<string>();
  
  for (const report of reports) {
    const componentRef = generateComponentRef(report.component);
    componentRefs.add(componentRef);
    
    for (const vuln of report.vulnerabilities) {
      vulnerabilities.push(convertVulnerabilityToSBOM(vuln, componentRef));
    }
  }
  
  // Generate dependencies (basic structure for now)
  const dependencies = Array.from(componentRefs).map(ref => ({
    ref,
    dependsOn: [] // Would be populated with actual dependency analysis
  }));
  
  const sbom: CycloneDXSBOM = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp,
      tools: [{
        vendor: 'DealBrief',
        name: 'DealBrief-Scanner',
        version: '1.0.0',
        externalReferences: [{
          type: 'website',
          url: 'https://dealbrief.com'
        }]
      }],
      component: {
        'bom-ref': `target-${metadata.scanId}`,
        type: 'application',
        name: metadata.targetName,
        version: metadata.targetVersion,
        description: metadata.targetDescription || `Security scan target: ${metadata.domain}`,
        properties: [
          { name: 'dealbrief:scan-id', value: metadata.scanId },
          { name: 'dealbrief:domain', value: metadata.domain },
          { name: 'dealbrief:scan-timestamp', value: timestamp }
        ]
      },
      properties: [
        { name: 'dealbrief:scan-type', value: 'technology-stack' },
        { name: 'dealbrief:component-count', value: components.length.toString() },
        { name: 'dealbrief:vulnerability-count', value: vulnerabilities.length.toString() }
      ]
    },
    components,
    dependencies,
    vulnerabilities,
    compositions: [{
      aggregate: 'incomplete',
      assemblies: Array.from(componentRefs)
    }],
    properties: [
      { name: 'dealbrief:generated-by', value: 'DealBrief-Scanner' },
      { name: 'dealbrief:scan-duration', value: 'N/A' },
      { name: 'dealbrief:confidence-level', value: 'medium' }
    ]
  };
  
  log(`SBOM generated: ${components.length} components, ${vulnerabilities.length} vulnerabilities`);
  
  return sbom;
}

/**
 * Convert a normalized component to CycloneDX format
 */
function convertComponentToSBOM(component: NormalizedComponent): CycloneDXComponent {
  const bomRef = generateComponentRef(component);
  
  // Determine component type based on ecosystem
  let type: CycloneDXComponent['type'] = 'library';
  if (component.ecosystem) {
    const frameworkEcosystems = ['express', 'django', 'rails', 'spring', 'laravel'];
    if (frameworkEcosystems.some(fw => component.name.toLowerCase().includes(fw))) {
      type = 'framework';
    }
    
    if (component.name.toLowerCase().includes('app') || 
        component.name.toLowerCase().includes('server') ||
        component.name.toLowerCase().includes('service')) {
      type = 'application';
    }
  }
  
  const cyclonComponent: CycloneDXComponent = {
    'bom-ref': bomRef,
    type,
    name: component.name,
    version: component.version,
    scope: 'required',
    properties: [
      { name: 'dealbrief:detection-source', value: component.source },
      { name: 'dealbrief:confidence', value: component.confidence.toString() }
    ]
  };
  
  // Add vendor information
  if (component.vendor) {
    cyclonComponent.supplier = {
      name: component.vendor
    };
  }
  
  // Add CPE if available
  if (component.cpe) {
    cyclonComponent.cpe = component.cpe;
  }
  
  // Add PURL if available
  if (component.purl) {
    cyclonComponent.purl = component.purl;
  }
  
  // Add ecosystem-specific properties
  if (component.ecosystem) {
    cyclonComponent.properties!.push({
      name: 'dealbrief:ecosystem',
      value: component.ecosystem
    });
  }
  
  return cyclonComponent;
}

/**
 * Convert a vulnerability match to CycloneDX format
 */
function convertVulnerabilityToSBOM(
  vulnerability: VulnerabilityMatch,
  componentRef: string
): CycloneDXVulnerability {
  
  // Map severity to CycloneDX format
  const severityMap: Record<string, 'critical' | 'high' | 'medium' | 'low'> = {
    'CRITICAL': 'critical',
    'HIGH': 'high',
    'MEDIUM': 'medium',
    'LOW': 'low'
  };
  
  const cyclonVuln: CycloneDXVulnerability = {
    'bom-ref': `vuln-${vulnerability.cveId}`,
    id: vulnerability.cveId,
    source: {
      name: 'NVD',
      url: 'https://nvd.nist.gov/'
    },
    description: vulnerability.description,
    published: vulnerability.publishedDate,
    affects: [{
      ref: componentRef,
      versions: [{
        status: 'affected'
      }]
    }],
    properties: [
      ...(vulnerability.matchConfidence ? [{ name: 'dealbrief:match-confidence', value: vulnerability.matchConfidence.toString() }] : []),
      ...(vulnerability.matchReason ? [{ name: 'dealbrief:match-reason', value: vulnerability.matchReason }] : [])
    ]
  };
  
  // Add CVSS rating if available
  if (vulnerability.cvssScore) {
    cyclonVuln.ratings = [{
      source: {
        name: 'NVD'
      },
      score: vulnerability.cvssScore,
      severity: severityMap[vulnerability.severity],
      method: 'CVSSv3'
    }];
  }
  
  // Add CISA KEV indicator
  if (vulnerability.cisaKev) {
    cyclonVuln.properties!.push({
      name: 'dealbrief:cisa-kev',
      value: 'true'
    });
  }
  
  // Add EPSS score
  if (vulnerability.epssScore) {
    cyclonVuln.properties!.push({
      name: 'dealbrief:epss-score',
      value: vulnerability.epssScore.toString()
    });
  }
  
  return cyclonVuln;
}

/**
 * Generate a unique component reference
 */
function generateComponentRef(component: NormalizedComponent): string {
  const name = component.name.toLowerCase().replace(/[^a-z0-9]/g, '-');
  const version = component.version ? `-${component.version.replace(/[^a-z0-9.]/g, '-')}` : '';
  return `component-${name}${version}`;
}

/**
 * Generate a UUID v4
 */
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

/**
 * Export SBOM as JSON string
 */
export function exportSBOMAsJSON(sbom: CycloneDXSBOM): string {
  return JSON.stringify(sbom, null, 2);
}

/**
 * Validate SBOM structure
 */
export function validateSBOM(sbom: CycloneDXSBOM): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Basic structure validation
  if (sbom.bomFormat !== 'CycloneDX') {
    errors.push('Invalid bomFormat - must be CycloneDX');
  }
  
  if (sbom.specVersion !== '1.5') {
    errors.push('Invalid specVersion - must be 1.5');
  }
  
  if (!sbom.serialNumber || !sbom.serialNumber.startsWith('urn:uuid:')) {
    errors.push('Invalid or missing serialNumber - must be a valid URN UUID');
  }
  
  if (!sbom.metadata || !sbom.metadata.timestamp) {
    errors.push('Missing required metadata.timestamp');
  }
  
  if (!sbom.metadata?.tools || sbom.metadata.tools.length === 0) {
    errors.push('Missing required metadata.tools');
  }
  
  // Component validation
  if (sbom.components) {
    for (let i = 0; i < sbom.components.length; i++) {
      const component = sbom.components[i];
      if (!component['bom-ref']) {
        errors.push(`Component ${i}: missing bom-ref`);
      }
      if (!component.name) {
        errors.push(`Component ${i}: missing name`);
      }
      if (!component.type) {
        errors.push(`Component ${i}: missing type`);
      }
    }
  }
  
  // Vulnerability validation
  if (sbom.vulnerabilities) {
    for (let i = 0; i < sbom.vulnerabilities.length; i++) {
      const vuln = sbom.vulnerabilities[i];
      if (!vuln.id) {
        errors.push(`Vulnerability ${i}: missing id`);
      }
      if (!vuln.affects || vuln.affects.length === 0) {
        errors.push(`Vulnerability ${i}: missing affects`);
      }
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Get SBOM statistics
 */
export function getSBOMStats(sbom: CycloneDXSBOM): {
  componentCount: number;
  vulnerabilityCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  ecosystems: string[];
} {
  
  const componentCount = sbom.components?.length || 0;
  const vulnerabilityCount = sbom.vulnerabilities?.length || 0;
  
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  
  if (sbom.vulnerabilities) {
    for (const vuln of sbom.vulnerabilities) {
      const severity = vuln.ratings && vuln.ratings.length > 0 ? vuln.ratings[0].severity : undefined;
      switch (severity) {
        case 'critical': criticalCount++; break;
        case 'high': highCount++; break;
        case 'medium': mediumCount++; break;
        case 'low': lowCount++; break;
      }
    }
  }
  
  // Extract unique ecosystems from component properties
  const ecosystems = new Set<string>();
  if (sbom.components) {
    for (const component of sbom.components) {
      const ecosystemProp = component.properties?.find(p => p.name === 'dealbrief:ecosystem');
      if (ecosystemProp) {
        ecosystems.add(ecosystemProp.value);
      }
    }
  }
  
  return {
    componentCount,
    vulnerabilityCount,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    ecosystems: Array.from(ecosystems)
  };
}