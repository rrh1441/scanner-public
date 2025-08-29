/**
 * Unified Security Scanner Wrapper System
 * 
 * Provides standardized execution interface for all security scanning tools:
 * - Nuclei v3.4.5
 * - OpenVAS/Greenbone CE  
 * - OWASP ZAP
 * - scan4all
 * - Trivy
 * - ScoutSuite/Prowler
 */

import { exec, execFile } from 'child_process';
import { promisify } from 'util';
import { writeFile, unlink, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { randomBytes } from 'crypto';

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

// Configuration
const SCAN_TIMEOUT_MS = 600000; // 10 minutes default timeout
const MAX_BUFFER_SIZE = 100 * 1024 * 1024; // 100MB
const TEMP_DIR = '/tmp/security-scans';

interface ScannerConfig {
  name: string;
  executable: string;
  version: string;
  timeout: number;
  maxConcurrent: number;
  outputFormats: string[];
  requiresEnvVars?: string[];
}

interface ScanRequest {
  scanner: string;
  target: string;
  scanType: string;
  options?: Record<string, any>;
  timeout?: number;
  scanId?: string;
}

interface ScanResult {
  scanner: string;
  target: string;
  success: boolean;
  findings: any[];
  rawOutput: string;
  metadata: {
    startTime: Date;
    endTime: Date;
    duration: number;
    command: string;
    exitCode: number;
  };
  error?: string;
}

// Scanner configurations
const SCANNER_CONFIGS: Record<string, ScannerConfig> = {
  nuclei: {
    name: 'Nuclei',
    executable: 'nuclei',
    version: 'v3.4.5',
    timeout: 600000,
    maxConcurrent: 4,
    outputFormats: ['json', 'yaml'],
    requiresEnvVars: []
  },
  openvas: {
    name: 'OpenVAS/Greenbone',
    executable: 'gvm-cli',
    version: 'latest',
    timeout: 1800000, // 30 minutes
    maxConcurrent: 2,
    outputFormats: ['xml', 'json'],
    requiresEnvVars: ['OPENVAS_HOST', 'OPENVAS_USER', 'OPENVAS_PASSWORD']
  },
  zap: {
    name: 'OWASP ZAP',
    executable: 'zap-baseline.py',
    version: 'latest',
    timeout: 900000, // 15 minutes
    maxConcurrent: 3,
    outputFormats: ['xml', 'json', 'html'],
    requiresEnvVars: []
  },
  scan4all: {
    name: 'scan4all',
    executable: 'scan4all',
    version: 'latest',
    timeout: 1200000, // 20 minutes
    maxConcurrent: 2,
    outputFormats: ['json'],
    requiresEnvVars: []
  },
  trivy: {
    name: 'Trivy',
    executable: 'trivy',
    version: 'latest',
    timeout: 300000, // 5 minutes
    maxConcurrent: 6,
    outputFormats: ['json', 'table'],
    requiresEnvVars: []
  },
  scoutsuite: {
    name: 'ScoutSuite',
    executable: 'scout',
    version: 'latest',
    timeout: 600000, // 10 minutes
    maxConcurrent: 1,
    outputFormats: ['json'],
    requiresEnvVars: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
  }
};

export class SecurityScannerWrapper {
  private activeScanCount = 0;
  private scanHistory: Map<string, ScanResult> = new Map();

  constructor() {
    this.ensureTempDirectory();
  }

  private async ensureTempDirectory(): Promise<void> {
    if (!existsSync(TEMP_DIR)) {
      await mkdir(TEMP_DIR, { recursive: true });
    }
  }

  /**
   * Execute a security scan using the unified interface
   */
  async executeScan(request: ScanRequest): Promise<ScanResult> {
    const config = SCANNER_CONFIGS[request.scanner];
    if (!config) {
      throw new Error(`Unknown scanner: ${request.scanner}`);
    }

    // Validate environment variables
    if (config.requiresEnvVars) {
      for (const envVar of config.requiresEnvVars) {
        if (!process.env[envVar]) {
          throw new Error(`Required environment variable ${envVar} not set for ${config.name}`);
        }
      }
    }

    // Check concurrent scan limits
    if (this.activeScanCount >= config.maxConcurrent) {
      throw new Error(`Maximum concurrent scans (${config.maxConcurrent}) reached for ${config.name}`);
    }

    const startTime = new Date();
    const sessionId = randomBytes(8).toString('hex');
    const outputFile = path.join(TEMP_DIR, `${request.scanner}_${sessionId}.json`);

    try {
      this.activeScanCount++;
      
      const command = await this.buildCommand(request, config, outputFile);
      const timeout = request.timeout || config.timeout;

      console.log(`[SecurityWrapper] Executing ${config.name}: ${command}`);

      const { stdout, stderr } = await execAsync(command, {
        timeout,
        maxBuffer: MAX_BUFFER_SIZE,
        env: { ...process.env, NO_COLOR: '1' }
      });

      const endTime = new Date();
      const findings = await this.parseOutput(request.scanner, outputFile, stdout);

      const result: ScanResult = {
        scanner: request.scanner,
        target: request.target,
        success: true,
        findings,
        rawOutput: stdout,
        metadata: {
          startTime,
          endTime,
          duration: endTime.getTime() - startTime.getTime(),
          command,
          exitCode: 0
        }
      };

      // Store in history for debugging
      this.scanHistory.set(sessionId, result);
      
      return result;

    } catch (error) {
      const endTime = new Date();
      const result: ScanResult = {
        scanner: request.scanner,
        target: request.target,
        success: false,
        findings: [],
        rawOutput: '',
        metadata: {
          startTime,
          endTime,
          duration: endTime.getTime() - startTime.getTime(),
          command: 'failed',
          exitCode: (error as any).code || -1
        },
        error: (error as Error).message
      };

      this.scanHistory.set(sessionId, result);
      return result;

    } finally {
      this.activeScanCount--;
      
      // Cleanup temporary files
      try {
        if (existsSync(outputFile)) {
          await unlink(outputFile);
        }
      } catch (cleanupError) {
        console.warn(`[SecurityWrapper] Failed to cleanup ${outputFile}:`, cleanupError);
      }
    }
  }

  /**
   * Build scanner-specific command
   */
  private async buildCommand(request: ScanRequest, config: ScannerConfig, outputFile: string): Promise<string> {
    const { scanner, target, scanType, options = {} } = request;

    switch (scanner) {
      case 'nuclei':
        return this.buildNucleiCommand(target, scanType, options, outputFile);
      
      case 'openvas':
        return this.buildOpenVASCommand(target, scanType, options, outputFile);
      
      case 'zap':
        return this.buildZAPCommand(target, scanType, options, outputFile);
      
      case 'scan4all':
        return this.buildScan4allCommand(target, scanType, options, outputFile);
      
      case 'trivy':
        return this.buildTrivyCommand(target, scanType, options, outputFile);
      
      case 'scoutsuite':
        return this.buildScoutSuiteCommand(target, scanType, options, outputFile);
      
      default:
        throw new Error(`Command builder not implemented for ${scanner}`);
    }
  }

  /**
   * Nuclei command builder (updated for v3.4.5)
   */
  private buildNucleiCommand(target: string, scanType: string, options: any, outputFile: string): string {
    const args = [
      'nuclei',
      '-u', target,
      '-json',
      '-silent',
      '-timeout', (options.timeout || 20).toString(),
      '-retries', (options.retries || 2).toString(),
      '-td', '/opt/nuclei-templates'
    ];

    // Add scan type specific flags
    switch (scanType) {
      case 'vulnerability':
        args.push('-tags', options.tags || 'cve,misconfiguration,exposure');
        break;
      case 'technology':
        args.push('-tags', 'tech');
        break;
      case 'network':
        args.push('-tags', 'network,port-scan');
        break;
      case 'web':
        args.push('-tags', 'web,http');
        break;
      default:
        args.push('-tags', options.tags || 'misconfiguration,exposure');
    }

    // Add SSL bypass if needed
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
      args.push('-dca'); // disable certificate verification
    }

    // Add headless mode for web scans
    if (['web', 'technology'].includes(scanType)) {
      args.push('-headless');
    }

    return args.join(' ');
  }

  /**
   * OpenVAS command builder
   */
  private buildOpenVASCommand(target: string, scanType: string, options: any, outputFile: string): string {
    // OpenVAS via GVM-CLI requires more complex setup
    const args = [
      'gvm-cli',
      '--host', process.env.OPENVAS_HOST || 'localhost',
      '--port', process.env.OPENVAS_PORT || '9390',
      '--user', process.env.OPENVAS_USER!,
      '--password', process.env.OPENVAS_PASSWORD!,
      '--xml', `"<create_task><name>DealBrief-${Date.now()}</name><target id='${target}'/><config id='full_and_fast'/></create_task>"`
    ];

    return args.join(' ');
  }

  /**
   * OWASP ZAP command builder
   */
  private buildZAPCommand(target: string, scanType: string, options: any, outputFile: string): string {
    const args = [
      'zap-baseline.py',
      '-t', target,
      '-J', outputFile,
      '-a' // Include the 'alpha' rules
    ];

    if (options.authenticatedScan) {
      args.push('-A', options.authenticatedUser || 'testuser');
    }

    return args.join(' ');
  }

  /**
   * scan4all command builder
   */
  private buildScan4allCommand(target: string, scanType: string, options: any, outputFile: string): string {
    const args = [
      'scan4all',
      '-host', target,
      '-json'
    ];

    if (scanType === 'comprehensive') {
      args.push('-all');
    }

    return args.join(' ');
  }

  /**
   * Trivy command builder
   */
  private buildTrivyCommand(target: string, scanType: string, options: any, outputFile: string): string {
    const args = ['trivy'];

    switch (scanType) {
      case 'image':
        args.push('image', target);
        break;
      case 'filesystem':
        args.push('fs', target);
        break;
      case 'repository':
        args.push('repo', target);
        break;
      default:
        args.push('image', target);
    }

    args.push('-f', 'json', '-o', outputFile);

    return args.join(' ');
  }

  /**
   * ScoutSuite command builder
   */
  private buildScoutSuiteCommand(target: string, scanType: string, options: any, outputFile: string): string {
    const args = [
      'scout',
      'aws', // Default to AWS, can be extended for other cloud providers
      '--no-browser',
      '--report-dir', path.dirname(outputFile)
    ];

    if (options.region) {
      args.push('--regions', options.region);
    }

    return args.join(' ');
  }

  /**
   * Parse scanner output into standardized format
   */
  private async parseOutput(scanner: string, outputFile: string, stdout: string): Promise<any[]> {
    try {
      switch (scanner) {
        case 'nuclei':
          return this.parseNucleiOutput(stdout);
        
        case 'openvas':
          return this.parseOpenVASOutput(outputFile);
        
        case 'zap':
          return this.parseZAPOutput(outputFile);
        
        case 'scan4all':
          return this.parseScan4allOutput(stdout);
        
        case 'trivy':
          return this.parseTrivyOutput(outputFile);
        
        case 'scoutsuite':
          return this.parseScoutSuiteOutput(outputFile);
        
        default:
          return [];
      }
    } catch (error) {
      console.warn(`[SecurityWrapper] Failed to parse ${scanner} output:`, error);
      return [];
    }
  }

  /**
   * Parse Nuclei JSON output
   */
  private parseNucleiOutput(stdout: string): any[] {
    const findings: any[] = [];
    
    for (const line of stdout.split('\n')) {
      if (line.trim()) {
        try {
          const result = JSON.parse(line);
          findings.push({
            id: result['template-id'],
            name: result.info.name,
            severity: result.info.severity,
            description: result.info.description,
            host: result.host,
            type: 'nuclei_vulnerability',
            metadata: result
          });
        } catch (parseError) {
          // Skip malformed lines
        }
      }
    }
    
    return findings;
  }

  /**
   * Stub parsers for other tools (to be implemented)
   */
  private parseOpenVASOutput(outputFile: string): any[] {
    // TODO: Implement OpenVAS XML parsing
    return [];
  }

  private parseZAPOutput(outputFile: string): any[] {
    // TODO: Implement ZAP JSON parsing
    return [];
  }

  private parseScan4allOutput(stdout: string): any[] {
    // TODO: Implement scan4all JSON parsing
    return [];
  }

  private parseTrivyOutput(outputFile: string): any[] {
    // TODO: Implement Trivy JSON parsing
    return [];
  }

  private parseScoutSuiteOutput(outputFile: string): any[] {
    // TODO: Implement ScoutSuite JSON parsing
    return [];
  }

  /**
   * Get scanner status and health
   */
  async getScannersStatus(): Promise<Record<string, any>> {
    const status: Record<string, any> = {};

    for (const [name, config] of Object.entries(SCANNER_CONFIGS)) {
      try {
        const { stdout } = await execAsync(`which ${config.executable}`);
        status[name] = {
          available: true,
          executable: stdout.trim(),
          version: config.version,
          activeScanCount: this.activeScanCount
        };
      } catch (error) {
        status[name] = {
          available: false,
          error: (error as Error).message
        };
      }
    }

    return status;
  }

  /**
   * Get scan history for debugging
   */
  getScanHistory(): Map<string, ScanResult> {
    return this.scanHistory;
  }
}

// Singleton instance
export const securityWrapper = new SecurityScannerWrapper();

// Convenience functions for common scan types
export async function runNucleiScan(target: string, scanType: string = 'vulnerability', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'nuclei',
    target,
    scanType,
    options
  });
}

export async function runOpenVASScan(target: string, scanType: string = 'comprehensive', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'openvas',
    target,
    scanType,
    options
  });
}

export async function runZAPScan(target: string, scanType: string = 'baseline', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'zap',
    target,
    scanType,
    options
  });
}

export async function runScan4allScan(target: string, scanType: string = 'comprehensive', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'scan4all',
    target,
    scanType,
    options
  });
}

export async function runTrivyScan(target: string, scanType: string = 'image', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'trivy',
    target,
    scanType,
    options
  });
}

export async function runScoutSuiteScan(target: string, scanType: string = 'aws', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'scoutsuite',
    target,
    scanType,
    options
  });
}