import { config } from 'dotenv';
import axios, { AxiosError } from 'axios';
import fs from 'fs/promises';
import { normalizeDomain } from '../apps/workers/util/domainNormalizer.js';

config();

interface Company {
  companyName: string;
  domain: string;
  tags?: string[];
}

interface ApiLoaderOptions {
  apiUrl: string;
  batchSize: number;
  delayBetweenBatches: number;
  stopOnError: boolean;
  maxRetries: number;
  retryDelay: number;
}

class BulkCompanyApiLoader {
  private options: ApiLoaderOptions;
  private processedCount: number = 0;
  private failedCount: number = 0;
  private errors: Array<{ company: Company; error: string }> = [];
  private scanIds: string[] = [];

  constructor(options: Partial<ApiLoaderOptions> = {}) {
    this.options = {
      apiUrl: process.env.API_URL || 'http://localhost:3000',
      batchSize: 10,
      delayBetweenBatches: 2000,
      stopOnError: true,
      maxRetries: 3,
      retryDelay: 1000,
      ...options
    };
  }

  private log(message: string, ...args: any[]) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [api-loader]`, message, ...args);
  }

  private async callBulkApi(companies: Company[]): Promise<any> {
    const endpoint = `${this.options.apiUrl}/scan/bulk`;
    
    try {
      const response = await axios.post(endpoint, { companies }, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 30000
      });
      
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError;
        if (axiosError.response) {
          throw new Error(`API error ${axiosError.response.status}: ${JSON.stringify(axiosError.response.data)}`);
        } else if (axiosError.request) {
          throw new Error('No response from API - is the server running?');
        }
      }
      throw error;
    }
  }

  private async callSingleApi(company: Company, retries = 0): Promise<string> {
    const endpoint = `${this.options.apiUrl}/scan`;
    
    try {
      const normalizedDomain = normalizeDomain(company.domain);
      if (!normalizedDomain) {
        throw new Error(`Invalid domain: ${company.domain}`);
      }

      const response = await axios.post(endpoint, {
        companyName: company.companyName,
        domain: normalizedDomain,
        tags: company.tags
      }, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 10000
      });
      
      if (response.data.scanId) {
        return response.data.scanId;
      } else {
        throw new Error('No scanId in response');
      }
    } catch (error) {
      if (retries < this.options.maxRetries) {
        this.log(`Retry ${retries + 1}/${this.options.maxRetries} for ${company.companyName}`);
        await new Promise(resolve => setTimeout(resolve, this.options.retryDelay));
        return this.callSingleApi(company, retries + 1);
      }
      
      if (axios.isAxiosError(error)) {
        const axiosError = error as AxiosError;
        if (axiosError.response) {
          throw new Error(`API error ${axiosError.response.status}: ${JSON.stringify(axiosError.response.data)}`);
        }
      }
      throw error;
    }
  }

  private async processBatch(companies: Company[]): Promise<boolean> {
    this.log(`Processing batch of ${companies.length} companies...`);
    
    // Try bulk endpoint first
    try {
      const result = await this.callBulkApi(companies);
      if (result.results && Array.isArray(result.results)) {
        result.results.forEach((r: any, index: number) => {
          if (r.scanId) {
            this.processedCount++;
            this.scanIds.push(r.scanId);
            this.log(`✅ Queued: ${companies[index].companyName} - Scan ID: ${r.scanId}`);
          } else if (r.error) {
            this.failedCount++;
            this.errors.push({ company: companies[index], error: r.error });
            this.log(`❌ Failed: ${companies[index].companyName} - ${r.error}`);
          }
        });
        return true;
      }
    } catch (bulkError) {
      this.log('Bulk API failed, falling back to individual calls:', bulkError);
      
      // Fall back to individual API calls
      for (const company of companies) {
        try {
          const scanId = await this.callSingleApi(company);
          this.processedCount++;
          this.scanIds.push(scanId);
          this.log(`✅ Queued: ${company.companyName} - Scan ID: ${scanId}`);
        } catch (error) {
          this.failedCount++;
          const errorMessage = error instanceof Error ? error.message : String(error);
          this.errors.push({ company, error: errorMessage });
          this.log(`❌ Failed: ${company.companyName} - ${errorMessage}`);
          
          if (this.options.stopOnError) {
            this.log('Stopping due to error (stopOnError=true)');
            return false;
          }
        }
      }
    }
    
    return true;
  }

  async loadFromFile(filePath: string): Promise<void> {
    try {
      const fileContent = await fs.readFile(filePath, 'utf-8');
      const companies: Company[] = JSON.parse(fileContent);
      
      if (!Array.isArray(companies)) {
        throw new Error('Input file must contain a JSON array of companies');
      }
      
      this.log(`Loading ${companies.length} companies from ${filePath}`);
      await this.loadCompanies(companies);
    } catch (error) {
      this.log('Error reading input file:', error);
      throw error;
    }
  }

  async loadCompanies(companies: Company[]): Promise<void> {
    this.log(`Starting bulk load of ${companies.length} companies via API`);
    this.log(`API URL: ${this.options.apiUrl}`);
    this.log(`Batch size: ${this.options.batchSize}, Delay: ${this.options.delayBetweenBatches}ms`);
    
    // Test API connectivity
    try {
      await axios.get(`${this.options.apiUrl}/health`, { timeout: 5000 });
      this.log('API health check passed');
    } catch (error) {
      this.log('Warning: API health check failed:', error);
    }
    
    // Process in batches
    for (let i = 0; i < companies.length; i += this.options.batchSize) {
      const batch = companies.slice(i, i + this.options.batchSize);
      const batchNumber = Math.floor(i / this.options.batchSize) + 1;
      const totalBatches = Math.ceil(companies.length / this.options.batchSize);
      
      this.log(`\nBatch ${batchNumber}/${totalBatches}`);
      
      const success = await this.processBatch(batch);
      if (!success && this.options.stopOnError) {
        break;
      }
      
      // Add delay between batches (except for the last batch)
      if (i + this.options.batchSize < companies.length) {
        this.log(`Waiting ${this.options.delayBetweenBatches}ms before next batch...`);
        await new Promise(resolve => setTimeout(resolve, this.options.delayBetweenBatches));
      }
    }
    
    // Final summary
    this.log('\n=== API LOAD SUMMARY ===');
    this.log(`Total companies: ${companies.length}`);
    this.log(`Successfully queued: ${this.processedCount}`);
    this.log(`Failed: ${this.failedCount}`);
    this.log(`Scan IDs generated: ${this.scanIds.length}`);
    
    if (this.errors.length > 0) {
      this.log('\nErrors:');
      this.errors.forEach(({ company, error }) => {
        this.log(`  - ${company.companyName}: ${error}`);
      });
    }
    
    // Save scan IDs for tracking
    if (this.scanIds.length > 0) {
      const outputFile = `scan-ids-${Date.now()}.json`;
      await fs.writeFile(outputFile, JSON.stringify({
        timestamp: new Date().toISOString(),
        totalScans: this.scanIds.length,
        scanIds: this.scanIds
      }, null, 2));
      this.log(`\nScan IDs saved to: ${outputFile}`);
    }
  }

  async checkScanStatus(scanId: string): Promise<any> {
    try {
      const response = await axios.get(`${this.options.apiUrl}/scan/${scanId}/status`);
      return response.data;
    } catch (error) {
      this.log(`Error checking status for ${scanId}:`, error);
      return null;
    }
  }

  async monitorScans(): Promise<void> {
    if (this.scanIds.length === 0) {
      this.log('No scans to monitor');
      return;
    }
    
    this.log(`\nMonitoring ${this.scanIds.length} scans...`);
    const statuses = new Map<string, string>();
    
    // Check status every 30 seconds
    const checkInterval = setInterval(async () => {
      let completed = 0;
      let failed = 0;
      let processing = 0;
      
      for (const scanId of this.scanIds) {
        const status = await this.checkScanStatus(scanId);
        if (status) {
          const previousStatus = statuses.get(scanId);
          if (status.state !== previousStatus) {
            this.log(`Status change for ${scanId}: ${previousStatus || 'new'} → ${status.state}`);
            statuses.set(scanId, status.state);
          }
          
          if (status.state === 'done') completed++;
          else if (status.state === 'failed') failed++;
          else if (status.state === 'processing') processing++;
        }
      }
      
      this.log(`Progress: ${completed} completed, ${processing} processing, ${failed} failed`);
      
      // Stop monitoring when all scans are done
      if (completed + failed === this.scanIds.length) {
        clearInterval(checkInterval);
        this.log('All scans completed!');
      }
    }, 30000);
  }
}

// CLI usage
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log(`
Usage: npm run api-load -- [options] <input-file>

Options:
  --api-url <url>       API URL (default: http://localhost:3000 or API_URL env)
  --batch-size <n>      Number of companies per batch (default: 10)
  --delay <ms>          Delay between batches in milliseconds (default: 2000)
  --no-stop-on-error    Continue processing even if errors occur
  --monitor             Monitor scan progress after queueing

Example:
  npm run api-load -- --api-url https://api.example.com --batch-size 5 companies.json
  
Input file format (JSON):
[
  {
    "companyName": "Example Corp",
    "domain": "example.com",
    "tags": ["financial", "enterprise"]
  },
  ...
]
`);
    process.exit(1);
  }
  
  // Parse CLI arguments
  const inputFile = args[args.length - 1];
  const apiUrl = args.includes('--api-url')
    ? args[args.indexOf('--api-url') + 1]
    : undefined;
  const batchSize = args.includes('--batch-size') 
    ? parseInt(args[args.indexOf('--batch-size') + 1]) 
    : 10;
  const delay = args.includes('--delay')
    ? parseInt(args[args.indexOf('--delay') + 1])
    : 2000;
  const stopOnError = !args.includes('--no-stop-on-error');
  const monitor = args.includes('--monitor');
  
  const loader = new BulkCompanyApiLoader({
    apiUrl,
    batchSize,
    delayBetweenBatches: delay,
    stopOnError
  });
  
  loader.loadFromFile(inputFile)
    .then(async () => {
      if (monitor) {
        await loader.monitorScans();
      }
    })
    .catch((error) => {
      console.error('Fatal error:', error);
      process.exit(1);
    });
}

export { BulkCompanyApiLoader, Company, ApiLoaderOptions };