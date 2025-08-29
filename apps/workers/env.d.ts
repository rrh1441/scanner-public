/**
 * Environment variable type definitions
 */

declare global {
  namespace NodeJS {
    interface ProcessEnv {
      // Existing environment variables
      NODE_ENV?: 'development' | 'production' | 'test';
      
      // API Keys
      ABUSEIPDB_API_KEY?: string;
      CENSYS_API_ID?: string;
      CENSYS_API_KEY?: string;
      CENSYS_API_SECRET?: string;
      CHAOS_API_KEY?: string;
      CLAUDE_API_KEY?: string;
      HAVEIBEENPWNED_API_KEY?: string;
      HIBP_API_KEY?: string;
      LEAKCHECK_API_KEY?: string;
      NUCLEI_API_KEY?: string;
      NVD_API_KEY?: string;
      OPENAI_API_KEY?: string;
      SERPER_KEY?: string;
      SHODAN_API_KEY?: string;
      SPIDERFOOT_API_KEY?: string;
      SPIDERFOOT_FILTER_MODE?: string;
      WHOISXML_API_KEY?: string;
      WHOISXML_KEY?: string;
      
      // Monitoring
      SENTRY_DSN?: string;
      
      // Google Cloud Platform
      GOOGLE_CLOUD_PROJECT?: string;
      GOOGLE_APPLICATION_CREDENTIALS?: string;
      GCS_BUCKET_NAME?: string;
      CLOUD_TASKS_LOCATION?: string;
      CLOUD_TASKS_QUEUE?: string;
      WORKER_URL?: string;
      K_SERVICE?: string;
      
      // Puppeteer Configuration (NEW)
      PUPPETEER_MAX_PAGES?: string;
      ENABLE_PUPPETEER?: '0' | '1';
      DEBUG_PUPPETEER?: 'true' | 'false';
      
      // Testing
      PUPPETEER_E2E?: '1';
      
      // OpenVAS/Greenbone Configuration
      OPENVAS_HOST?: string;
      OPENVAS_PORT?: string;
      OPENVAS_USERNAME?: string;
      OPENVAS_PASSWORD?: string;
      OPENVAS_TIMEOUT?: string;
    }
  }
}

export {};