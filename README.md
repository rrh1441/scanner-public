# DealBrief Scanner

A comprehensive cybersecurity scanning platform with both backend scanning capabilities and frontend dashboard interface.

## Architecture

- **Backend**: Comprehensive security scanning engine with multiple modules
- **Frontend**: Next.js dashboard with React/Supabase integration
- **API Gateway**: Fastify-based REST API for job management
- **Worker System**: Background job processing with Redis queue
- **Storage**: PostgreSQL for artifacts, S3-compatible storage for files
- **Deployment**: Docker containerized, Fly.io ready

## Features

### Security Scanning Backend
- **File Hunting**: Google dork searches with Serper API to find exposed files
- **CRM Exposure**: HubSpot and Salesforce CDN scanning for leaked documents
- **Passive Reconnaissance**: SpiderFoot integration for subdomain and IP discovery
- **Domain Security**: DNS twist for typo-squatting detection, DMARC/SPF checks
- **TLS/SSL Analysis**: Certificate and cipher suite security assessment
- **Vulnerability Scanning**: Nuclei templates for common web vulnerabilities
- **Secret Detection**: TruffleHog integration for exposed credentials
- **Database Security**: Port scanning and default credential checks
- **Rate Limiting Tests**: OWASP ZAP integration for rate limit bypass testing
- **Fast Tech Detection**: Lightweight technology stack identification (≤150ms)

### Frontend Dashboard
- **Scan Management**: Create, monitor, and manage security scans
- **Findings Analysis**: View and analyze security findings with filtering
- **Report Generation**: Generate executive and technical reports
- **Dashboard Analytics**: Real-time statistics and recent scan overview
- **User Management**: Settings and configuration management

## Setup

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Environment Variables**:
   ```bash
   # Redis (Upstash)
   REDIS_URL=redis://...

   # Database (Fly Postgres)
   DB_URL=postgresql://...

   # Supabase
   SUPABASE_URL=https://...
   SUPABASE_SERVICE_ROLE_KEY=...

   # S3 Storage
   S3_ENDPOINT=https://...
   S3_ACCESS_KEY=...
   S3_SECRET_KEY=...

   # API Keys
   SERPER_KEY=...
   ```

3. **Development**:
   ```bash
   # Run everything (backend + frontend)
   npm run dev

   # Run individual components
   npm run dev:workers    # Security scanning workers
   npm run dev:api       # API server
   npm run dev:frontend  # Next.js frontend
   ```

4. **Build & Deploy**:
   ```bash
   npm run build
   npm start
   ```

## API Endpoints

- `POST /scan` - Start a new security scan
- `GET /scan/:id/status` - Check scan status
- `POST /scan/:id/callback` - Webhook for scan completion

## Frontend Routes

- `/dashboard` - Main dashboard with stats and recent scans
- `/scans` - Scan management interface
- `/scans/new` - Create new security scan
- `/scans/[id]` - View scan details and findings
- `/findings` - Global findings analysis
- `/reports` - Report generation and management
- `/settings` - User settings and configuration

## Fast Tech Scanner Usage

The Fast Tech Scanner provides lightweight technology detection without external dependencies:

```typescript
import { detectTechnologiesBatch } from './apps/workers/util/fast-tech-scanner.js';

(async () => {
  const results = await detectTechnologiesBatch([
    'https://example.com', 
    'https://shopify.com'
  ]);
  
  console.table(results.map(r => ({ 
    url: r.url, 
    techs: r.technologies.map(t => t.name).join(', '),
    duration: `${r.duration}ms`
  })));
})();
```

## Security Tools Required

The worker modules expect these tools to be available in the runtime environment:

- `sf` (SpiderFoot CLI)
- `dnstwist`
- `dig`
- `testssl.sh`
- `trufflehog`
- `nuclei`
- `nmap`
- `openssl`

## Severity Classification System

The scanner uses a 5-level severity system to classify security findings:

- **CRITICAL (5)**: Immediate action required - confirmed active threats, exposed credentials, missing TLS certificates
- **HIGH (4)**: Urgent remediation needed - deprecated protocols, exposed services, malicious IPs  
- **MEDIUM (3)**: Important to address - configuration issues, suspicious activity, moderate CVSS scores
- **LOW (2)**: Should be addressed - minor violations, low-confidence threats
- **INFO (1)**: Informational only - successful scans, no issues detected

### Key Severity Factors:

- **CVSS Scores**: Industry-standard vulnerability ratings (9.0+ = CRITICAL, 7.0+ = HIGH)
- **Business Impact**: Legal exposure (accessibility), financial risk (payment keys)  
- **Attack Surface**: TLS vulnerabilities enable broader attack vectors
- **Threat Intelligence**: Confirmed malicious vs. suspicious indicators

For complete severity assignment logic, see [`severity.md`](severity.md).

## License

Private - DealBrief Scanner