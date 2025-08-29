# Scanner Local - Security Scanning Workflows

*Complete operational workflows for Tier1 and Tier2 security scanning with SimplCyber reporting*

## 🎯 Overview

Scanner Local provides two main scanning modes:
- **Tier1 Scans** (16 modules, ~68 seconds) - Fast comprehensive security assessment
- **Tier2 Scans** (7 additional modules, 5-15+ minutes) - Extended deep analysis with intensive tools

All scans generate professional SimplCyber reports with EAL (Expected Annual Loss) financial risk calculations.

## 🚀 Quick Start Workflow

### Prerequisites Setup
```bash
# 1. Start PostgreSQL database
brew services start postgresql@16

# 2. Navigate to scanner directory
cd /Users/ryanheger/scannerlocal/apps/workers

# 3. Start the scanner server
npm run dev
# OR for production: pm2 start dist/localServer.js --name scanner-local

# 4. Verify system health
curl -s http://localhost:8080/health | jq '.'
```

## 📊 Tier1 Scan Workflow (Fast - 68 seconds)

**Purpose**: Comprehensive security assessment with 16 core modules for rapid threat identification.

### Step 1: Initiate Tier1 Scan
```bash
# Basic Tier1 scan
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Tier1 scan with custom scan ID
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "scan_id": "tier1-$(date +%s)"}'
```

### Step 2: Monitor Scan Progress
```bash
# Check scan status
curl -s http://localhost:8080/scans | jq '.[0]'

# Monitor scan completion
watch -n 5 'curl -s http://localhost:8080/scans | jq ".[0] | {id: .id, domain: .domain, status: .status, findings: .findings_count}"'
```

### Step 3: Tier1 Modules Execution (68s total)

**Stage 1 - Intelligence Gathering (Parallel, ~5-10s):**
1. `shodan_scan` - External threat intelligence (21ms)
2. `whois_wrapper` - Domain registration analysis (1ms) 
3. `spf_dmarc` - Email security assessment (7ms)
4. `abuse_intel_scan` - IP reputation analysis (21ms)

**Stage 2 - Surface Analysis (Parallel, ~15-20s):**
5. `accessibility_lightweight` - WCAG compliance check (6ms)
6. `lightweight_cve_check` - Known vulnerability detection (13ms)
7. `infostealer_probe` - Credential breach detection (8ms)
8. `document_exposure` - Sensitive file discovery (7ms)

**Stage 3 - Deep Discovery (Sequential, ~45-55s):**
9. `config_exposure_scanner` - Configuration file exposure (3.7s)
10. `tls_scan` - SSL/TLS security analysis (60s) **[Critical Security]**
11. `endpoint_discovery` - Web application mapping (34s)
12. `tech_stack_scan` - Technology fingerprinting (34s)

**Stage 4 - Dependency Processing (Sequential, ~3-5s):**
13. `client_secret_scanner` - Exposed credential detection (2ms)
14. `backend_exposure_scanner` - Internal service discovery (3ms)
15. `denial_wallet_scan` - Cost amplification vulnerabilities (2ms)
16. `asset_correlator` - Cross-module data integration (55ms)

### Step 4: Generate and Access Reports
```bash
# Generate PDF report
curl -s "http://localhost:8080/reports/{SCAN_ID}/report.pdf" > report.pdf

# Generate HTML report  
curl -s "http://localhost:8080/reports/{SCAN_ID}/report.html" > report.html

# Access reports via filesystem
ls -la scan-reports/{SCAN_ID}/
```

## 🔬 Tier2 Scan Workflow (Extended - 5-15+ minutes)

**Purpose**: Deep security analysis with intensive scanning tools and comprehensive vulnerability assessment.

### Step 1: Initiate Tier2 Scan
```bash
# Tier2 comprehensive scan
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "tier": "tier2", "scan_id": "tier2-$(date +%s)"}'
```

### Step 2: Tier2 Additional Modules (5-15+ minutes)

**Extended Analysis Modules:**
1. **ZAP Scan** (2-5 minutes) - OWASP ZAP web application scanning
2. **Nuclei Templates** (3-8 minutes) - 4000+ vulnerability templates  
3. **OpenVAS Integration** (5-15 minutes) - Network vulnerability assessment
4. **Advanced Port Scanning** (1-3 minutes) - Database and service enumeration
5. **Web Archive Analysis** (30s) - Historical vulnerability discovery
6. **AI Path Discovery** (30s) - ML-powered endpoint generation
7. **Platform Asset Discovery** (1-2 minutes) - Internet-wide asset enumeration

### Step 3: Monitor Extended Scan
```bash
# Extended monitoring for longer scans
watch -n 30 'curl -s http://localhost:8080/scans | jq ".[0] | {id: .id, status: .status, duration: .duration_ms, findings: .findings_count}"'

# Check detailed module status
curl -s http://localhost:8080/scans | jq '.[0].metadata.module_status'
```

## 📈 Report Generation Workflow

### Automatic Report Generation
Reports are generated automatically when accessed:
```bash
# Access triggers generation if not cached
curl "http://localhost:8080/reports/{SCAN_ID}/report.pdf"
curl "http://localhost:8080/reports/{SCAN_ID}/report.html" 
```

### Report Content Structure

#### **SimplCyber Report Sections:**
1. **Executive Header** - Domain, scan date, SimplCyber branding
2. **Expected Annual Loss (EAL)** - Financial risk calculations:
   - Conservative estimate (p90 confidence)
   - Most likely scenario 
   - Worst case exposure
3. **Executive Summary** - Key metrics and critical findings count
4. **Risk Category Breakdown**:
   - Cybersecurity risks ($)
   - Legal & compliance ($) 
   - Cloud infrastructure ($)
   - Daily exposure ($/day)
5. **Security Findings** - Detailed vulnerability list with:
   - Severity badges (Critical, High, Medium, Low, Info)
   - Technical descriptions
   - Recommended remediation actions
6. **Methodology** - EAL calculation approach

### Report Storage Locations
```bash
# Local filesystem storage
./scan-reports/{SCAN_ID}/report.html
./scan-reports/{SCAN_ID}/report.pdf

# PostgreSQL metadata
psql scanner_local -c "SELECT * FROM scans WHERE id = '{SCAN_ID}';"

# EAL financial calculations  
psql scanner_local -c "SELECT * FROM scan_eal_summary WHERE scan_id = '{SCAN_ID}';"
```

## 🔧 Operational Commands

### Database Management
```bash
# Check recent scans
psql scanner_local -c "SELECT id, domain, status, findings_count, created_at FROM scans ORDER BY created_at DESC LIMIT 10;"

# Analyze findings by severity
psql scanner_local -c "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity ORDER BY count DESC;"

# Check EAL calculations
psql scanner_local -c "SELECT scan_id, total_eal_ml, cyber_total_ml, legal_total_ml FROM scan_eal_summary ORDER BY total_eal_ml DESC;"
```

### System Monitoring
```bash
# Check server health with detailed status
curl -s http://localhost:8080/health | jq '.'

# Monitor active scans
curl -s http://localhost:8080/scans | jq '.[] | select(.status == "running")'

# Check system resources
ps aux | grep -E "(tsx|node)" | grep localServer
```

### Troubleshooting
```bash
# Restart scanner server
pkill -f "tsx.*localServer" && npx tsx localServer.ts > /tmp/scanner.log 2>&1 &

# Check scan logs
tail -f /tmp/scanner.log

# Verify database connectivity
psql scanner_local -c "SELECT COUNT(*) FROM scans;"

# Test module dependencies  
node test-dependent-modules.js
```

## 🌐 Production Deployment Workflow

### Mac Mini Production Setup
```bash
# 1. Install system dependencies
brew install postgresql@16 nodejs npm httpx nuclei sslscan nmap

# 2. Clone and setup scanner
git clone https://github.com/rrh1441/scanner-local
cd scanner-local/apps/workers
npm install && npm run build

# 3. Configure environment
cp .env.example .env
# Edit .env with your API keys

# 4. Start production services
brew services start postgresql@16
pm2 start dist/localServer.js --name scanner-local
pm2 startup && pm2 save
```

### Remote Access Setup
```bash
# Option 1: Cloudflare Tunnel (Recommended)
brew install cloudflare/cloudflare/cloudflared
cloudflared tunnel create scanner-local
# Configure tunnel routing to localhost:8080

# Option 2: ngrok (Development)
brew install ngrok
ngrok http 8080
```

## 📚 Integration Examples

### Website Integration
```javascript
// Frontend scan trigger
const scanResponse = await fetch('/api/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ 
    domain: userDomain,
    tier: 'tier1',
    scan_id: `web-${Date.now()}`
  })
});

// Poll for completion
const scanId = scanResponse.data.scan_id;
const checkStatus = setInterval(async () => {
  const status = await fetch(`/api/scans/${scanId}`);
  if (status.data.status === 'completed') {
    window.location.href = `/reports/${scanId}/report.pdf`;
    clearInterval(checkStatus);
  }
}, 5000);
```

### API Automation
```bash
# Automated daily scans
#!/bin/bash
DOMAINS=("example.com" "test.com" "client-site.com")

for domain in "${DOMAINS[@]}"; do
  scan_id="daily-$(date +%Y%m%d)-${domain//\./-}"
  curl -X POST http://localhost:8080/scan \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"$domain\", \"scan_id\": \"$scan_id\"}"
  
  echo "Started scan: $scan_id for $domain"
  sleep 30  # Stagger scan starts
done
```

## 🎯 Performance Characteristics

### Tier1 Scan Performance
- **Total Runtime**: 68 seconds average
- **Resource Usage**: ~200MB RAM per scan
- **Database Connections**: 2-3 connections per scan
- **File System**: ~50KB artifacts per scan
- **Network Requests**: ~200-500 external API calls

### Tier2 Scan Performance  
- **Total Runtime**: 5-15+ minutes depending on target complexity
- **Resource Usage**: ~500MB-1GB RAM per scan
- **Tool Dependencies**: nmap, nuclei, OWASP ZAP
- **Findings Volume**: 10x-50x more findings than Tier1
- **Storage Requirements**: ~5-10MB artifacts per scan

## 🚀 Next Steps & Enhancements

### Immediate Priorities (For Next Agent)
1. **Queue Management System** - Support concurrent scans
2. **Worker Pool Architecture** - Multiple parallel scan workers
3. **Resource Isolation** - Per-scan resource management
4. **Rate Limiting** - API quota management for external services
5. **Load Testing** - Verify concurrent scan performance

### Future Enhancements
- Real-time scan progress WebSocket API
- Scan result caching and incremental updates  
- Custom scan profiles and module selection
- Integration with SIEM platforms
- Automated remediation workflows

---

*Updated: 2025-08-22 | Scanner Local v1.0.0 | SimplCyber Template Integration Complete*