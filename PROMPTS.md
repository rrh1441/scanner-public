# Scanner Local - Setup Prompts & Instructions

*Detailed setup guides and configuration instructions*

## 🔧 Local Development Setup

### PostgreSQL Installation & Configuration

```bash
# Install PostgreSQL 16
brew install postgresql@16
brew services start postgresql@16

# Create database
createdb scanner_local

# Test connection
psql scanner_local -c "SELECT version();"
```

### Security Tools Installation

```bash
# Install security scanning tools
brew install httpx sslscan nuclei nmap

# Verify installations
httpx -version
sslscan --version  
nuclei -version
nmap --version
```

### Node.js Dependencies

```bash
# Navigate to workers directory
cd /Users/ryanheger/scannerlocal/apps/workers

# Install dependencies
npm install pg @types/pg express multer cors helmet

# Remove GCP packages (if present)
npm uninstall @google-cloud/firestore @google-cloud/storage @google-cloud/tasks @google-cloud/logging
```

### Environment Configuration

```bash
# Create .env file for local development
cat > .env << 'EOF'
# Database Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=scanner_local
POSTGRES_USER=postgres
POSTGRES_PASSWORD=

# Server Configuration
NODE_ENV=development
PORT=8080

# Local Storage Paths
REPORTS_DIR=./scan-reports
ARTIFACTS_DIR=./scan-artifacts

# Runtime Mode
RUNTIME_MODE=local
EOF
```

## 🚀 Production Deployment

### Mac Mini Setup (Production)

```bash
# Install required software
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install postgresql@16 nodejs npm

# Start PostgreSQL service
brew services start postgresql@16

# Setup application user
sudo useradd -m scanner
sudo usermod -aG admin scanner

# Clone repository
git clone https://github.com/rrh1441/scanner-local.git /opt/scanner
cd /opt/scanner/apps/workers

# Install dependencies
npm ci --only=production

# Build application
npm run build

# Setup PM2 for process management
npm install -g pm2
pm2 start dist/localServer.js --name scanner-local
pm2 startup  # Auto-start on boot
pm2 save
```

### Database Setup (Production)

```sql
-- Run this SQL to setup production database
CREATE DATABASE scanner_production;

-- Create tables (automatically done by localStore.ts on startup)
-- Tables: scans, findings, artifacts with proper indexes
```

## 🌐 Remote Access Configuration

### Option 1: Cloudflare Tunnel (Recommended)

```bash
# Install Cloudflare tunnel
brew install cloudflare/cloudflare/cloudflared

# Login to Cloudflare (requires free account)
cloudflared tunnel login

# Create tunnel
cloudflared tunnel create scanner

# Configure DNS record
# scanner.yourdomain.com → your Mac
# yourdomain.com stays on Vercel (unchanged)

# Create tunnel configuration
cat > ~/.cloudflared/config.yml << 'EOF'
tunnel: YOUR_TUNNEL_ID
credentials-file: ~/.cloudflared/YOUR_TUNNEL_ID.json

ingress:
  - hostname: scanner.yourdomain.com
    service: http://localhost:8080
  - service: http_status:404
EOF

# Run tunnel
cloudflared tunnel run scanner
```

### Option 2: ngrok (Quick Development)

```bash
# Install ngrok
brew install ngrok

# Configure auth token (sign up at ngrok.com)
ngrok config add-authtoken YOUR_AUTH_TOKEN

# Expose scanner
ngrok http 8080

# For custom subdomain (paid plan $8/month)
ngrok http 8080 --subdomain=yourscanner
```

### Option 3: SSH Tunnel (Secure)

```bash
# From development machine
ssh -L 8080:localhost:8080 user@your-mac-ip

# Access via localhost:8080
curl http://localhost:8080/health
```

## 🔄 Website Integration

### Frontend Integration Code

```javascript
// api/scan.js - Vercel function
export default async function handler(req, res) {
  // Replace with your tunnel URL
  const SCANNER_URL = process.env.SCANNER_URL || 'https://scanner.yourdomain.com';
  
  try {
    const response = await fetch(`${SCANNER_URL}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        domain: req.body.domain,
        scan_id: `web-${Date.now()}`
      })
    });
    
    const result = await response.json();
    res.json({
      scan_id: result.scan_id,
      status: result.status,
      report_url: result.report_url,
      duration_ms: result.duration_ms
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Scanner temporarily unavailable',
      details: error.message 
    });
  }
}
```

### React Component Example

```jsx
// ScanTrigger.jsx
import { useState } from 'react';

export function ScanTrigger() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const triggerScan = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      
      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error('Scan failed:', error);
    }
    setLoading(false);
  };

  return (
    <div>
      <input 
        type="text" 
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        placeholder="Enter domain to scan"
      />
      <button onClick={triggerScan} disabled={loading}>
        {loading ? 'Scanning...' : 'Start Scan'}
      </button>
      
      {result && (
        <div>
          <p>Scan ID: {result.scan_id}</p>
          <p>Status: {result.status}</p>
          <p>Duration: {result.duration_ms}ms</p>
          {result.report_url && (
            <a href={result.report_url} target="_blank" rel="noopener">
              Download Report
            </a>
          )}
        </div>
      )}
    </div>
  );
}
```

## 🧪 Testing & Validation

### Health Check Tests

```bash
# Basic health check
curl -s http://localhost:8080/health | jq '.'

# Expected response structure:
{
  "status": "ok",
  "timestamp": "2025-08-20T...",
  "uptime": 1234.56,
  "services": {
    "database": {"status": "ok"},
    "security_tools": {
      "httpx": {"status": "ok"},
      "nuclei": {"status": "ok"},
      "sslscan": {"status": "ok"}
    }
  }
}
```

### Single Scan Test

```bash
# Test scan with clean target
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "httpbin.org", "scan_id": "test-clean"}'

# Test scan with vulnerable target  
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "testphp.vulnweb.com", "scan_id": "test-vuln"}'
```

### Database Validation

```sql
-- Check scan results
SELECT 
  scan_id, 
  domain, 
  status, 
  findings_count, 
  duration_ms
FROM scans 
ORDER BY created_at DESC 
LIMIT 5;

-- Verify findings structure
SELECT 
  scan_id,
  type,
  severity,
  title
FROM findings 
WHERE scan_id LIKE 'test-%'
LIMIT 10;

-- Check for orphaned findings
SELECT COUNT(*) as orphaned_findings
FROM findings 
WHERE scan_id = 'unknown' OR scan_id NOT IN (SELECT id FROM scans);
```

### Performance Benchmarking

```bash
# Concurrent scan test
cat > test-concurrent.sh << 'EOF'
#!/bin/bash
DOMAINS=("httpbin.org" "example.com" "badssl.com")

for i in "${!DOMAINS[@]}"; do
  domain="${DOMAINS[$i]}"
  scan_id="concurrent-$i"
  
  curl -X POST http://localhost:8080/scan \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"$domain\", \"scan_id\": \"$scan_id\"}" &
done

wait
echo "All concurrent scans initiated"
EOF

chmod +x test-concurrent.sh
./test-concurrent.sh
```

## 🚨 Monitoring & Alerting Setup

### Basic Health Monitoring Script

```bash
#!/bin/bash
# monitor-scanner.sh - Run via cron every 5 minutes

HEALTHCHECK_URL="http://localhost:8080/health"
SLACK_WEBHOOK="YOUR_SLACK_WEBHOOK_URL"

check_health() {
    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 $HEALTHCHECK_URL)
    [ "$response" = "200" ]
}

send_alert() {
    local message="$1"
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"🚨 Scanner Alert: $message\"}" \
        $SLACK_WEBHOOK
}

if ! check_health; then
    send_alert "Scanner health check failed - service may be down"
    exit 1
fi

echo "$(date): Scanner healthy"
```

### Cron Job Setup

```bash
# Add to crontab: crontab -e
*/5 * * * * /usr/local/bin/monitor-scanner.sh >> /var/log/scanner-monitor.log 2>&1

# Log rotation
sudo tee /etc/logrotate.d/scanner << 'EOF'
/var/log/scanner-monitor.log {
    daily
    missingok
    rotate 7
    compress
    create 644 scanner scanner
}
EOF
```

## 🔐 Security Considerations

### Firewall Configuration

```bash
# macOS firewall rules (if needed)
sudo pfctl -f /etc/pf.conf

# Allow scanner port
echo "pass in on en0 proto tcp from any to any port 8080" | sudo tee -a /etc/pf.conf
sudo pfctl -f /etc/pf.conf
```

### SSL/TLS Setup (with Caddy)

```bash
# Install Caddy for SSL termination
brew install caddy

# Create Caddyfile
cat > /opt/scanner/Caddyfile << 'EOF'
scanner.yourdomain.com {
    reverse_proxy localhost:8080
    log {
        output file /var/log/caddy/scanner.log
    }
}
EOF

# Start Caddy
caddy run --config /opt/scanner/Caddyfile
```

### Environment Variables Security

```bash
# Secure .env file permissions
chmod 600 /opt/scanner/apps/workers/.env
chown scanner:scanner /opt/scanner/apps/workers/.env

# Store sensitive values in environment
export SLACK_WEBHOOK="your_webhook_url"
export POSTGRES_PASSWORD="secure_password"
```

## 🔧 Troubleshooting Guide

### Common Issues & Solutions

**Issue: Database connection failed**
```bash
# Check PostgreSQL status
brew services list | grep postgresql

# Restart PostgreSQL
brew services restart postgresql@16

# Verify database exists
psql -l | grep scanner_local
```

**Issue: Security tools not found**
```bash
# Verify tool installations
which httpx nuclei sslscan nmap

# Reinstall if missing
brew install httpx nuclei sslscan nmap
```

**Issue: Scanner hangs during scan**
```bash
# Check active processes
ps aux | grep -E "(httpx|nuclei|sslscan|nmap)"

# Kill hung processes
pkill -f httpx
pkill -f nuclei

# Restart scanner
pm2 restart scanner-local
```

**Issue: Reports not generating**
```bash
# Check report directory permissions
ls -la scan-reports/
chmod 755 scan-reports/

# Verify Puppeteer installation
npm list puppeteer
npm install puppeteer  # If missing
```

### Log Analysis

```bash
# PM2 logs
pm2 logs scanner-local

# Scanner application logs
tail -f ~/.pm2/logs/scanner-local-out.log
tail -f ~/.pm2/logs/scanner-local-error.log

# PostgreSQL logs (if needed)
tail -f /usr/local/var/log/postgresql@16.log
```

## 📋 Deployment Checklist

### Pre-Deployment Verification

- [ ] PostgreSQL 16 installed and running
- [ ] All security tools installed (httpx, nuclei, sslscan, nmap)
- [ ] Node.js and npm latest versions
- [ ] Repository cloned and dependencies installed
- [ ] Environment variables configured
- [ ] Database schema created automatically
- [ ] Health endpoint returns 200 OK
- [ ] Single scan test completes successfully
- [ ] Reports generate without errors
- [ ] PM2 configured for auto-restart

### Production Launch Steps

1. **Setup Mac Mini hardware and network**
2. **Install and configure all software dependencies**
3. **Deploy application code and configure environment**
4. **Setup remote access (Cloudflare tunnel or ngrok)**
5. **Configure monitoring and alerting**
6. **Update website integration endpoints**
7. **Perform end-to-end testing**
8. **Monitor for 24-48 hours before going fully live**

---

*Complete setup and deployment instructions for Scanner Local*  
*Updated: 2025-08-20*