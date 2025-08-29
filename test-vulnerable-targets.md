# Vulnerable Test Targets for Scanner Validation

## Purpose
Validate that each security module actually detects real vulnerabilities by testing against known vulnerable targets.

## Test Targets

### 1. Web Application Vulnerabilities
- **testphp.vulnweb.com** - Known vulnerable PHP application
- **zero.webappsecurity.com** - Banking application with multiple vulnerabilities
- **demo.testfire.net** - Altoro Mutual vulnerable banking site

### 2. TLS/SSL Issues
- **expired.badssl.com** - Expired certificates
- **wrong.host.badssl.com** - Wrong hostname
- **self-signed.badssl.com** - Self-signed certificates
- **untrusted-root.badssl.com** - Untrusted root CA

### 3. Configuration Exposure
- **httpbin.org** - API endpoints that might expose internal configs
- Create custom subdomains with exposed .git, .env files

### 4. Breach/Credential Testing
- **example.com** - High breach count domain (1000+ breaches in LeakCheck)
- **adobe.com** - Known large-scale breach history
- **linkedin.com** - Major breach history

### 5. Document Exposure
- Sites with exposed PDFs, docs in robots.txt or common paths

### 6. Tech Stack Detection
- **wordpress.com** - WordPress detection
- **shopify.dev** - E-commerce platform detection
- **github.com** - Tech stack identification

## Test Validation Commands

```bash
# Test vulnerable web app
curl -X POST http://localhost:8080/scan \\
  -H "Content-Type: application/json" \\
  -d '{"domain": "testphp.vulnweb.com", "scan_id": "vuln-web-test"}'

# Test SSL issues
curl -X POST http://localhost:8080/scan \\
  -H "Content-Type: application/json" \\
  -d '{"domain": "expired.badssl.com", "scan_id": "ssl-test"}'

# Test breach detection
curl -X POST http://localhost:8080/scan \\
  -H "Content-Type: application/json" \\
  -d '{"domain": "example.com", "scan_id": "breach-test"}'
```

## Expected Results Per Module

### 1. Breach Directory Probe
- **example.com**: Should find 1000+ breach records
- **adobe.com**: Should find major breach exposures

### 2. TLS Scan
- **expired.badssl.com**: Should flag expired certificate
- **self-signed.badssl.com**: Should flag self-signed cert

### 3. Endpoint Discovery
- **testphp.vulnweb.com**: Should find admin panels, test pages
- **zero.webappsecurity.com**: Should find banking endpoints

### 4. Config Exposure Scanner
- Sites with exposed .git, .env, config files

### 5. Document Exposure
- Sites with PDFs, docs in common locations

### 6. Tech Stack Scan
- **wordpress.com**: Should detect WordPress
- **shopify.dev**: Should detect Shopify/e-commerce

### 7. SPF/DMARC
- Domains with missing or weak email security policies

### 8. Shodan Scan
- Domains with exposed services/ports

### 9. WHOIS Wrapper
- Domain registration info and potential issues

### 10. CVE Check
- Sites running vulnerable software versions

## Quality Validation

Each module should produce:
- **Relevant findings**: Actually related to security
- **Actionable recommendations**: Clear next steps
- **Accurate severity**: CRITICAL/HIGH/MEDIUM/LOW/INFO properly assigned
- **No false positives**: Findings should be real issues

## Success Criteria

✅ **Vulnerable targets produce findings**
✅ **Safe targets produce minimal findings**
✅ **Findings are actionable and accurate**
✅ **Performance remains under 60 seconds**
✅ **No module crashes or timeouts**