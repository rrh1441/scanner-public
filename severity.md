# Security Scanner - Severity Assignment Logic

This document outlines how the security scanner assigns severity levels to findings across all modules.

## Severity Levels

The scanner uses a 5-level severity system with numeric values for comparison:

- **CRITICAL**: 5 - Immediate action required, business-critical impact
- **HIGH**: 4 - Urgent remediation needed, significant security risk  
- **MEDIUM**: 3 - Important to address, moderate security impact
- **LOW**: 2 - Should be addressed, minimal security impact
- **INFO**: 1 - Informational, no immediate action required

## Module-Specific Severity Logic

### CVE/Vulnerability Severity (CVSS-based)
**File**: `apps/workers/util/nvdMirror.ts:310-313`

Based on CVSS v3 base scores (industry standard):
- **CRITICAL**: CVSS score ≥ 9.0
- **HIGH**: CVSS score ≥ 7.0  
- **MEDIUM**: CVSS score ≥ 4.0
- **LOW**: CVSS score < 4.0

### TLS/SSL Security Issues
**File**: `apps/workers/modules/tlsScan.ts:681-688`

- **HIGH**: 
  - SSLv2/SSLv3 protocols (deprecated, insecure)
  - Missing SSL certificates
  - NULL or RC4 ciphers (cryptographically broken)
- **MEDIUM**: 
  - TLSv1.0 (outdated protocol)
  - DES encryption (weak encryption)
- **Default**: MEDIUM for other TLS configuration issues

### Configuration/Secret Exposure
**File**: `apps/workers/modules/configExposureScanner.ts:109-129`

#### CRITICAL Secrets:
- AWS Access Keys (`aws_access_key_id`, `aws_secret_access_key`)
- Database Passwords and URLs (PostgreSQL, MySQL, MongoDB, Redis)
- Supabase Service Keys (`supabase_service_key`)
- Stripe Live Keys (`sk_live_`, `pk_live_`)
- Private Keys (RSA, EC, OpenSSH, DSA)

#### HIGH Secrets:
- Generic API Keys (`api_key`, `apikey`, `api_secret`)
- Google API Keys (`AIza...`)
- JWT Tokens (`eyJ...`)
- Bearer Tokens
- Slack Tokens (`xox...`)
- Generic Application Secrets (`client_secret`, `app_secret`)

### Accessibility Violations (Legal Risk)
**File**: `apps/workers/modules/accessibilityScan.ts:399-402`

- **HIGH**: 
  - Any critical WCAG violations (ADA lawsuit risk)
  - More than 5 serious violations
- **MEDIUM**: 
  - Any serious violations 
  - More than 10 total violations
- **LOW**: Any violations present
- **INFO**: No violations found

### Abuse Intelligence/Threat Detection
**File**: `apps/workers/modules/abuseIntelScan.ts:181`

- **HIGH**: Confirmed malicious IPs (active threats)
- **MEDIUM**: Suspicious but unconfirmed IPs

### Email/Authentication Attack Surface
**File**: `apps/workers/modules/emailBruteforceSurface.ts:215-231`

- **HIGH**: 
  - Microsoft OWA portals (high-value targets)
  - SSH access endpoints
- **MEDIUM**: 
  - Generic login forms
  - VPN endpoints  
  - RDP access points

### Backend/Service Exposure
**File**: `apps/workers/modules/backendExposureScanner.ts:204`

- **HIGH**: Exposed backend services found
- **INFO**: No exposures detected

### DNS Typosquatting/Domain Threats
**File**: `apps/workers/modules/dnsTwist.ts:1361-1377`

Based on threat scoring algorithm:
- **CRITICAL**: Score ≥ 40 (active phishing, confirmed threats)
- **HIGH**: Score ≥ 25 (high-confidence typosquats)
- **MEDIUM**: Score ≥ 15 (moderate-confidence variants)
- **LOW**: Score > 0 (low-confidence matches)
- **INFO**: Parked domains, sale pages

Factors increasing score:
- Active web content (+15 points)
- Email configuration (+10 points)
- Similar technology stack (+5 points)
- Short registration age (+10 points)

### Secret Detection (TruffleHog)
**File**: `apps/workers/modules/trufflehog.ts:60`

- **CRITICAL**: Verified secrets (confirmed active)
- **HIGH**: Unverified but detected secrets

### Web Application Security (ZAP/OWASP)
**File**: `apps/workers/modules/zapScan.ts:134`

- **HIGH**: More than 5 findings
- **MEDIUM**: 1-5 findings
- **INFO**: No findings

### OpenVAS Vulnerability Scanner
**File**: `apps/workers/modules/openvasScan.ts:504-506`

Maps OpenVAS severity scores to levels:
- **CRITICAL**: Score ≥ 9.0
- **HIGH**: Score ≥ 7.0
- **MEDIUM**: Score ≥ 4.0
- **LOW**: Score < 4.0

### Nuclei Template Scanner
**File**: `apps/workers/modules/nuclei.ts:96`

Uses Nuclei's built-in severity classification:
- Maps template severity directly to scanner levels
- Default: **MEDIUM** if severity not specified

## Severity Aggregation Logic

When multiple findings exist for the same asset, the system uses the `maxSeverity()` function to determine the overall severity by taking the highest severity level found.

**File**: `apps/workers/modules/assetCorrelator.ts:414`

## Business Impact Considerations

Severity assignments consider:

1. **Regulatory Compliance**: Accessibility violations = high legal exposure
2. **Financial Impact**: Payment processor keys = critical business risk
3. **Attack Vectors**: TLS vulnerabilities enable broader attacks
4. **Exploit Likelihood**: Confirmed threats vs. theoretical vulnerabilities
5. **Data Sensitivity**: Database access = critical data exposure

## Usage Notes

- Each module implements domain-specific logic rather than a centralized mapping
- Severity levels are designed to align with business risk and remediation priority
- CVSS scores are used where industry standards exist
- Legal and financial impact drives accessibility and credential exposure ratings