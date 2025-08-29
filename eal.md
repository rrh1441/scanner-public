This file is a merged representation of the entire codebase, combined into a single document by Repomix.

<file_summary>
This section contains a summary of this file.

<purpose>
This file contains a packed representation of the entire repository's contents.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.
</purpose>

<file_format>
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  - File path as an attribute
  - Full contents of the file
</file_format>

<usage_guidelines>
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.
</usage_guidelines>

<notes>
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)
</notes>

</file_summary>

<directory_structure>
consolidated-eal-methodology.md
dynamic-browser.md
eal-calculation.md
eal-financial-cost-methodology.md
</directory_structure>

<files>
This section contains the contents of the repository's files.

<file path="consolidated-eal-methodology.md">
# Consolidated EAL (Expected Annual Loss) Methodology

## Overview

This document describes the unified cost calculation methodology that consolidates all risk factors into a single, configurable system aligned with the existing scan totals aggregation.

## Architecture

### Core Tables

1. **attack_meta** - Defines attack categories and base financial impacts
   - `attack_type_code`: Primary key (e.g., PHISHING_BEC, SITE_HACK)
   - `prevalence`: Likelihood factor (0-1)
   - `raw_weight`: Base financial impact in dollars
   - `category`: CYBER, LEGAL, or CLOUD

2. **finding_type_mapping** - Maps finding types to attack categories
   - Links specific findings (e.g., VERIFIED_CVE) to attack types (e.g., SITE_HACK)
   - Allows severity overrides and custom multipliers

3. **severity_weight** - Severity-based multipliers
   - CRITICAL: 5.0x multiplier
   - HIGH: 2.5x multiplier
   - MEDIUM: 1.0x multiplier
   - LOW: 0.3x multiplier

4. **risk_constants** - Configurable system parameters
   - Confidence intervals
   - Time factors
   - Special case values (e.g., ADA settlements)

5. **dow_cost_constants** - Denial of Wallet service costs
   - Cost per request for different cloud services
   - Typical RPS and amplification factors

## Calculation Formula

```
Base Impact = raw_weight × severity_multiplier × custom_multiplier × prevalence

EAL Low = Base Impact × severity_low_confidence × LOW_CONFIDENCE_CONSTANT
EAL ML = Base Impact × severity_ml_confidence × ML_CONFIDENCE_CONSTANT  
EAL High = Base Impact × severity_high_confidence × HIGH_CONFIDENCE_CONSTANT
```

## Attack Categories

### CYBER (Aggregated as cyber_total)
- **PHISHING_BEC**: Business email compromise ($300k base)
- **SITE_HACK**: Website vulnerabilities ($500k base)
- **MALWARE**: Malware infections ($400k base)
- **CLIENT_SIDE_SECRET_EXPOSURE**: Exposed secrets ($600k base)

### LEGAL (Separate line items)
- **ADA_COMPLIANCE**: Fixed $25k-$500k liability
- **GDPR_VIOLATION**: GDPR fines ($500k base)
- **PCI_COMPLIANCE_FAILURE**: PCI violations ($250k base)

### CLOUD (Daily costs)
- **DENIAL_OF_WALLET**: Cloud cost attacks (calculated daily)

## Special Cases

### ADA Compliance
- Fixed settlement amounts regardless of severity
- Low: $25,000 (minimum settlement)
- ML: $75,000 (average settlement)
- High: $500,000 (major lawsuit)

### Denial of Wallet
- Extracts daily cost from finding description if available
- Otherwise calculates based on service type and RPS
- EAL values are multiples of daily cost (30, 90, 365 days)

## Integration with Sync Worker

The sync worker aggregates EAL values by attack_type_code:

```sql
SELECT attack_type_code, 
       SUM(eal_low) as total_eal_low,
       SUM(eal_ml) as total_eal_ml,
       SUM(eal_high) as total_eal_high
FROM findings 
WHERE scan_id = ? 
GROUP BY attack_type_code
```

Then maps to scan_totals_automated columns:
- PHISHING_BEC → phishing_bec_low/ml/high
- SITE_HACK → site_hack_low/ml/high  
- MALWARE → malware_low/ml/high
- ADA_COMPLIANCE → ada_compliance_low/ml/high
- DENIAL_OF_WALLET → dow_daily_low/ml/high

## Configuration

### To adjust financial impacts:
```sql
UPDATE attack_meta 
SET raw_weight = 750000 
WHERE attack_type_code = 'SITE_HACK';
```

### To add new finding types:
```sql
INSERT INTO finding_type_mapping (finding_type, attack_type_code, custom_multiplier)
VALUES ('NEW_FINDING_TYPE', 'SITE_HACK', 1.2);
```

### To modify risk constants:
```sql
UPDATE risk_constants 
SET value = 4.0 
WHERE key = 'HIGH_CONFIDENCE';
```

## Migration

Apply the migration to enable the consolidated system:

1. Go to Supabase SQL Editor
2. Run `supabase/migrations/20250111_consolidated_eal_system.sql`
3. Existing findings will be automatically recalculated

## Benefits

1. **Configurable**: All multipliers and weights in database tables
2. **Aligned**: Matches sync worker's attack_type_code aggregation
3. **Extensible**: Easy to add new finding types and attack categories
4. **Auditable**: Clear calculation path from finding to financial impact
5. **Consistent**: Single source of truth for all cost calculations
</file>

<file path="dynamic-browser.md">
# Dynamic Browser System

The Dynamic Browser system provides a singleton Puppeteer browser instance with semaphore-controlled page pooling to eliminate resource waste from multiple Chrome spawns across scan modules.

## Features

- **Singleton Browser**: Single Chrome instance shared across all scan modules
- **Page Pool Management**: Semaphore-controlled concurrent page limits
- **Memory Monitoring**: Automatic browser restart at memory thresholds
- **Crash Recovery**: Automatic retry on browser/page errors
- **Graceful Shutdown**: Proper cleanup on process termination
- **Development Mode**: Enhanced debugging support

## Environment Variables

### Required Configuration

- **`ENABLE_PUPPETEER`**: Controls browser availability
  - `1` (default): Enable Puppeteer browser
  - `0`: Disable browser (modules will skip browser-dependent operations)

### Optional Configuration

- **`PUPPETEER_MAX_PAGES`**: Maximum concurrent pages
  - Default: `min(3, os.cpus().length)`
  - Minimum: `1`
  - Controls semaphore size for page pool

- **`DEBUG_PUPPETEER`**: Debug mode
  - `true`: Enable dumpio and DevTools in development
  - `false` (default): Normal operation

- **`NODE_ENV`**: Environment mode
  - `development`: Headful browser with DevTools support
  - `production`: Headless operation

## Usage

### Basic Page Operations

```typescript
import { withPage } from '../util/dynamicBrowser.js';

// Execute function with managed page
const result = await withPage(async (page) => {
  await page.goto('https://example.com');
  return await page.title();
});
```

### Custom Browser Options

```typescript
import { getBrowser } from '../util/dynamicBrowser.js';

// Get browser with custom launch options
const browser = await getBrowser({
  args: ['--custom-flag'],
  timeout: 90000
});
```

### Memory Monitoring

```typescript
import { getBrowserMemoryStats } from '../util/dynamicBrowser.js';

const stats = getBrowserMemoryStats();
console.log(`RSS: ${stats.rss}MB, Active Pages: ${stats.activePagesCount}`);
```

## Resource Management

### Memory Limits

- **Target RSS**: ≤ 3 GB
- **Restart Threshold**: 3.5 GB
- **Monitoring Interval**: 15 seconds
- **Page Leak Warning**: 5 minutes

### Concurrency Control

```typescript
// Default semaphore size
const maxPages = Math.min(3, os.cpus().length);

// Override with environment variable
PUPPETEER_MAX_PAGES=5
```

### Performance Metrics

- **Browser RSS/Heap**: Logged every 30 seconds
- **Active Page Count**: Real-time monitoring
- **Page Operation Duration**: Per-navigation timing
- **Cache Hit Rates**: Various intelligence caches

## Fly.io Scaling

Scale up for memory-intensive operations:

```bash
# Scale up to 4GB for browser operations
fly machines update $MACH --size shared-cpu-2x

# Run your scans...

# Scale back down to save costs
fly machines update $MACH --size shared-cpu-1x
```

### Memory Expectations

| Configuration | Expected Usage |
|---------------|----------------|
| 1 page (baseline) | ~500MB |
| 3 pages (default) | ~800MB |
| 5 pages (max recommended) | ~1.2GB |
| + Node.js heap | ~200-400MB |
| **Total (3 pages)** | **~1.2GB** |

## Error Handling

### Automatic Recovery

- **Browser Crashes**: Automatic restart and retry (1 attempt)
- **Page Errors**: Graceful cleanup and error propagation
- **Memory Exhaustion**: Automatic browser restart at threshold
- **Timeout Handling**: Configurable timeouts with fallback

### Graceful Degradation

When `ENABLE_PUPPETEER=0`:

```typescript
// techStackScan behavior
{
  dynamic_browser_skipped: true,
  thirdPartyOrigins: 0  // Skip discovery
}

// accessibilityScan behavior
{
  type: 'accessibility_scan_unavailable',
  severity: 'INFO',
  reason: 'puppeteer_disabled'
}
```

## Development

### Local Development

```bash
# Enable debug mode
export DEBUG_PUPPETEER=true
export NODE_ENV=development

# Run with visible browser
npm run dev
```

### Testing

```bash
# Unit tests (mocked browser)
npm run test

# E2E tests (real Chromium)
npm run test:e2e

# With coverage
npm run test -- --coverage
```

### Debugging

- **Headful Mode**: Set `NODE_ENV=development`
- **DevTools**: Set `DEBUG_PUPPETEER=true`
- **Verbose Logging**: Browser events logged at INFO/WARN levels
- **Memory Tracking**: Regular memory usage reports

## Integration Examples

### TechStack Scan

```typescript
// Before: Module-specific browser
browser = await puppeteer.launch({ ... });
const page = await browser.newPage();
// ... page operations
await browser.close();

// After: Shared browser
return await withPage(async (page) => {
  // ... same page operations
  return results;
});
```

### Accessibility Scan

```typescript
// Graceful fallback
if (process.env.ENABLE_PUPPETEER === '0') {
  return { tested: false, error: 'Puppeteer disabled' };
}

return await withPage(async (page) => {
  await page.addScriptTag({ url: AXE_CORE_CDN });
  const results = await page.evaluate(() => axe.run());
  return processResults(results);
});
```

## Best Practices

### Resource Efficiency

1. **Minimize Page Operations**: Batch related tasks in single `withPage()` call
2. **Handle Errors Gracefully**: Don't let page errors crash entire scans
3. **Respect Semaphore**: Don't spawn additional browsers outside the system
4. **Monitor Memory**: Use `getBrowserMemoryStats()` for capacity planning

### Error Resilience

1. **Timeout Configuration**: Set appropriate page timeouts for your use case
2. **Retry Logic**: Handle recoverable errors (network, target closed)
3. **Fallback Modes**: Provide functionality when browser unavailable
4. **Cleanup Guarantees**: Always use `withPage()` for automatic cleanup

### Production Deployment

1. **Memory Monitoring**: Alert on high RSS usage
2. **Scale Appropriately**: Use `shared-cpu-2x` for browser workloads
3. **Environment Variables**: Configure `PUPPETEER_MAX_PAGES` based on workload
4. **Health Checks**: Monitor browser connectivity and page success rates

## Troubleshooting

### Common Issues

**Browser Won't Start**
```bash
# Check environment
echo $ENABLE_PUPPETEER

# Verify dependencies
npm list puppeteer async-mutex
```

**Memory Issues**
```bash
# Monitor usage
fly logs --app your-app | grep browser_rss_mb

# Scale up temporarily
fly machines update $MACH --size shared-cpu-2x
```

**Semaphore Deadlock**
```bash
# Check active pages
# Look for "pages_open" in metrics logs
# Reduce PUPPETEER_MAX_PAGES if needed
```

### Support

For issues with the Dynamic Browser system:

1. Check logs for browser startup/memory warnings
2. Verify environment variable configuration
3. Test with simplified page operations
4. Monitor memory usage patterns
5. Consider scaling Fly.io instance size

The system is designed to be resilient and self-healing, but proper configuration and monitoring ensure optimal performance.
</file>

<file path="eal-calculation.md">
# EAL (Expected Annual Loss) Calculation System

## Overview

The EAL calculation system automatically computes financial risk values for every security finding. It runs completely automatically - no manual intervention needed.

## How It Works

### Automatic Calculation (Preferred)

When findings are inserted into Supabase, a database trigger automatically calculates:
- **eal_low**: Conservative estimate (90% confidence)
- **eal_ml**: Most likely annual loss
- **eal_high**: Worst case scenario
- **eal_daily**: Daily exposure/cost

### Manual Calculation (Backup)

If needed, you can manually trigger EAL calculation for a scan:
```bash
node scripts/trigger-eal-calculation.js <scan_id>
```

## EAL Calculation Logic

### Base Values by Severity

| Severity | Low | Most Likely | High | Daily |
|----------|-----|-------------|------|-------|
| CRITICAL | $50,000 | $250,000 | $1,000,000 | $10,000 |
| HIGH | $10,000 | $50,000 | $250,000 | $2,500 |
| MEDIUM | $2,500 | $10,000 | $50,000 | $500 |
| LOW | $500 | $2,500 | $10,000 | $100 |
| INFO | $0 | $0 | $0 | $0 |

### Finding Type Multipliers

Different finding types have different financial impact multipliers:

**Critical Financial Impact (10x daily cost)**
- DENIAL_OF_WALLET
- CLOUD_COST_AMPLIFICATION

**Legal/Compliance (Fixed amounts or high multipliers)**
- ADA_LEGAL_CONTINGENT_LIABILITY: Fixed $25k-$500k
- GDPR_VIOLATION: 3-10x multiplier
- PCI_COMPLIANCE_FAILURE: 2-8x multiplier

**Data Exposure (High risk)**
- EXPOSED_DATABASE: 4-15x multiplier
- DATA_BREACH_EXPOSURE: 3-10x multiplier
- CLIENT_SIDE_SECRET_EXPOSURE: 2-5x multiplier

**Brand Damage**
- MALICIOUS_TYPOSQUAT: 1.5-6x multiplier
- PHISHING_INFRASTRUCTURE: 2-8x multiplier

## Special Cases

### DENIAL_OF_WALLET
If the finding description contains "Estimated daily cost: $X", the system extracts that value and calculates:
- Daily = Extracted amount
- Low = 30 days
- Most Likely = 90 days  
- High = 365 days

### ADA Compliance
Fixed legal liability amounts:
- Low: $25,000 (minimum settlement)
- Most Likely: $75,000 (average settlement)
- High: $500,000 (major lawsuit)
- Daily: $0 (not a recurring cost)

## Database Components

### Trigger Function
`calculate_finding_eal()` - Automatically runs on insert/update

### Database Triggers
- `calculate_eal_on_insert` - Calculates EAL for new findings
- `calculate_eal_on_update` - Recalculates if severity/type changes

### Summary View
`scan_eal_summary` - Aggregated EAL totals by scan

### Edge Function (Backup)
`eal-calculator` - Manual calculation endpoint

## Viewing EAL Data

### Get scan summary:
```sql
SELECT * FROM scan_eal_summary WHERE scan_id = 'YOUR_SCAN_ID';
```

### Get detailed findings with EAL:
```sql
SELECT finding_type, severity, eal_low, eal_ml, eal_high, eal_daily 
FROM findings 
WHERE scan_id = 'YOUR_SCAN_ID'
ORDER BY eal_ml DESC;
```

## Migration

To enable automatic EAL calculation:

1. Go to Supabase SQL Editor: https://supabase.com/dashboard/project/cssqcaieeixukjxqpynp/sql
2. Copy contents of `supabase/migrations/20250111_eal_trigger.sql`
3. Run in SQL editor

This creates all necessary functions, triggers, and views.
</file>

<file path="eal-financial-cost-methodology.md">
# EAL (Expected Annual Loss) and Financial Cost Methodology

## Executive Summary

The Flyscanner platform implements a comprehensive Expected Annual Loss (EAL) calculation system that automatically assigns financial risk values to security findings. This methodology provides quantified risk assessments for cybersecurity, legal compliance, and cloud infrastructure vulnerabilities, enabling data-driven risk management decisions.

## Overview

The EAL system converts qualitative security findings into quantitative financial impact estimates using a multi-factor calculation approach that considers:

- **Severity levels** (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- **Finding types** (e.g., VERIFIED_CVE, DATA_BREACH_EXPOSURE, ADA_LEGAL_CONTINGENT_LIABILITY)
- **Attack categories** (CYBER, LEGAL, CLOUD)
- **Confidence intervals** (Low, Most Likely, High estimates)
- **Time horizons** (Daily, Annual exposure)

## Architecture and Components

### Database Schema

The EAL system is built on five core database tables:

#### 1. attack_meta
Defines attack categories and base financial impacts:
```sql
- attack_type_code (Primary Key): PHISHING_BEC, SITE_HACK, MALWARE, etc.
- prevalence: Likelihood factor (0-1 scale)
- raw_weight: Base financial impact in dollars
- category: CYBER, LEGAL, or CLOUD
```

#### 2. finding_type_mapping
Maps specific finding types to attack categories:
```sql
- finding_type: Specific security finding (e.g., VERIFIED_CVE)
- attack_type_code: Associated attack category (e.g., SITE_HACK)
- custom_multiplier: Type-specific adjustment factor
- severity_override: Optional severity adjustment
```

#### 3. severity_weight
Severity-based multipliers for risk calculation:
```sql
- CRITICAL: 5.0x multiplier
- HIGH: 2.5x multiplier  
- MEDIUM: 1.0x multiplier
- LOW: 0.3x multiplier
- INFO: 0.0x multiplier
```

#### 4. risk_constants
Configurable system parameters:
```sql
- LOW_CONFIDENCE_CONSTANT: Conservative estimate factor
- ML_CONFIDENCE_CONSTANT: Most likely estimate factor
- HIGH_CONFIDENCE_CONSTANT: Worst-case estimate factor
- ADA_SETTLEMENT_LOW/ML/HIGH: Fixed legal liability amounts
```

#### 5. dow_cost_constants
Denial of Wallet service cost parameters:
```sql
- service_type: Cloud service identifier
- cost_per_request: Base cost per API call
- typical_rps: Expected requests per second
- amplification_factor: Attack amplification multiplier
```

## Calculation Methodology

### Core EAL Formula

```
Base Impact = raw_weight × severity_multiplier × custom_multiplier × prevalence

EAL Low = Base Impact × severity_low_confidence × LOW_CONFIDENCE_CONSTANT
EAL ML = Base Impact × severity_ml_confidence × ML_CONFIDENCE_CONSTANT  
EAL High = Base Impact × severity_high_confidence × HIGH_CONFIDENCE_CONSTANT
```

### Base Values by Severity

| Severity | EAL Low | EAL Most Likely | EAL High | EAL Daily |
|----------|---------|----------------|----------|-----------|
| CRITICAL | $50,000 | $250,000 | $1,000,000 | $10,000 |
| HIGH | $10,000 | $50,000 | $250,000 | $2,500 |
| MEDIUM | $2,500 | $10,000 | $50,000 | $500 |
| LOW | $500 | $2,500 | $10,000 | $100 |
| INFO | $0 | $0 | $0 | $0 |

### Finding Type Multipliers

#### Critical Financial Impact (10x daily cost)
- **DENIAL_OF_WALLET**: Cloud cost amplification attacks
- **CLOUD_COST_AMPLIFICATION**: Resource exhaustion attacks

#### Legal/Compliance Risks
- **ADA_LEGAL_CONTINGENT_LIABILITY**: Fixed $25k-$500k liability
- **GDPR_VIOLATION**: 3-10x multiplier for data privacy violations
- **PCI_COMPLIANCE_FAILURE**: 2-8x multiplier for payment card security

#### Data Exposure (High risk multipliers)
- **EXPOSED_DATABASE**: 4-15x multiplier
- **DATA_BREACH_EXPOSURE**: 3-10x multiplier  
- **CLIENT_SIDE_SECRET_EXPOSURE**: 2-5x multiplier
- **SENSITIVE_FILE_EXPOSURE**: 2-8x multiplier

#### Verified Vulnerabilities
- **VERIFIED_CVE**: 2-8x multiplier for confirmed CVEs
- **VULNERABILITY**: 1.5-5x multiplier for potential vulnerabilities

#### Brand/Reputation Damage
- **MALICIOUS_TYPOSQUAT**: 1.5-6x multiplier
- **PHISHING_INFRASTRUCTURE**: 2-8x multiplier
- **ADVERSE_MEDIA**: 1-5x multiplier

#### Infrastructure/Operational
- **EXPOSED_SERVICE**: 1.5-5x multiplier
- **MISSING_RATE_LIMITING**: 1-4x multiplier
- **TLS_CONFIGURATION_ISSUE**: 0.8-3x multiplier
- **EMAIL_SECURITY_GAP**: 1-4x multiplier

## Attack Categories and Aggregation

### CYBER (Aggregated as cyber_total)
- **PHISHING_BEC**: Business email compromise ($300k base impact)
- **SITE_HACK**: Website vulnerabilities ($500k base impact)
- **MALWARE**: Malware infections ($400k base impact)
- **CLIENT_SIDE_SECRET_EXPOSURE**: Exposed secrets ($600k base impact)

### LEGAL (Separate line items)
- **ADA_COMPLIANCE**: Fixed $25k-$500k liability
- **GDPR_VIOLATION**: GDPR fines ($500k base impact)
- **PCI_COMPLIANCE_FAILURE**: PCI violations ($250k base impact)

### CLOUD (Daily cost calculations)
- **DENIAL_OF_WALLET**: Cloud cost attacks (calculated daily)

## Special Case Calculations

### ADA Compliance
Fixed legal liability amounts regardless of severity:
```
- EAL Low: $25,000 (minimum settlement)
- EAL ML: $75,000 (average settlement)  
- EAL High: $500,000 (major lawsuit)
- EAL Daily: $0 (not a recurring cost)
```

### Denial of Wallet
Dynamic calculation based on extracted costs:
```
If finding description contains "Estimated daily cost: $X":
- EAL Daily = Extracted amount
- EAL Low = Daily × 30 (1 month exposure)
- EAL ML = Daily × 90 (3 month exposure)
- EAL High = Daily × 365 (1 year exposure)
```

## Implementation Details

### Automatic Calculation
The system uses database triggers to automatically calculate EAL values:
```sql
-- Trigger function: calculate_finding_eal()
-- Triggers: calculate_eal_on_insert, calculate_eal_on_update
```

### Manual Calculation
Backup calculation via Edge Function:
```bash
# Trigger EAL calculation for specific scan
node scripts/trigger-eal-calculation.js <scan_id>

# Debug EAL calculation
node scripts/query-findings-eal.js <scan_id>
```

### Integration with Sync Worker
The sync worker aggregates EAL values by attack_type_code:
```sql
SELECT attack_type_code, 
       SUM(eal_low) as total_eal_low,
       SUM(eal_ml) as total_eal_ml,
       SUM(eal_high) as total_eal_high
FROM findings 
WHERE scan_id = ? 
GROUP BY attack_type_code
```

Maps to scan_totals_automated columns:
- PHISHING_BEC → phishing_bec_low/ml/high
- SITE_HACK → site_hack_low/ml/high  
- MALWARE → malware_low/ml/high
- ADA_COMPLIANCE → ada_compliance_low/ml/high
- DENIAL_OF_WALLET → dow_daily_low/ml/high

## Configuration and Maintenance

### Adjusting Financial Impacts
```sql
-- Update base impact for attack type
UPDATE attack_meta 
SET raw_weight = 750000 
WHERE attack_type_code = 'SITE_HACK';
```

### Adding New Finding Types
```sql
-- Map new finding type to attack category
INSERT INTO finding_type_mapping (finding_type, attack_type_code, custom_multiplier)
VALUES ('NEW_FINDING_TYPE', 'SITE_HACK', 1.2);
```

### Modifying Risk Constants
```sql
-- Adjust confidence intervals
UPDATE risk_constants 
SET value = 4.0 
WHERE key = 'HIGH_CONFIDENCE';
```

## Quality Assurance

### Validation Queries
```sql
-- Check EAL calculation completeness
SELECT 
    COUNT(*) as total_findings,
    COUNT(eal_ml) as findings_with_eal,
    AVG(eal_ml) as avg_eal_ml
FROM findings 
WHERE scan_id = 'YOUR_SCAN_ID';

-- Identify findings without EAL values
SELECT finding_type, severity, COUNT(*) 
FROM findings 
WHERE scan_id = 'YOUR_SCAN_ID' AND eal_ml IS NULL
GROUP BY finding_type, severity;
```

### Summary Views
```sql
-- Get scan EAL summary
SELECT * FROM scan_eal_summary WHERE scan_id = 'YOUR_SCAN_ID';

-- Get detailed findings with EAL
SELECT finding_type, severity, eal_low, eal_ml, eal_high, eal_daily 
FROM findings 
WHERE scan_id = 'YOUR_SCAN_ID'
ORDER BY eal_ml DESC;
```

## Benefits and Outcomes

1. **Quantified Risk Management**: Converts qualitative security findings into quantifiable financial impact estimates

2. **Data-Driven Prioritization**: Enables risk-based prioritization of security remediation efforts

3. **Regulatory Compliance**: Provides structured approach to legal and compliance risk assessment

4. **Cost-Benefit Analysis**: Supports business case development for security investments

5. **Trend Analysis**: Enables tracking of risk exposure changes over time

6. **Stakeholder Communication**: Provides business-relevant metrics for executive reporting

## Limitations and Considerations

- **Point-in-Time Assessment**: EAL values represent risk at time of calculation, not future projections
- **Industry Variability**: Base impact values may need adjustment for specific industry sectors
- **Correlation Risks**: Multiple findings may have overlapping or correlated impacts not captured in simple summation
- **External Factors**: Market conditions, regulatory changes, and threat landscape evolution may affect accuracy
- **Confidence Intervals**: Estimates represent ranges rather than precise values due to inherent uncertainty in risk quantification

## Future Enhancements

- **Machine Learning Integration**: Incorporate ML models for dynamic risk factor adjustment
- **Industry Benchmarking**: Add industry-specific impact multipliers
- **Threat Intelligence Integration**: Connect with threat feeds for dynamic prevalence updates
- **Monte Carlo Simulation**: Implement statistical modeling for more sophisticated risk calculations
- **Business Context Integration**: Include company-specific factors (revenue, industry, geography) in calculations
</file>

</files>
