# SimplCyber Three-Tier Report System API

## Overview

The SimplCyber scanner now supports three distinct report types, each designed for different audiences and use cases:

1. **Snapshot Report** - Lead generation focused
2. **Executive Overview** - Business leadership focused  
3. **Technical Report** - IT team focused

## API Endpoints

### Generate Report

```bash
POST /reports/generate
```

**Body:**
```json
{
    "scan_id": "scan-abc123",
    "report_type": "snapshot-report|executive-report|technical-report"
}
```

**Response:**
```json
{
    "report_url": "/reports/scan-abc123/snapshot-report.pdf",
    "html_url": "/reports/scan-abc123/snapshot-report.html",
    "report_type": "snapshot-report",
    "scan_id": "scan-abc123",
    "domain": "example.com",
    "total_findings": 12,
    "severity_counts": {
        "CRITICAL": 2,
        "HIGH": 4,
        "MEDIUM": 5,
        "LOW": 1,
        "INFO": 0
    },
    "generated_at": "2024-01-01T12:00:00.000Z",
    "generation_time_ms": 1250,
    "status": "snapshot-report generated successfully"
}
```

### Direct Report Access

Access reports directly via URL:

```bash
# Snapshot Reports
GET /reports/{scan_id}/snapshot-report.pdf
GET /reports/{scan_id}/snapshot-report.html

# Executive Reports
GET /reports/{scan_id}/executive-report.pdf
GET /reports/{scan_id}/executive-report.html

# Technical Reports  
GET /reports/{scan_id}/technical-report.pdf
GET /reports/{scan_id}/technical-report.html
```

## Report Types

### 1. Snapshot Report (`snapshot-report`)

**Purpose:** Lead generation and initial prospect engagement

**Target Audience:** 
- Business decision makers
- Prospects evaluating security services
- Anyone needing a quick risk overview

**Key Features:**
- Financial risk assessment (EAL, compliance costs, cloud costs)
- High-level security findings in layman's terms  
- Call-to-action for scheduling consultations
- Limited to critical and high-severity findings only
- Maximum 1-2 pages for easy consumption

**Content:**
- Financial impact assessment
- Key vulnerability categories
- Business risk explanations
- Strong call-to-action

### 2. Executive Overview (`executive-report`)

**Purpose:** Detailed business briefing for paid clients

**Target Audience:**
- C-level executives
- Board members
- Business stakeholders

**Key Features:**
- Comprehensive business impact analysis
- Detailed financial risk breakdown
- Strategic recommendations
- Regulatory compliance implications
- All findings explained in business terms

**Content:**
- Executive summary with key metrics
- Financial risk assessment  
- Business impact analysis by category
- Strategic recommendations
- Finding categories and counts

### 3. Technical Report (`technical-report`)

**Purpose:** Detailed remediation guidance for technical implementation

**Target Audience:**
- Security engineers
- IT administrators  
- DevOps teams
- Technical consultants

**Key Features:**
- Complete technical details for all findings
- Step-by-step remediation instructions
- Code examples and commands
- Risk scoring and CVSS data
- Tools and methodology used

**Content:**
- Scan overview with technical metrics
- Security tools and methodology
- Detailed findings with technical analysis
- Specific remediation steps for each issue
- Code blocks and configuration examples

## Example Usage

### Generate a Snapshot Report for Lead Generation

```bash
curl -X POST http://localhost:8080/reports/generate \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "scan-abc123",
    "report_type": "snapshot-report"
  }'
```

### Generate an Executive Overview for Leadership

```bash
curl -X POST http://localhost:8080/reports/generate \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "scan-abc123", 
    "report_type": "executive-report"
  }'
```

### Generate a Technical Report for IT Team

```bash
curl -X POST http://localhost:8080/reports/generate \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "scan-abc123",
    "report_type": "technical-report"
  }'
```

### Direct Access to Generated Reports

```bash
# View snapshot report in browser
open http://localhost:8080/reports/scan-abc123/snapshot-report.pdf

# Download executive report
curl -O http://localhost:8080/reports/scan-abc123/executive-report.pdf

# View technical report HTML
curl http://localhost:8080/reports/scan-abc123/technical-report.html
```

## Testing

Run the test script to verify all report types work correctly:

```bash
node test-report-types.js
```

## Notes

- Reports are automatically generated on-demand if they don't exist
- All report types use the same scan data but present it differently
- The `executive-report` is used as the default if no report_type is specified
- Reports are cached locally after generation for faster subsequent access
- Each report type has different finding limits for optimal presentation