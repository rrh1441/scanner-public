-- EAL (Expected Annual Loss) System Migration for Local PostgreSQL
-- Based on consolidated-eal-methodology.md

-- 1. Add EAL columns to findings table
ALTER TABLE findings ADD COLUMN IF NOT EXISTS eal_low DECIMAL(12,2);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS eal_ml DECIMAL(12,2);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS eal_high DECIMAL(12,2);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS eal_daily DECIMAL(12,2);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack_type_code TEXT;

-- 2. Create attack_meta table - defines attack categories and base financial impacts
CREATE TABLE IF NOT EXISTS attack_meta (
    attack_type_code TEXT PRIMARY KEY,
    prevalence DECIMAL(3,2) NOT NULL CHECK (prevalence >= 0 AND prevalence <= 1),
    raw_weight DECIMAL(12,2) NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('CYBER', 'LEGAL', 'CLOUD')),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Create finding_type_mapping table - maps finding types to attack categories
CREATE TABLE IF NOT EXISTS finding_type_mapping (
    id SERIAL PRIMARY KEY,
    finding_type TEXT NOT NULL,
    attack_type_code TEXT NOT NULL REFERENCES attack_meta(attack_type_code),
    custom_multiplier DECIMAL(5,2) DEFAULT 1.0,
    severity_override TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(finding_type, attack_type_code)
);

-- 4. Create severity_weight table - severity-based multipliers
CREATE TABLE IF NOT EXISTS severity_weight (
    severity TEXT PRIMARY KEY,
    multiplier DECIMAL(5,2) NOT NULL,
    description TEXT
);

-- 5. Create risk_constants table - configurable system parameters
CREATE TABLE IF NOT EXISTS risk_constants (
    key TEXT PRIMARY KEY,
    value DECIMAL(10,4) NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. Create dow_cost_constants table - Denial of Wallet service costs
CREATE TABLE IF NOT EXISTS dow_cost_constants (
    service_type TEXT PRIMARY KEY,
    cost_per_request DECIMAL(10,6) NOT NULL,
    typical_rps INTEGER NOT NULL,
    amplification_factor DECIMAL(5,2) DEFAULT 1.0,
    description TEXT
);

-- 7. Insert base data for attack_meta
INSERT INTO attack_meta (attack_type_code, prevalence, raw_weight, category, description) VALUES
    ('PHISHING_BEC', 0.15, 300000, 'CYBER', 'Business email compromise attacks'),
    ('SITE_HACK', 0.25, 500000, 'CYBER', 'Website vulnerabilities and compromises'),
    ('MALWARE', 0.20, 400000, 'CYBER', 'Malware infections and related damage'),
    ('CLIENT_SIDE_SECRET_EXPOSURE', 0.10, 600000, 'CYBER', 'Exposed API keys and secrets'),
    ('ADA_COMPLIANCE', 0.30, 75000, 'LEGAL', 'ADA accessibility compliance violations'),
    ('GDPR_VIOLATION', 0.12, 500000, 'LEGAL', 'GDPR data privacy violations'),
    ('PCI_COMPLIANCE_FAILURE', 0.18, 250000, 'LEGAL', 'PCI DSS compliance failures'),
    ('DENIAL_OF_WALLET', 0.08, 50000, 'CLOUD', 'Cloud cost amplification attacks')
ON CONFLICT (attack_type_code) DO NOTHING;

-- 8. Insert severity weights
INSERT INTO severity_weight (severity, multiplier, description) VALUES
    ('CRITICAL', 5.0, 'Critical security issues requiring immediate attention'),
    ('HIGH', 2.5, 'High severity issues with significant impact'),
    ('MEDIUM', 1.0, 'Medium severity baseline multiplier'),
    ('LOW', 0.3, 'Low severity issues with limited impact'),
    ('INFO', 0.0, 'Informational findings with no direct risk')
ON CONFLICT (severity) DO NOTHING;

-- 9. Insert risk constants
INSERT INTO risk_constants (key, value, description) VALUES
    ('LOW_CONFIDENCE_CONSTANT', 0.2, 'Conservative estimate multiplier'),
    ('ML_CONFIDENCE_CONSTANT', 1.0, 'Most likely estimate multiplier'),
    ('HIGH_CONFIDENCE_CONSTANT', 4.0, 'Worst case estimate multiplier'),
    ('ADA_SETTLEMENT_LOW', 25000, 'Minimum ADA settlement amount'),
    ('ADA_SETTLEMENT_ML', 75000, 'Average ADA settlement amount'),
    ('ADA_SETTLEMENT_HIGH', 500000, 'Maximum ADA settlement amount')
ON CONFLICT (key) DO NOTHING;

-- 10. Insert DOW cost constants
INSERT INTO dow_cost_constants (service_type, cost_per_request, typical_rps, amplification_factor, description) VALUES
    ('openai', 0.015, 10, 100, 'OpenAI API costs per token/request'),
    ('anthropic', 0.030, 5, 80, 'Anthropic Claude API costs'),
    ('aws_lambda', 0.0000002, 1000, 50, 'AWS Lambda execution costs'),
    ('gcp_cloud_run', 0.000024, 500, 60, 'Google Cloud Run costs'),
    ('azure_functions', 0.0000002, 800, 45, 'Azure Functions costs'),
    ('sendgrid', 0.001, 100, 20, 'SendGrid email API costs'),
    ('twilio', 0.0075, 50, 30, 'Twilio SMS/Voice API costs')
ON CONFLICT (service_type) DO NOTHING;

-- 11. Insert finding type mappings
INSERT INTO finding_type_mapping (finding_type, attack_type_code, custom_multiplier) VALUES
    -- Cyber findings
    ('VERIFIED_CVE', 'SITE_HACK', 3.0),
    ('VULNERABILITY', 'SITE_HACK', 2.0),
    ('EXPOSED_DATABASE', 'SITE_HACK', 4.0),
    ('DATA_BREACH_EXPOSURE', 'SITE_HACK', 3.5),
    ('CLIENT_SIDE_SECRET_EXPOSURE', 'CLIENT_SIDE_SECRET_EXPOSURE', 2.5),
    ('SENSITIVE_FILE_EXPOSURE', 'SITE_HACK', 2.8),
    ('EXPOSED_SERVICE', 'SITE_HACK', 1.5),
    ('MISSING_RATE_LIMITING', 'SITE_HACK', 1.2),
    ('TLS_CONFIGURATION_ISSUE', 'SITE_HACK', 0.8),
    ('MISSING_TLS_CERTIFICATE', 'SITE_HACK', 1.0),
    ('EMAIL_SECURITY_GAP', 'PHISHING_BEC', 1.5),
    ('MALICIOUS_TYPOSQUAT', 'PHISHING_BEC', 2.0),
    ('PHISHING_INFRASTRUCTURE', 'PHISHING_BEC', 3.0),
    ('ADVERSE_MEDIA', 'SITE_HACK', 1.5),
    
    -- Legal/Compliance findings
    ('ADA_LEGAL_CONTINGENT_LIABILITY', 'ADA_COMPLIANCE', 1.0),
    ('ACCESSIBILITY_VIOLATION', 'ADA_COMPLIANCE', 0.8),
    ('GDPR_VIOLATION', 'GDPR_VIOLATION', 3.0),
    ('PCI_COMPLIANCE_FAILURE', 'PCI_COMPLIANCE_FAILURE', 2.5),
    
    -- Cloud findings
    ('DENIAL_OF_WALLET', 'DENIAL_OF_WALLET', 10.0),
    ('CLOUD_COST_AMPLIFICATION', 'DENIAL_OF_WALLET', 8.0)
ON CONFLICT (finding_type, attack_type_code) DO NOTHING;

-- 12. Create EAL calculation function
CREATE OR REPLACE FUNCTION calculate_finding_eal()
RETURNS TRIGGER AS $$
DECLARE
    base_impact DECIMAL(12,2);
    severity_mult DECIMAL(5,2);
    custom_mult DECIMAL(5,2) := 1.0;
    prevalence_val DECIMAL(3,2) := 1.0;
    raw_weight_val DECIMAL(12,2) := 0;
    low_const DECIMAL(10,4);
    ml_const DECIMAL(10,4);
    high_const DECIMAL(10,4);
    extracted_daily_cost DECIMAL(12,2);
    attack_type TEXT;
BEGIN
    -- Get severity multiplier
    SELECT multiplier INTO severity_mult
    FROM severity_weight
    WHERE severity = NEW.severity;
    
    IF severity_mult IS NULL THEN
        severity_mult := 1.0;
    END IF;
    
    -- Get finding type mapping
    SELECT ftm.attack_type_code, ftm.custom_multiplier, am.raw_weight, am.prevalence
    INTO attack_type, custom_mult, raw_weight_val, prevalence_val
    FROM finding_type_mapping ftm
    JOIN attack_meta am ON ftm.attack_type_code = am.attack_type_code
    WHERE ftm.finding_type = NEW.type
    LIMIT 1;
    
    -- Set attack_type_code
    NEW.attack_type_code := attack_type;
    
    -- Get risk constants
    SELECT value INTO low_const FROM risk_constants WHERE key = 'LOW_CONFIDENCE_CONSTANT';
    SELECT value INTO ml_const FROM risk_constants WHERE key = 'ML_CONFIDENCE_CONSTANT';
    SELECT value INTO high_const FROM risk_constants WHERE key = 'HIGH_CONFIDENCE_CONSTANT';
    
    -- Default constants if not found
    low_const := COALESCE(low_const, 0.2);
    ml_const := COALESCE(ml_const, 1.0);
    high_const := COALESCE(high_const, 4.0);
    
    -- Special case: ADA Compliance fixed amounts
    IF attack_type = 'ADA_COMPLIANCE' THEN
        SELECT value INTO NEW.eal_low FROM risk_constants WHERE key = 'ADA_SETTLEMENT_LOW';
        SELECT value INTO NEW.eal_ml FROM risk_constants WHERE key = 'ADA_SETTLEMENT_ML';
        SELECT value INTO NEW.eal_high FROM risk_constants WHERE key = 'ADA_SETTLEMENT_HIGH';
        NEW.eal_daily := 0;
        RETURN NEW;
    END IF;
    
    -- Special case: Denial of Wallet - extract daily cost from description
    IF attack_type = 'DENIAL_OF_WALLET' AND NEW.description IS NOT NULL THEN
        -- Try to extract "Estimated daily cost: $X" from description
        extracted_daily_cost := (
            SELECT (regexp_matches(NEW.description, '\$([0-9,]+(?:\.[0-9]{2})?)', 'g'))[1]::TEXT
        )::DECIMAL(12,2);
        
        IF extracted_daily_cost IS NOT NULL THEN
            NEW.eal_daily := extracted_daily_cost;
            NEW.eal_low := extracted_daily_cost * 30;    -- 1 month
            NEW.eal_ml := extracted_daily_cost * 90;     -- 3 months
            NEW.eal_high := extracted_daily_cost * 365;  -- 1 year
            RETURN NEW;
        END IF;
    END IF;
    
    -- Calculate base impact
    IF raw_weight_val > 0 THEN
        base_impact := raw_weight_val * severity_mult * custom_mult * prevalence_val;
    ELSE
        -- Fallback base values by severity
        CASE NEW.severity
            WHEN 'CRITICAL' THEN base_impact := 250000 * custom_mult;
            WHEN 'HIGH' THEN base_impact := 50000 * custom_mult;
            WHEN 'MEDIUM' THEN base_impact := 10000 * custom_mult;
            WHEN 'LOW' THEN base_impact := 2500 * custom_mult;
            ELSE base_impact := 0;
        END CASE;
    END IF;
    
    -- Calculate EAL values
    NEW.eal_low := base_impact * low_const;
    NEW.eal_ml := base_impact * ml_const;
    NEW.eal_high := base_impact * high_const;
    
    -- Calculate daily EAL
    CASE NEW.severity
        WHEN 'CRITICAL' THEN NEW.eal_daily := 10000 * custom_mult;
        WHEN 'HIGH' THEN NEW.eal_daily := 2500 * custom_mult;
        WHEN 'MEDIUM' THEN NEW.eal_daily := 500 * custom_mult;
        WHEN 'LOW' THEN NEW.eal_daily := 100 * custom_mult;
        ELSE NEW.eal_daily := 0;
    END CASE;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 13. Create triggers for automatic EAL calculation
DROP TRIGGER IF EXISTS calculate_eal_on_insert ON findings;
DROP TRIGGER IF EXISTS calculate_eal_on_update ON findings;

CREATE TRIGGER calculate_eal_on_insert
    BEFORE INSERT ON findings
    FOR EACH ROW
    EXECUTE FUNCTION calculate_finding_eal();

CREATE TRIGGER calculate_eal_on_update
    BEFORE UPDATE ON findings
    FOR EACH ROW
    WHEN (OLD.type IS DISTINCT FROM NEW.type OR OLD.severity IS DISTINCT FROM NEW.severity)
    EXECUTE FUNCTION calculate_finding_eal();

-- 14. Create scan EAL summary view
CREATE OR REPLACE VIEW scan_eal_summary AS
SELECT 
    scan_id,
    COUNT(*) as total_findings,
    COUNT(eal_ml) as findings_with_eal,
    SUM(eal_low) as total_eal_low,
    SUM(eal_ml) as total_eal_ml,
    SUM(eal_high) as total_eal_high,
    SUM(eal_daily) as total_eal_daily,
    AVG(eal_ml) as avg_eal_ml,
    MAX(eal_ml) as max_eal_ml,
    
    -- Aggregate by attack category
    SUM(CASE WHEN am.category = 'CYBER' THEN eal_ml ELSE 0 END) as cyber_total_ml,
    SUM(CASE WHEN am.category = 'LEGAL' THEN eal_ml ELSE 0 END) as legal_total_ml,
    SUM(CASE WHEN am.category = 'CLOUD' THEN eal_ml ELSE 0 END) as cloud_total_ml,
    
    -- Top attack types
    SUM(CASE WHEN attack_type_code = 'PHISHING_BEC' THEN eal_ml ELSE 0 END) as phishing_bec_ml,
    SUM(CASE WHEN attack_type_code = 'SITE_HACK' THEN eal_ml ELSE 0 END) as site_hack_ml,
    SUM(CASE WHEN attack_type_code = 'ADA_COMPLIANCE' THEN eal_ml ELSE 0 END) as ada_compliance_ml,
    SUM(CASE WHEN attack_type_code = 'DENIAL_OF_WALLET' THEN eal_daily ELSE 0 END) as dow_daily_ml
    
FROM findings f
LEFT JOIN finding_type_mapping ftm ON f.type = ftm.finding_type
LEFT JOIN attack_meta am ON ftm.attack_type_code = am.attack_type_code
GROUP BY scan_id;

-- 15. Update existing findings with EAL calculations
UPDATE findings SET type = type WHERE id = id;

COMMIT;