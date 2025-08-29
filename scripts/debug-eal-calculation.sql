-- Debug EAL Calculation Issues

-- 1. Check if triggers exist
SELECT 
    trigger_name,
    event_manipulation,
    action_timing
FROM information_schema.triggers
WHERE event_object_table = 'findings'
AND trigger_schema = 'public'
ORDER BY trigger_name;

-- 2. Check severity_weight values
SELECT * FROM severity_weight ORDER BY severity;

-- 3. Check risk_constants for ADA
SELECT * FROM risk_constants 
WHERE key IN ('ADA_MIN_SETTLEMENT', 'ADA_AVG_SETTLEMENT', 'ADA_MAX_SETTLEMENT');

-- 4. Check attack_meta values
SELECT attack_type_code, prevalence, raw_weight, category 
FROM attack_meta 
WHERE attack_type_code IN ('PHISHING_BEC', 'CERTIFICATE_ATTACK', 'TYPOSQUAT', 'ADA_COMPLIANCE')
ORDER BY attack_type_code;

-- 5. Check finding_type_mapping
SELECT * FROM finding_type_mapping 
WHERE finding_type IN ('EMAIL_SECURITY_GAP', 'TLS_CONFIGURATION_ISSUE', 'PARKED_TYPOSQUAT', 'ADA_LEGAL_CONTINGENT_LIABILITY');

-- 6. Test the function directly on a sample finding
SELECT 
    finding_type,
    attack_type_code,
    severity,
    eal_low,
    eal_ml,
    eal_high,
    eal_daily
FROM findings 
WHERE id = 77;

-- 7. Force recalculation on one finding to test
UPDATE findings 
SET eal_ml = NULL 
WHERE id = 77;

-- Check if it recalculated
SELECT 
    finding_type,
    attack_type_code,
    severity,
    eal_low,
    eal_ml,
    eal_high,
    eal_daily
FROM findings 
WHERE id = 77;