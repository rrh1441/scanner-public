-- Create separated risk calculation view with three distinct categories
DROP VIEW IF EXISTS scan_eal_summary;
CREATE VIEW scan_eal_summary AS
SELECT 
    s.id as scan_id,
    s.domain,
    s.status,
    s.created_at,
    s.completed_at,
    s.findings_count,
    
    -- 1. EAL (Annual) - Only for breach/ransomware/cyber attacks
    -- Excludes compliance (ADA) and cloud abuse findings
    COALESCE(
        (SELECT ROUND(SUM(
            CASE 
                WHEN f.type IN ('PASSWORD_BREACH_EXPOSURE', 'CRITICAL_BREACH_EXPOSURE', 'EMAIL_BREACH_EXPOSURE', 
                               'EMAIL_SECURITY_MISCONFIGURATION', 'TECHNOLOGY_RISK', 'EMAIL_SECURITY_GAP')
                THEN sw.multiplier * 25000 * 0.05  -- 5% annual breach probability
                ELSE 0
            END
        ))::INTEGER
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity
         WHERE f.scan_id = s.id), 0
    ) as total_eal_ml,
    
    -- 2. Daily Cloud Risk - For denial-of-wallet/resource abuse
    -- No probability calculation - raw exposure amount per day
    COALESCE(
        (SELECT ROUND(SUM(
            CASE 
                WHEN f.type LIKE '%DENIAL%' OR f.type LIKE '%WALLET%' OR f.type LIKE '%RESOURCE%'
                THEN sw.multiplier * 10000  -- $10K base daily exposure per severity level
                ELSE 0
            END
        ))::INTEGER
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity
         WHERE f.scan_id = s.id), 0
    ) as daily_cloud_risk,
    
    -- 3. Compliance Risk - Tranche-based caps ($25K, $50K, $75K)
    -- No probability or timeline - just the cost if it happens
    COALESCE(
        (SELECT 
            CASE 
                WHEN MAX(CASE WHEN (f.attack_type_code = 'ADA_COMPLIANCE' OR f.type = 'ACCESSIBILITY_VIOLATION') AND f.severity = 'HIGH' THEN 1 ELSE 0 END) = 1 
                THEN 75000  -- $75K for HIGH severity compliance issues
                WHEN MAX(CASE WHEN (f.attack_type_code = 'ADA_COMPLIANCE' OR f.type = 'ACCESSIBILITY_VIOLATION') AND f.severity = 'MEDIUM' THEN 1 ELSE 0 END) = 1 
                THEN 50000  -- $50K for MEDIUM severity compliance issues
                WHEN MAX(CASE WHEN (f.attack_type_code = 'ADA_COMPLIANCE' OR f.type = 'ACCESSIBILITY_VIOLATION') AND f.severity = 'LOW' THEN 1 ELSE 0 END) = 1 
                THEN 25000  -- $25K for LOW severity compliance issues
                ELSE 0
            END
         FROM findings f 
         WHERE f.scan_id = s.id), 0
    ) as compliance_risk,
    
    -- Legacy fields for compatibility (now represent only cyber risk)
    COALESCE(
        (SELECT ROUND(SUM(
            CASE 
                WHEN f.type IN ('PASSWORD_BREACH_EXPOSURE', 'CRITICAL_BREACH_EXPOSURE', 'EMAIL_BREACH_EXPOSURE', 
                               'EMAIL_SECURITY_MISCONFIGURATION', 'TECHNOLOGY_RISK', 'EMAIL_SECURITY_GAP')
                THEN sw.multiplier * 25000 * 0.02  -- Conservative 2%
                ELSE 0
            END
        ))::INTEGER
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity
         WHERE f.scan_id = s.id), 0
    ) as total_eal_low,
    
    COALESCE(
        (SELECT ROUND(SUM(
            CASE 
                WHEN f.type IN ('PASSWORD_BREACH_EXPOSURE', 'CRITICAL_BREACH_EXPOSURE', 'EMAIL_BREACH_EXPOSURE', 
                               'EMAIL_SECURITY_MISCONFIGURATION', 'TECHNOLOGY_RISK', 'EMAIL_SECURITY_GAP')
                THEN sw.multiplier * 25000 * 0.15  -- Worst case 15%
                ELSE 0
            END
        ))::INTEGER
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity
         WHERE f.scan_id = s.id), 0
    ) as total_eal_high,
    
    -- Risk breakdown by category
    COALESCE(
        (SELECT COUNT(*)
         FROM findings f 
         WHERE f.scan_id = s.id 
         AND f.type IN ('PASSWORD_BREACH_EXPOSURE', 'CRITICAL_BREACH_EXPOSURE', 'EMAIL_BREACH_EXPOSURE', 
                        'EMAIL_SECURITY_MISCONFIGURATION', 'TECHNOLOGY_RISK', 'EMAIL_SECURITY_GAP')), 0
    ) as cyber_findings_count,
    
    COALESCE(
        (SELECT COUNT(*)
         FROM findings f 
         WHERE f.scan_id = s.id 
         AND (f.type LIKE '%DENIAL%' OR f.type LIKE '%WALLET%' OR f.type LIKE '%RESOURCE%')), 0
    ) as cloud_findings_count,
    
    COALESCE(
        (SELECT COUNT(*)
         FROM findings f 
         WHERE f.scan_id = s.id 
         AND (f.attack_type_code = 'ADA_COMPLIANCE' OR f.type = 'ACCESSIBILITY_VIOLATION')), 0
    ) as compliance_findings_count,
    
    -- Count by severity (unchanged)
    (SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity = 'CRITICAL') as critical_count,
    (SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity = 'HIGH') as high_count,
    (SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity = 'MEDIUM') as medium_count,
    (SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity = 'LOW') as low_count,
    (SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity = 'INFO') as info_count,
    
    -- Total daily exposure (legacy compatibility)
    COALESCE(
        (SELECT ROUND(SUM(
            CASE 
                WHEN f.type IN ('PASSWORD_BREACH_EXPOSURE', 'CRITICAL_BREACH_EXPOSURE', 'EMAIL_BREACH_EXPOSURE', 
                               'EMAIL_SECURITY_MISCONFIGURATION', 'TECHNOLOGY_RISK', 'EMAIL_SECURITY_GAP')
                THEN sw.multiplier * 25000 * 0.05 / 365  -- Annual EAL / 365
                ELSE 0
            END
        ))::INTEGER
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity
         WHERE f.scan_id = s.id), 0
    ) as total_eal_daily,
    
    -- Risk score (cyber only)
    COALESCE(
        (SELECT AVG(sw.multiplier * 100) 
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity 
         WHERE f.scan_id = s.id 
         AND f.type IN ('PASSWORD_BREACH_EXPOSURE', 'CRITICAL_BREACH_EXPOSURE', 'EMAIL_BREACH_EXPOSURE', 
                        'EMAIL_SECURITY_MISCONFIGURATION', 'TECHNOLOGY_RISK', 'EMAIL_SECURITY_GAP')), 0
    ) as risk_score
FROM scans s;

-- Test the new separated risk calculations
SELECT 
    scan_id, 
    domain, 
    total_eal_ml as cyber_eal, 
    daily_cloud_risk, 
    compliance_risk,
    cyber_findings_count,
    compliance_findings_count
FROM scan_eal_summary 
WHERE created_at >= CURRENT_DATE 
ORDER BY total_eal_ml DESC 
LIMIT 10;