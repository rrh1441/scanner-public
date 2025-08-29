-- Create the missing scan_eal_summary view for report generation
DROP VIEW IF EXISTS scan_eal_summary;
CREATE VIEW scan_eal_summary AS
SELECT 
    s.id as scan_id,
    s.domain,
    s.status,
    s.created_at,
    s.completed_at,
    s.findings_count,
    
    -- Base EAL calculation
    COALESCE(
        (SELECT SUM(sw.multiplier * 25000)
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity
         WHERE f.scan_id = s.id), 0
    ) as base_eal,
    
    -- Template-expected EAL fields with confidence multipliers (cast to integer)
    COALESCE(
        (SELECT ROUND(SUM(sw.multiplier * 25000 * 0.2))::INTEGER  -- Conservative (20%)
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity
         WHERE f.scan_id = s.id), 0
    ) as total_eal_low,
    
    COALESCE(
        (SELECT ROUND(SUM(sw.multiplier * 25000 * 1.0))::INTEGER  -- Most Likely (100%)
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity
         WHERE f.scan_id = s.id), 0
    ) as total_eal_ml,
    
    COALESCE(
        (SELECT ROUND(SUM(sw.multiplier * 25000 * 4.0))::INTEGER  -- Worst Case (400%)
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity
         WHERE f.scan_id = s.id), 0
    ) as total_eal_high,
    
    -- Category breakdowns (cyber security focused)
    COALESCE(
        (SELECT ROUND(SUM(sw.multiplier * 25000 * 1.0))::INTEGER
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity
         WHERE f.scan_id = s.id), 0
    ) as cyber_total_ml,
    
    -- Daily exposure (annual / 365)
    COALESCE(
        (SELECT ROUND(SUM(sw.multiplier * 25000 * 1.0 / 365))::INTEGER
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity
         WHERE f.scan_id = s.id), 0
    ) as total_eal_daily,
    
    -- Risk score based on findings
    COALESCE(
        (SELECT AVG(sw.multiplier * 100) 
         FROM findings f 
         JOIN severity_weight sw ON f.severity = sw.severity 
         WHERE f.scan_id = s.id), 0
    ) as risk_score,
    
    -- Count by severity
    (SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity = 'CRITICAL') as critical_count,
    (SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity = 'HIGH') as high_count,
    (SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity = 'MEDIUM') as medium_count,
    (SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity = 'LOW') as low_count,
    (SELECT COUNT(*) FROM findings WHERE scan_id = s.id AND severity = 'INFO') as info_count
FROM scans s;

-- Test the view
SELECT scan_id, domain, findings_count, total_eal_ml, total_eal_high FROM scan_eal_summary LIMIT 5;