-- Check existing table structures
-- Run this first to see what columns exist

-- Check attack_meta structure
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name = 'attack_meta'
ORDER BY ordinal_position;

-- Check risk_constants structure
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name = 'risk_constants'
ORDER BY ordinal_position;

-- Check if severity_weight exists and its structure
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name = 'severity_weight'
ORDER BY ordinal_position;

-- Check what tables exist
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name IN ('attack_meta', 'risk_constants', 'severity_weight', 'finding_type_mapping', 'dow_cost_constants')
ORDER BY table_name;