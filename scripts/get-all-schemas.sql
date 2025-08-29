-- Comprehensive schema query to understand existing structure

-- 1. List all tables that might be related to EAL/cost calculation
SELECT 
    'TABLES:' as section,
    table_name,
    table_type
FROM information_schema.tables 
WHERE table_schema = 'public' 
AND (
    table_name LIKE '%attack%' 
    OR table_name LIKE '%risk%' 
    OR table_name LIKE '%severity%' 
    OR table_name LIKE '%eal%'
    OR table_name LIKE '%cost%'
    OR table_name LIKE '%finding%'
    OR table_name IN ('attack_meta', 'risk_constants', 'severity_weight', 'finding_type_mapping', 'dow_cost_constants')
)
ORDER BY table_name;

-- 2. Get attack_meta columns if it exists
SELECT 
    'ATTACK_META COLUMNS:' as section,
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name = 'attack_meta'
ORDER BY ordinal_position;

-- 3. Get risk_constants columns if it exists
SELECT 
    'RISK_CONSTANTS COLUMNS:' as section,
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name = 'risk_constants'
ORDER BY ordinal_position;

-- 4. Get severity_weight columns if it exists  
SELECT 
    'SEVERITY_WEIGHT COLUMNS:' as section,
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name = 'severity_weight'
ORDER BY ordinal_position;

-- 5. Get findings table EAL-related columns
SELECT 
    'FINDINGS EAL COLUMNS:' as section,
    column_name,
    data_type,
    is_nullable
FROM information_schema.columns 
WHERE table_schema = 'public' 
AND table_name = 'findings'
AND (column_name LIKE '%eal%' OR column_name = 'attack_type_code')
ORDER BY ordinal_position;

-- 6. Check for any existing EAL calculation functions
SELECT 
    'FUNCTIONS:' as section,
    routine_name,
    routine_type
FROM information_schema.routines
WHERE routine_schema = 'public'
AND (routine_name LIKE '%eal%' OR routine_name LIKE '%calculate%finding%')
ORDER BY routine_name;

-- 7. Check for any existing triggers on findings table
SELECT 
    'TRIGGERS:' as section,
    trigger_name,
    event_manipulation,
    action_timing
FROM information_schema.triggers
WHERE event_object_table = 'findings'
AND trigger_schema = 'public'
ORDER BY trigger_name;

-- 8. Sample data from attack_meta if it exists
SELECT 
    'ATTACK_META SAMPLE DATA:' as section,
    attack_type_code,
    prevalence,
    raw_weight
FROM public.attack_meta
LIMIT 5;

-- 9. Sample data from risk_constants if it exists
SELECT 
    'RISK_CONSTANTS SAMPLE DATA:' as section,
    key,
    value
FROM public.risk_constants
WHERE key IN ('LOW_CONFIDENCE', 'ML_CONFIDENCE', 'HIGH_CONFIDENCE', 'ADA_MIN_SETTLEMENT', 'ADA_AVG_SETTLEMENT', 'ADA_MAX_SETTLEMENT')
LIMIT 10;