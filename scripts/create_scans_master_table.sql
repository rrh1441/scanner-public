-- scripts/create_scans_master_table.sql
-- Create scans_master table for tracking scan status
CREATE TABLE IF NOT EXISTS scans_master (
    scan_id VARCHAR(255) PRIMARY KEY,
    company_name VARCHAR(255),
    domain VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'queued', -- e.g., 'queued', 'processing', 'analyzing_modules', 'done', 'failed', 'module_failed'
    progress INTEGER DEFAULT 0,
    current_module VARCHAR(100),
    total_modules INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    total_findings_count INTEGER DEFAULT 0,
    max_severity VARCHAR(20)
);

-- Trigger to update 'updated_at' timestamp automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ language 'plpgsql';

-- Drop trigger if it exists, then recreate
DROP TRIGGER IF EXISTS update_scans_master_updated_at ON scans_master;
CREATE TRIGGER update_scans_master_updated_at
BEFORE UPDATE ON scans_master
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scans_master_updated_at ON scans_master(updated_at);
CREATE INDEX IF NOT EXISTS idx_scans_master_status ON scans_master(status);
-- Note: idx_findings_created_at is for the 'findings' table, ensure it's created there if needed.