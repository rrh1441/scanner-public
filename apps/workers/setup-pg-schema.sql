-- Scanner Local PostgreSQL Schema Setup
-- Run this before starting the scanner

-- Drop existing tables if they exist
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS artifacts CASCADE;
DROP TABLE IF EXISTS scans CASCADE;

-- Create scans table
CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  completed_at TIMESTAMP,
  findings_count INTEGER DEFAULT 0,
  artifacts_count INTEGER DEFAULT 0,
  duration_ms INTEGER,
  metadata JSONB
);

-- Create findings table
CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  type TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  data JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (scan_id) REFERENCES scans (id)
);

-- Create artifacts table
CREATE TABLE artifacts (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  type TEXT NOT NULL,
  file_path TEXT NOT NULL,
  size_bytes INTEGER,
  severity TEXT,
  val_text TEXT,
  src_url TEXT,
  sha256 TEXT,
  mime_type TEXT,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (scan_id) REFERENCES scans (id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_scan_id ON artifacts(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

-- Verify tables created
SELECT 'Tables created successfully!' as status;
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';