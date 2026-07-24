-- ====================================================================
-- SUPABASE POSTGRESQL SCHEMA FOR INSIDER THREAT BATCH REVIEW CYCLES
-- Copy and run this script in your Supabase SQL Editor
-- ====================================================================

-- 1. Create insider_threat_profiles table
CREATE TABLE IF NOT EXISTS public.insider_threat_profiles (
  employee_id TEXT PRIMARY KEY,
  employee_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  role TEXT,
  department TEXT,
  authorized_device_details TEXT,
  normal_working_time TEXT,
  normal_location TEXT,
  normal_ip_address TEXT,
  total_transactions_processed INTEGER DEFAULT 0,
  total_transactions_accepted INTEGER DEFAULT 0,
  total_transactions_rejected INTEGER DEFAULT 0,
  average_transaction_amount NUMERIC DEFAULT 0,
  maximum_transaction_amount NUMERIC DEFAULT 0,
  average_accounts_accessed_per_day NUMERIC DEFAULT 0,
  maximum_accounts_accessed_per_day INTEGER DEFAULT 0,
  total_data_downloaded TEXT DEFAULT '150 MB',
  total_data_exported TEXT DEFAULT '25 MB',
  authorized_departments TEXT DEFAULT '["Fraud Operations", "Risk Management"]',
  authorized_resources TEXT DEFAULT '["Analyst Portal", "High Risk Sessions"]',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Create analyst_decisions table
CREATE TABLE IF NOT EXISTS public.analyst_decisions (
  id TEXT PRIMARY KEY,
  analyst_id TEXT NOT NULL,
  analyst_name TEXT NOT NULL,
  analyst_email TEXT NOT NULL,
  session_id TEXT NOT NULL,
  transaction_id TEXT,
  user_id TEXT,
  threat_type TEXT DEFAULT 'BEHAVIORAL_FRAUD',
  risk_score NUMERIC DEFAULT 0,
  decision TEXT NOT NULL,
  decision_reason TEXT NOT NULL,
  analyst_notes TEXT,
  previous_status TEXT,
  new_status TEXT,
  insider_event_id TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Create review_cycles table (Stores completed batch review sessions)
CREATE TABLE IF NOT EXISTS public.review_cycles (
  review_cycle_id TEXT PRIMARY KEY,
  analyst_id TEXT NOT NULL,
  analyst_email TEXT NOT NULL,
  start_time TIMESTAMPTZ NOT NULL,
  completion_time TIMESTAMPTZ NOT NULL,
  total_transactions_reviewed INTEGER NOT NULL,
  total_approved INTEGER NOT NULL,
  total_rejected INTEGER NOT NULL,
  review_duration_seconds INTEGER DEFAULT 0,
  avg_time_per_transaction_seconds NUMERIC DEFAULT 0,
  avg_amount_reviewed NUMERIC DEFAULT 0,
  max_amount_reviewed NUMERIC DEFAULT 0,
  ip_address TEXT,
  location TEXT,
  device TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Create insider_threat_analyses table (Stores results of completed batch analyses)
CREATE TABLE IF NOT EXISTS public.insider_threat_analyses (
  analysis_id TEXT PRIMARY KEY,
  review_cycle_id TEXT NOT NULL,
  analyst_id TEXT NOT NULL,
  analyst_email TEXT NOT NULL,
  is_learning_mode BOOLEAN DEFAULT FALSE,
  historical_cycles_count INTEGER DEFAULT 0,
  historical_baseline JSONB,
  current_cycle_metrics JSONB,
  detected_deviations JSONB,
  risk_score NUMERIC DEFAULT 0,
  risk_level TEXT NOT NULL,
  threat_percentage INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. DISABLE RLS & GRANT API PRIVILEGES
ALTER TABLE public.analyst_decisions DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.insider_threat_profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.review_cycles DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.insider_threat_analyses DISABLE ROW LEVEL SECURITY;

GRANT ALL ON TABLE public.analyst_decisions TO anon, authenticated, service_role;
GRANT ALL ON TABLE public.insider_threat_profiles TO anon, authenticated, service_role;
GRANT ALL ON TABLE public.review_cycles TO anon, authenticated, service_role;
GRANT ALL ON TABLE public.insider_threat_analyses TO anon, authenticated, service_role;

-- 6. Seed Initial 10 Analyst Baseline Profiles into insider_threat_profiles
INSERT INTO public.insider_threat_profiles (
  employee_id, employee_name, email, role, department, authorized_device_details,
  normal_working_time, normal_location, normal_ip_address,
  total_transactions_processed, total_transactions_accepted, total_transactions_rejected,
  average_transaction_amount, maximum_transaction_amount,
  average_accounts_accessed_per_day, maximum_accounts_accessed_per_day,
  total_data_downloaded, total_data_exported, authorized_departments, authorized_resources
) VALUES
('ANL-001001', 'Analyzer 01', 'analyzer1@gmail.com', 'Senior Fraud Investigator', 'Fraud Operations', 'Chrome 122 on Windows 11 Workstation', '09:00 AM - 06:00 PM EST', 'New York, US', '192.168.1.101', 0, 0, 0, 15000.00, 50000.00, 12, 25, '150 MB', '25 MB', '["Fraud Operations", "Risk Management"]', '["Analyst Portal", "High Risk Sessions"]'),
('ANL-001002', 'Analyzer 02', 'analyzer2@gmail.com', 'SOC Risk Lead', 'Risk Intelligence', 'Safari on macOS Sonoma Workstation', '08:00 AM - 05:00 PM EST', 'New York, US', '192.168.1.102', 0, 0, 0, 18000.00, 75000.00, 15, 30, '210 MB', '30 MB', '["Risk Intelligence", "Cyber Defense"]', '["Analyst Portal", "High Risk Sessions"]'),
('ANL-001003', 'Analyzer 03', 'analyzer3@gmail.com', 'Behavioral Fraud Specialist', 'Behavioral Analytics', 'Edge on Windows 11 Workstation', '09:30 AM - 06:30 PM EST', 'Chicago, US', '192.168.1.103', 0, 0, 0, 12000.00, 40000.00, 10, 20, '120 MB', '15 MB', '["Behavioral Analytics", "Fraud Operations"]', '["Analyst Portal", "Telemetry Engine"]'),
('ANL-001004', 'Analyzer 04', 'analyzer4@gmail.com', 'AML & Money Laundering Analyst', 'AML Compliance', 'Firefox on Linux Ubuntu Workstation', '09:00 AM - 06:00 PM EST', 'Charlotte, US', '192.168.1.104', 0, 0, 0, 25000.00, 100000.00, 18, 35, '300 MB', '45 MB', '["AML Compliance", "Legal"]', '["Analyst Portal", "High Risk Sessions"]'),
('ANL-001005', 'Analyzer 05', 'analyzer5@gmail.com', 'Session Hijacking Investigator', 'Cyber Security', 'Chrome on macOS Sonoma Workstation', '10:00 AM - 07:00 PM EST', 'San Francisco, US', '192.168.1.105', 0, 0, 0, 14000.00, 45000.00, 11, 22, '175 MB', '20 MB', '["Cyber Security", "Fraud Operations"]', '["Analyst Portal", "Session Tracker"]'),
('ANL-001006', 'Analyzer 06', 'analyzer6@gmail.com', 'Cyber Risk Operations Officer', 'Risk Operations', 'Edge on Windows 11 Enterprise', '08:30 AM - 05:30 PM EST', 'Dallas, US', '192.168.1.106', 0, 0, 0, 16500.00, 60000.00, 14, 28, '190 MB', '28 MB', '["Risk Operations", "Fraud Operations"]', '["Analyst Portal", "High Risk Sessions"]'),
('ANL-001007', 'Analyzer 07', 'analyzer7@gmail.com', 'Identity & Authentication Specialist', 'Identity Security', 'Safari on macOS Sonoma Workstation', '09:00 AM - 06:00 PM EST', 'Boston, US', '192.168.1.107', 0, 0, 0, 13500.00, 42000.00, 13, 24, '160 MB', '18 MB', '["Identity Security", "IAM Team"]', '["Analyst Portal", "Authentication Logs"]'),
('ANL-001008', 'Analyzer 08', 'analyzer8@gmail.com', 'Forensic Audit Investigator', 'Internal Audit', 'Chrome on Windows 11 Enterprise', '09:00 AM - 06:00 PM EST', 'New York, US', '192.168.1.108', 0, 0, 0, 22000.00, 90000.00, 20, 40, '350 MB', '50 MB', '["Internal Audit", "Executive"]', '["Analyst Portal", "Forensic Audit Log"]'),
('ANL-001009', 'Analyzer 09', 'analyzer9@gmail.com', 'Risk Engine Rule Engineer', 'Risk Engineering', 'Firefox on Linux Fedora Workstation', '10:00 AM - 07:00 PM EST', 'Seattle, US', '192.168.1.109', 0, 0, 0, 11000.00, 35000.00, 9, 18, '140 MB', '12 MB', '["Risk Engineering", "Platform Dev"]', '["Analyst Portal", "Risk Rules"]'),
('ANL-001010', 'Analyzer 10', 'analyzer10@gmail.com', 'Chief Fraud Intelligence Analyst', 'Fraud Operations Command', 'Chrome on macOS M3 Max Workstation', '08:00 AM - 06:00 PM EST', 'New York, US', '192.168.1.110', 0, 0, 0, 30000.00, 150000.00, 25, 50, '500 MB', '75 MB', '["Executive Command", "Fraud Operations"]', '["Analyst Portal", "Command Center"]')
ON CONFLICT (employee_id) DO NOTHING;
