-- ====================================================================
-- SUPABASE POSTGRESQL SCHEMA FOR MONEY MULE INTELLIGENCE ENGINE (MMIE)
-- Copy and run this script in your Supabase SQL Editor
-- ====================================================================

-- 1. Create mule_posture table
CREATE TABLE IF NOT EXISTS public.mule_posture (
  account_id TEXT PRIMARY KEY,
  posture_score NUMERIC DEFAULT 0,
  hawkes_intensity NUMERIC DEFAULT 0,
  hawkes_last_updated TIMESTAMPTZ,
  retention_half_life_seconds NUMERIC,
  unique_senders_24h INT DEFAULT 0,
  inflow_count_24h INT DEFAULT 0,
  community_id TEXT,
  graph_reputation NUMERIC DEFAULT 0,
  last_updated TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Create entity_edges table
CREATE TABLE IF NOT EXISTS public.entity_edges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_a TEXT NOT NULL,
  account_b TEXT NOT NULL,
  edge_type TEXT CHECK (edge_type IN ('device','ip','phone','address','beneficiary')),
  token_hash TEXT NOT NULL,
  weight NUMERIC DEFAULT 1,
  last_seen TIMESTAMPTZ DEFAULT NOW()
);

-- Unique index to prevent duplicate edges and support ON CONFLICT updates
CREATE UNIQUE INDEX IF NOT EXISTS uidx_entity_edges ON public.entity_edges (account_a, account_b, edge_type, token_hash);

-- 3. Create mule_assessments table
CREATE TABLE IF NOT EXISTS public.mule_assessments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_id TEXT,
  sender_account_id TEXT NOT NULL,
  receiver_account_id TEXT NOT NULL,
  mule_confidence NUMERIC NOT NULL,
  evidence JSONB NOT NULL,
  decision TEXT CHECK (decision IN ('allow','step_up','hold','block')),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Create fraud_reports table
CREATE TABLE IF NOT EXISTS public.fraud_reports (
  account_id TEXT NOT NULL,
  reported_at TIMESTAMPTZ DEFAULT NOW(),
  reason TEXT
);

-- 5. DISABLE RLS & GRANT API PRIVILEGES
ALTER TABLE public.mule_posture DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.entity_edges DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.mule_assessments DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.fraud_reports DISABLE ROW LEVEL SECURITY;

GRANT ALL ON TABLE public.mule_posture TO anon, authenticated, service_role;
GRANT ALL ON TABLE public.entity_edges TO anon, authenticated, service_role;
GRANT ALL ON TABLE public.mule_assessments TO anon, authenticated, service_role;
GRANT ALL ON TABLE public.fraud_reports TO anon, authenticated, service_role;

-- 6. Seed a sample fraud report to demonstrate personalized PageRank
INSERT INTO public.fraud_reports (account_id, reason)
VALUES ('TURTLE-2397733728', 'Confirmed Mule Account - Suspended for suspicious inflows')
ON CONFLICT DO NOTHING;
