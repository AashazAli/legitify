-- ==============================================================================
-- LEGITIFY: Production Database Schema & RLS Policies (Idempotent & Safe)
-- ==============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. PROFILES TABLE (Mirrors auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT,
  full_name TEXT,
  avatar_url TEXT,
  role TEXT DEFAULT 'user' CHECK (role IN ('user', 'analyst', 'admin')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Ensure all profile columns exist if table was already present
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS full_name TEXT;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS avatar_url TEXT;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';

-- Trigger to automatically create profile on auth.user creation
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, full_name, avatar_url, role)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
    COALESCE(NEW.raw_user_meta_data->>'avatar_url', NEW.raw_user_meta_data->>'picture', ''),
    'user'
  )
  ON CONFLICT (id) DO UPDATE
  SET
    email = EXCLUDED.email,
    full_name = COALESCE(EXCLUDED.full_name, profiles.full_name),
    avatar_url = COALESCE(EXCLUDED.avatar_url, profiles.avatar_url),
    updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT OR UPDATE ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 2. SCANS TABLE
CREATE TABLE IF NOT EXISTS public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL DEFAULT 'company',
  entity_value TEXT NOT NULL DEFAULT '',
  normalized_entity_name TEXT,
  email TEXT,
  domain TEXT,
  website TEXT,
  status TEXT NOT NULL DEFAULT 'QUEUED',
  trust_score INTEGER,
  confidence_score NUMERIC(5,2),
  risk_level TEXT,
  verdict TEXT,
  metadata JSONB DEFAULT '{}'::JSONB,
  error_message TEXT,
  started_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Ensure all scans columns exist if table was already present
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS normalized_entity_name TEXT;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS domain TEXT;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS website TEXT;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'QUEUED';
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS trust_score INTEGER;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS confidence_score NUMERIC(5,2);
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS risk_level TEXT;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS verdict TEXT;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::JSONB;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS error_message TEXT;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;

-- 3. SCAN INPUTS (Private User Submissions)
CREATE TABLE IF NOT EXISTS public.scan_inputs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  input_type TEXT NOT NULL,
  original_filename TEXT,
  mime_type TEXT,
  file_size INTEGER,
  storage_path TEXT,
  content_hash TEXT,
  extracted_text TEXT,
  metadata JSONB DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. COMPANIES (Shared Public/Registry Directory)
CREATE TABLE IF NOT EXISTS public.companies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  normalized_name TEXT UNIQUE NOT NULL,
  legal_name TEXT,
  registration_number TEXT,
  country TEXT DEFAULT 'India',
  state TEXT,
  city TEXT,
  website TEXT,
  domain TEXT,
  status TEXT DEFAULT 'ACTIVE',
  registry_status TEXT DEFAULT 'NOT_INDEPENDENTLY_VERIFIED',
  trust_score INTEGER,
  risk_level TEXT,
  registered_address TEXT,
  source TEXT,
  source_url TEXT,
  last_verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. COMPANY ALIASES
CREATE TABLE IF NOT EXISTS public.company_aliases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id UUID NOT NULL REFERENCES public.companies(id) ON DELETE CASCADE,
  alias TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. COMPANY INTELLIGENCE CACHE (Sanitized Shared Evidence)
CREATE TABLE IF NOT EXISTS public.company_intelligence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  company_id UUID NOT NULL REFERENCES public.companies(id) ON DELETE CASCADE,
  category TEXT,
  source TEXT NOT NULL,
  source_url TEXT,
  title TEXT,
  content_summary TEXT,
  evidence_type TEXT,
  evidence JSONB DEFAULT '{}'::JSONB,
  confidence NUMERIC(5,2) DEFAULT 100.0,
  observed_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 7. DOMAINS INTELLIGENCE
CREATE TABLE IF NOT EXISTS public.domains (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  domain TEXT UNIQUE NOT NULL,
  normalized_domain TEXT,
  company_id UUID REFERENCES public.companies(id) ON DELETE SET NULL,
  registrar TEXT,
  registration_date TIMESTAMPTZ,
  expiration_date TIMESTAMPTZ,
  domain_age_days INTEGER,
  nameservers TEXT[],
  ssl_valid BOOLEAN DEFAULT FALSE,
  ssl_issuer TEXT,
  reputation_score INTEGER,
  threat_status TEXT DEFAULT 'CLEAN',
  lookalike_detected BOOLEAN DEFAULT FALSE,
  source_data JSONB DEFAULT '{}'::JSONB,
  last_checked_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 8. RECRUITERS INTELLIGENCE
CREATE TABLE IF NOT EXISTS public.recruiters (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  normalized_email TEXT,
  display_name TEXT,
  company_id UUID REFERENCES public.companies(id) ON DELETE SET NULL,
  domain TEXT,
  domain_alignment TEXT DEFAULT 'UNKNOWN',
  email_authentication JSONB DEFAULT '{}'::JSONB,
  reputation_score INTEGER,
  known_scam BOOLEAN DEFAULT FALSE,
  source_data JSONB DEFAULT '{}'::JSONB,
  last_checked_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 9. EVIDENCE TABLE (Granular Findings for a Scan)
CREATE TABLE IF NOT EXISTS public.evidence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  evidence_type TEXT,
  source_name TEXT NOT NULL,
  source_url TEXT,
  title TEXT NOT NULL,
  snippet TEXT,
  evidence_text TEXT,
  evidence_strength TEXT DEFAULT 'MEDIUM',
  status TEXT DEFAULT 'VERIFIED',
  severity TEXT DEFAULT 'INFO',
  verified BOOLEAN DEFAULT FALSE,
  confidence NUMERIC(5,2) DEFAULT 100.0,
  raw_reference TEXT,
  collected_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 10. REPORTS TABLE
CREATE TABLE IF NOT EXISTS public.reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID UNIQUE NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  summary TEXT,
  verdict TEXT NOT NULL,
  trust_score INTEGER NOT NULL,
  risk_level TEXT NOT NULL,
  confidence NUMERIC(5,2) NOT NULL,
  report_json JSONB NOT NULL,
  share_token TEXT UNIQUE,
  shared_at TIMESTAMPTZ,
  is_public BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 11. THREAT INDICATORS TABLE
CREATE TABLE IF NOT EXISTS public.threat_indicators (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  indicator_type TEXT NOT NULL,
  indicator_value TEXT NOT NULL,
  normalized_value TEXT NOT NULL,
  threat_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  source TEXT NOT NULL,
  source_url TEXT,
  description TEXT,
  confidence NUMERIC(5,2) DEFAULT 100.0,
  first_seen TIMESTAMPTZ DEFAULT NOW(),
  last_seen TIMESTAMPTZ DEFAULT NOW(),
  metadata JSONB DEFAULT '{}'::JSONB,
  is_demo BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 12. AUDIT LOGS TABLE
CREATE TABLE IF NOT EXISTS public.audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  ip_hash TEXT,
  user_agent TEXT,
  metadata JSONB DEFAULT '{}'::JSONB,
  risk TEXT DEFAULT 'low',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 13. USER FEEDBACK TABLE
CREATE TABLE IF NOT EXISTS public.feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  rating TEXT NOT NULL,
  comment TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==============================================================================
-- INDEXES FOR MAXIMUM QUERY PERFORMANCE
-- ==============================================================================

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON public.scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_normalized_entity ON public.scans(normalized_entity_name);
CREATE INDEX IF NOT EXISTS idx_scan_inputs_scan_id ON public.scan_inputs(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_inputs_user_id ON public.scan_inputs(user_id);
CREATE INDEX IF NOT EXISTS idx_companies_normalized_name ON public.companies(normalized_name);
CREATE INDEX IF NOT EXISTS idx_company_aliases_company_id ON public.company_aliases(company_id);
CREATE INDEX IF NOT EXISTS idx_company_intelligence_company_id ON public.company_intelligence(company_id);
CREATE INDEX IF NOT EXISTS idx_domains_domain ON public.domains(domain);
CREATE INDEX IF NOT EXISTS idx_domains_normalized ON public.domains(normalized_domain);
CREATE INDEX IF NOT EXISTS idx_recruiters_email ON public.recruiters(email);
CREATE INDEX IF NOT EXISTS idx_recruiters_normalized ON public.recruiters(normalized_email);
CREATE INDEX IF NOT EXISTS idx_evidence_scan_id ON public.evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON public.reports(scan_id);
CREATE INDEX IF NOT EXISTS idx_reports_user_id ON public.reports(user_id);
CREATE INDEX IF NOT EXISTS idx_reports_share_token ON public.reports(share_token);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_normalized ON public.threat_indicators(normalized_value);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_type ON public.threat_indicators(indicator_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON public.audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON public.audit_logs(created_at DESC);

-- ==============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.companies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.company_aliases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.company_intelligence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.recruiters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.feedback ENABLE ROW LEVEL SECURITY;

-- Drop existing policies before creating to avoid duplication errors
DO $$
BEGIN
  DROP POLICY IF EXISTS "Users can read own profile" ON public.profiles;
  DROP POLICY IF EXISTS "Users can update own profile" ON public.profiles;
  DROP POLICY IF EXISTS "Users can read own scans" ON public.scans;
  DROP POLICY IF EXISTS "Users can insert own scans" ON public.scans;
  DROP POLICY IF EXISTS "Users can update own scans" ON public.scans;
  DROP POLICY IF EXISTS "Users can delete own scans" ON public.scans;
  DROP POLICY IF EXISTS "Users can read own scan inputs" ON public.scan_inputs;
  DROP POLICY IF EXISTS "Users can insert own scan inputs" ON public.scan_inputs;
  DROP POLICY IF EXISTS "Users can delete own scan inputs" ON public.scan_inputs;
  DROP POLICY IF EXISTS "Authenticated users can read companies" ON public.companies;
  DROP POLICY IF EXISTS "Authenticated users can read aliases" ON public.company_aliases;
  DROP POLICY IF EXISTS "Authenticated users can read company intelligence" ON public.company_intelligence;
  DROP POLICY IF EXISTS "Authenticated users can read domains" ON public.domains;
  DROP POLICY IF EXISTS "Authenticated users can read recruiters" ON public.recruiters;
  DROP POLICY IF EXISTS "Users can read evidence of own scans" ON public.evidence;
  DROP POLICY IF EXISTS "Users can read own reports" ON public.reports;
  DROP POLICY IF EXISTS "Users can insert own reports" ON public.reports;
  DROP POLICY IF EXISTS "Users can update own reports" ON public.reports;
  DROP POLICY IF EXISTS "Users can delete own reports" ON public.reports;
  DROP POLICY IF EXISTS "Authenticated users can read threat indicators" ON public.threat_indicators;
  DROP POLICY IF EXISTS "Users can read own audit logs" ON public.audit_logs;
  DROP POLICY IF EXISTS "Users can insert own audit logs" ON public.audit_logs;
  DROP POLICY IF EXISTS "Users can read own feedback" ON public.feedback;
  DROP POLICY IF EXISTS "Users can insert own feedback" ON public.feedback;
END $$;

-- Profiles
CREATE POLICY "Users can read own profile" ON public.profiles
  FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON public.profiles
  FOR UPDATE USING (auth.uid() = id);

-- Scans
CREATE POLICY "Users can read own scans" ON public.scans
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own scans" ON public.scans
  FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own scans" ON public.scans
  FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own scans" ON public.scans
  FOR DELETE USING (auth.uid() = user_id);

-- Scan Inputs
CREATE POLICY "Users can read own scan inputs" ON public.scan_inputs
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own scan inputs" ON public.scan_inputs
  FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete own scan inputs" ON public.scan_inputs
  FOR DELETE USING (auth.uid() = user_id);

-- Companies & Aliases
CREATE POLICY "Authenticated users can read companies" ON public.companies
  FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can read aliases" ON public.company_aliases
  FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can read company intelligence" ON public.company_intelligence
  FOR SELECT TO authenticated USING (true);

-- Domains & Recruiters
CREATE POLICY "Authenticated users can read domains" ON public.domains
  FOR SELECT TO authenticated USING (true);

CREATE POLICY "Authenticated users can read recruiters" ON public.recruiters
  FOR SELECT TO authenticated USING (true);

-- Evidence
CREATE POLICY "Users can read evidence of own scans" ON public.evidence
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.scans WHERE public.scans.id = public.evidence.scan_id AND public.scans.user_id = auth.uid()
    )
  );

-- Reports
CREATE POLICY "Users can read own reports" ON public.reports
  FOR SELECT USING (auth.uid() = user_id OR is_public = true);

CREATE POLICY "Users can insert own reports" ON public.reports
  FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own reports" ON public.reports
  FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own reports" ON public.reports
  FOR DELETE USING (auth.uid() = user_id);

-- Threat Indicators
CREATE POLICY "Authenticated users can read threat indicators" ON public.threat_indicators
  FOR SELECT TO authenticated USING (true);

-- Audit Logs
CREATE POLICY "Users can read own audit logs" ON public.audit_logs
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own audit logs" ON public.audit_logs
  FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Feedback
CREATE POLICY "Users can read own feedback" ON public.feedback
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own feedback" ON public.feedback
  FOR INSERT WITH CHECK (auth.uid() = user_id);
