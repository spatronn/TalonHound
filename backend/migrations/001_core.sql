CREATE TABLE IF NOT EXISTS ioc_ips (
  id BIGSERIAL PRIMARY KEY,
  ip INET NOT NULL,
  source_name TEXT NOT NULL,
  source_url TEXT,
  confidence TEXT NOT NULL DEFAULT 'medium',
  category TEXT,
  note TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_preferences (
  email TEXT PRIMARY KEY,
  timezone TEXT NOT NULL DEFAULT 'UTC',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ioc_ip_geo_cache (
  ip INET PRIMARY KEY,
  country_code TEXT NOT NULL DEFAULT 'UN',
  asn BIGINT,
  as_name TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS integration_runs (
  id BIGSERIAL PRIMARY KEY,
  job_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'success', 'failed')),
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at TIMESTAMPTZ,
  records_processed INT NOT NULL DEFAULT 0,
  error_message TEXT,
  triggered_by TEXT NOT NULL DEFAULT 'scheduler',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS integration_checkpoints (
  source_name TEXT PRIMARY KEY,
  last_cursor TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_ioc_ips_created_at ON ioc_ips (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_ips_source_name ON ioc_ips (source_name);
CREATE INDEX IF NOT EXISTS idx_ioc_ips_confidence ON ioc_ips (confidence);
CREATE INDEX IF NOT EXISTS idx_ioc_ips_ip ON ioc_ips (ip);
CREATE INDEX IF NOT EXISTS idx_ioc_ips_ip_created_at ON ioc_ips (ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_ip_geo_cache_country_code ON ioc_ip_geo_cache (country_code);
CREATE INDEX IF NOT EXISTS idx_integration_runs_created_at ON integration_runs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_integration_runs_status ON integration_runs (status);
CREATE INDEX IF NOT EXISTS idx_ioc_ips_dedup_lookup
ON ioc_ips (
  ip,
  source_name,
  confidence,
  COALESCE(category, ''),
  COALESCE(source_url, '')
);
