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

CREATE INDEX IF NOT EXISTS idx_ioc_ips_created_at ON ioc_ips (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_ips_source_name ON ioc_ips (source_name);
CREATE INDEX IF NOT EXISTS idx_ioc_ips_confidence ON ioc_ips (confidence);
CREATE INDEX IF NOT EXISTS idx_ioc_ips_ip ON ioc_ips (ip);

CREATE TABLE IF NOT EXISTS user_preferences (
  email TEXT PRIMARY KEY,
  timezone TEXT NOT NULL DEFAULT 'UTC',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
