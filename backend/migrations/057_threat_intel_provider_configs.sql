CREATE TABLE IF NOT EXISTS threat_intel_provider_configs (
  id BIGSERIAL PRIMARY KEY,
  provider TEXT NOT NULL UNIQUE,
  enabled BOOLEAN NOT NULL DEFAULT true,
  api_key TEXT,
  ttl_hours INTEGER NOT NULL DEFAULT 24,
  timeout_ms INTEGER NOT NULL DEFAULT 12000,
  last_test_at TIMESTAMPTZ,
  last_success_at TIMESTAMPTZ,
  last_error_at TIMESTAMPTZ,
  last_error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO threat_intel_provider_configs (provider, enabled, ttl_hours, timeout_ms)
VALUES ('virustotal', true, 24, 12000)
ON CONFLICT (provider) DO NOTHING;
