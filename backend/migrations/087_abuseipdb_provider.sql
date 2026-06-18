CREATE TABLE IF NOT EXISTS ioc_abuseipdb_enrichment (
  id BIGSERIAL PRIMARY KEY,
  ip TEXT NOT NULL,
  provider_status TEXT NULL,
  max_age_days INTEGER NOT NULL DEFAULT 90,
  verbose_enabled BOOLEAN NOT NULL DEFAULT false,
  normalized_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  raw_json JSONB NULL,
  error_message TEXT NULL,
  last_enriched_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ioc_abuseipdb_enrichment_ip_uniq
  ON ioc_abuseipdb_enrichment (ip);

CREATE INDEX IF NOT EXISTS ioc_abuseipdb_enrichment_last_enriched_at_idx
  ON ioc_abuseipdb_enrichment (last_enriched_at);

INSERT INTO threat_intel_provider_configs (provider, enabled, ttl_hours, timeout_ms, api_key, config)
VALUES (
  'abuseipdb',
  false,
  24,
  8000,
  NULL,
  '{"max_age_days":90,"verbose":false}'::jsonb
)
ON CONFLICT (provider) DO NOTHING;
