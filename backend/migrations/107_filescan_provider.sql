CREATE TABLE IF NOT EXISTS ioc_filescan_enrichment (
  id                 BIGSERIAL PRIMARY KEY,
  cache_key          TEXT NOT NULL,        -- normalizeFilescanCacheKey(ioc_type, ioc_value)
  ioc_type           TEXT NOT NULL,
  ioc_value          TEXT NOT NULL,
  provider_status    TEXT NULL,
  normalized_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  raw_json           JSONB NULL,
  error_message      TEXT NULL,
  last_enriched_at   TIMESTAMPTZ NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ioc_filescan_enrichment_cache_key_uniq
  ON ioc_filescan_enrichment (cache_key);

CREATE INDEX IF NOT EXISTS ioc_filescan_enrichment_last_enriched_at_idx
  ON ioc_filescan_enrichment (last_enriched_at);

INSERT INTO threat_intel_provider_configs (provider, enabled, ttl_hours, timeout_ms, api_key, config)
VALUES (
  'filescan',
  false,
  24,
  15000,
  NULL,
  '{"rate_limit_per_minute":10}'::jsonb
)
ON CONFLICT (provider) DO NOTHING;
