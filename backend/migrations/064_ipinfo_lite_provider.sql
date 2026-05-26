ALTER TABLE threat_intel_provider_configs
  ADD COLUMN IF NOT EXISTS config JSONB NOT NULL DEFAULT '{}'::jsonb;

INSERT INTO threat_intel_provider_configs (provider, enabled, ttl_hours, timeout_ms, config)
VALUES ('ipinfo_lite', false, 24, 6000, '{"base_url":"https://api.ipinfo.io/lite","timeout_seconds":6}'::jsonb)
ON CONFLICT (provider) DO NOTHING;

UPDATE integration_feeds
SET active = false, updated_at = NOW()
WHERE key = 'asn_enrichment';
