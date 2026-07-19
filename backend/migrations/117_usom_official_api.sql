-- Preserve the existing USOM feed identity while moving its transport and
-- presentation to the official Siber Güvenlik Başkanlığı API.

ALTER TABLE ioc_feed_source_evidence
  ADD COLUMN IF NOT EXISTS provider_metadata JSONB NULL;

ALTER TABLE integration_runs
  ADD COLUMN IF NOT EXISTS run_details JSONB NULL;

UPDATE integration_feeds
SET name = 'Siber Güvenlik Başkanlığı / USOM',
    source_url = 'https://siberguvenlik.gov.tr/api/address/index',
    updated_at = NOW()
WHERE key = 'usom-trcert'
  AND (
    name IS DISTINCT FROM 'Siber Güvenlik Başkanlığı / USOM'
    OR source_url IS DISTINCT FROM 'https://siberguvenlik.gov.tr/api/address/index'
  );

UPDATE ioc_items
SET source_url = 'https://siberguvenlik.gov.tr/api/address/index'
WHERE source_name = 'USOM:TR-CERT'
  AND source_url IS DISTINCT FROM 'https://siberguvenlik.gov.tr/api/address/index';

UPDATE ioc_feed_source_evidence
SET source_url = 'https://siberguvenlik.gov.tr/api/address/index',
    updated_at = NOW()
WHERE source_name = 'USOM:TR-CERT'
  AND source_url IS DISTINCT FROM 'https://siberguvenlik.gov.tr/api/address/index';

COMMENT ON COLUMN ioc_feed_source_evidence.provider_metadata IS
  'Sanitized per-provider record metadata; provider timestamps do not control IOC lifecycle.';

COMMENT ON COLUMN integration_runs.run_details IS
  'Provider-specific JSON metrics such as page totals, retries and lookup refresh outcomes.';
