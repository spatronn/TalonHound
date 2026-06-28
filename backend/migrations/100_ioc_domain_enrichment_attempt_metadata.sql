ALTER TABLE ioc_domain_enrichment
  ADD COLUMN IF NOT EXISTS last_success_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS last_error TEXT NULL;

UPDATE ioc_domain_enrichment
SET last_success_at = COALESCE(last_success_at, CASE WHEN rdap_status = 'success' THEN last_enriched_at ELSE NULL END),
    last_attempt_at = COALESCE(last_attempt_at, last_enriched_at),
    last_error = COALESCE(last_error, CASE WHEN rdap_status = 'success' THEN NULL ELSE error_message END)
WHERE last_success_at IS NULL
   OR last_attempt_at IS NULL
   OR (last_error IS NULL AND rdap_status IS DISTINCT FROM 'success' AND error_message IS NOT NULL);

CREATE INDEX IF NOT EXISTS ioc_domain_enrichment_updated_at_idx
  ON ioc_domain_enrichment (updated_at);

CREATE INDEX IF NOT EXISTS ioc_domain_enrichment_last_success_at_idx
  ON ioc_domain_enrichment (last_success_at);
