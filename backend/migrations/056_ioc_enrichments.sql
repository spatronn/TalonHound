CREATE TABLE IF NOT EXISTS ioc_enrichments (
  id BIGSERIAL PRIMARY KEY,
  ioc_id BIGINT NULL,
  ioc_value TEXT NOT NULL,
  ioc_type TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'virustotal',
  status TEXT NOT NULL,
  normalized_summary JSONB,
  raw_response JSONB,
  error_message TEXT,
  fetched_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ioc_enrichments_provider_value_type_uniq
  ON ioc_enrichments(provider, ioc_value, ioc_type);

CREATE INDEX IF NOT EXISTS ioc_enrichments_expires_at_idx
  ON ioc_enrichments(expires_at);

CREATE INDEX IF NOT EXISTS ioc_enrichments_ioc_id_idx
  ON ioc_enrichments(ioc_id);
