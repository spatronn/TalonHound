-- Manual-only DNSMania enrichment cache (passive DNS history).
CREATE TABLE IF NOT EXISTS ioc_dnsmania_enrichment (
  id BIGSERIAL PRIMARY KEY,
  lookup_key TEXT NOT NULL,
  lookup_type TEXT NOT NULL CHECK (lookup_type IN ('domain', 'ip')),
  lookup_value TEXT NOT NULL,
  observable_value TEXT NOT NULL,
  ioc_type TEXT NOT NULL,
  provider_status TEXT NOT NULL DEFAULT 'not_run'
    CHECK (provider_status IN ('completed', 'no_data', 'failed', 'disabled')),
  known BOOLEAN NOT NULL DEFAULT FALSE,
  normalized_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  relations_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  raw_json JSONB NULL,
  error_code TEXT NULL,
  error_message TEXT NULL,
  enriched_at TIMESTAMPTZ NULL,
  last_attempt_at TIMESTAMPTZ NULL,
  last_success_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ioc_dnsmania_enrichment_lookup_key_uniq
  ON ioc_dnsmania_enrichment (lookup_key);

CREATE INDEX IF NOT EXISTS ioc_dnsmania_enrichment_last_attempt_at_idx
  ON ioc_dnsmania_enrichment (last_attempt_at DESC NULLS LAST);
