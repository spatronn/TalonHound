-- Per-IOC Spamhaus DROP enrichment results (manual enrich only; local dataset lookup).
CREATE TABLE IF NOT EXISTS ioc_spamhaus_drop_enrichment (
  id BIGSERIAL PRIMARY KEY,
  lookup_ip TEXT NOT NULL,
  lookup_type TEXT NOT NULL DEFAULT 'ip' CHECK (lookup_type IN ('ip')),
  observable_value TEXT NULL,
  ioc_type TEXT NULL,
  provider_status TEXT NOT NULL
    CHECK (provider_status IN ('listed', 'not_listed', 'failed')),
  listed BOOLEAN NULL,
  matched_cidr TEXT NULL,
  list_type TEXT NULL,
  sblid TEXT NULL,
  rir TEXT NULL,
  dataset_status TEXT NULL,
  last_sync_at TIMESTAMPTZ NULL,
  error_code TEXT NULL,
  error_message TEXT NULL,
  raw_json JSONB NULL,
  enriched_at TIMESTAMPTZ NULL,
  last_attempt_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ioc_spamhaus_drop_enrichment_lookup_ip_uniq
  ON ioc_spamhaus_drop_enrichment (lookup_ip);

CREATE INDEX IF NOT EXISTS ioc_spamhaus_drop_enrichment_last_attempt_at_idx
  ON ioc_spamhaus_drop_enrichment (last_attempt_at DESC NULLS LAST);
