CREATE TABLE IF NOT EXISTS ioc_domain_enrichment (
  id BIGSERIAL PRIMARY KEY,
  observable_value TEXT NOT NULL,
  root_domain TEXT NOT NULL,
  ioc_type TEXT NULL,

  rdap_status TEXT NULL,

  registrar TEXT NULL,
  registration_date TIMESTAMPTZ NULL,
  expiration_date TIMESTAMPTZ NULL,
  last_changed_date TIMESTAMPTZ NULL,
  domain_age_days INTEGER NULL,

  nameservers JSONB NOT NULL DEFAULT '[]'::jsonb,
  statuses JSONB NOT NULL DEFAULT '[]'::jsonb,
  derived_signals JSONB NOT NULL DEFAULT '{}'::jsonb,
  rdap_raw_json JSONB NULL,

  error_message TEXT NULL,
  last_enriched_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ioc_domain_enrichment_root_domain_uniq
  ON ioc_domain_enrichment (root_domain);

CREATE INDEX IF NOT EXISTS ioc_domain_enrichment_root_domain_idx
  ON ioc_domain_enrichment (root_domain);

CREATE INDEX IF NOT EXISTS ioc_domain_enrichment_last_enriched_at_idx
  ON ioc_domain_enrichment (last_enriched_at);
