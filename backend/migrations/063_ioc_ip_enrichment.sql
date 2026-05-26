CREATE TABLE IF NOT EXISTS ioc_ip_enrichment (
  id BIGSERIAL PRIMARY KEY,
  ip TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'ipinfo_lite',
  provider_status TEXT NULL,

  asn TEXT NULL,
  as_name TEXT NULL,
  as_domain TEXT NULL,
  country_code TEXT NULL,
  country TEXT NULL,
  continent_code TEXT NULL,
  continent TEXT NULL,

  derived_signals JSONB NOT NULL DEFAULT '{}'::jsonb,
  raw_json JSONB NULL,
  error_message TEXT NULL,

  last_enriched_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ioc_ip_enrichment_ip_uniq ON ioc_ip_enrichment (ip);
CREATE INDEX IF NOT EXISTS ioc_ip_enrichment_asn_idx ON ioc_ip_enrichment (asn);
CREATE INDEX IF NOT EXISTS ioc_ip_enrichment_country_code_idx ON ioc_ip_enrichment (country_code);
CREATE INDEX IF NOT EXISTS ioc_ip_enrichment_last_enriched_at_idx ON ioc_ip_enrichment (last_enriched_at);
