CREATE TABLE IF NOT EXISTS asn_lookup (
  id BIGSERIAL PRIMARY KEY,
  start_ip_int BIGINT NOT NULL,
  end_ip_int BIGINT NOT NULL,
  asn BIGINT,
  asn_owner TEXT,
  country TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (start_ip_int >= 0 AND end_ip_int >= 0 AND start_ip_int <= end_ip_int)
);

CREATE INDEX IF NOT EXISTS idx_asn_lookup_start_end ON asn_lookup (start_ip_int, end_ip_int);
CREATE INDEX IF NOT EXISTS idx_asn_lookup_asn ON asn_lookup (asn);
CREATE INDEX IF NOT EXISTS idx_asn_lookup_country ON asn_lookup (country);
