-- Performance-oriented ASN range table (IPv4)
-- Use this table for fast IOC enrichment lookups.

CREATE TABLE IF NOT EXISTS asn_ipv4_ranges (
  id BIGSERIAL PRIMARY KEY,
  start_ip_num BIGINT NOT NULL,
  end_ip_num BIGINT NOT NULL,
  asn BIGINT,
  country_code TEXT,
  as_name TEXT
);

CREATE INDEX IF NOT EXISTS idx_asn_ipv4_ranges_start_end
  ON asn_ipv4_ranges (start_ip_num, end_ip_num);

CREATE INDEX IF NOT EXISTS idx_asn_ipv4_ranges_asn
  ON asn_ipv4_ranges (asn);
