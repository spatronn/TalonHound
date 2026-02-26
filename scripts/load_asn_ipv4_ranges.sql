-- Load optimized IPv4 ASN ranges from asn_networks_raw
-- Assumes asn_networks_raw contains IPv4 start/end strings and numeric ASN text.

TRUNCATE asn_ipv4_ranges;

INSERT INTO asn_ipv4_ranges (start_ip_num, end_ip_num, asn, country_code, as_name)
SELECT
  ((split_part(range_start, '.', 1)::bigint << 24)
 + (split_part(range_start, '.', 2)::bigint << 16)
 + (split_part(range_start, '.', 3)::bigint << 8)
 +  split_part(range_start, '.', 4)::bigint) AS start_ip_num,
  ((split_part(range_end, '.', 1)::bigint << 24)
 + (split_part(range_end, '.', 2)::bigint << 16)
 + (split_part(range_end, '.', 3)::bigint << 8)
 +  split_part(range_end, '.', 4)::bigint) AS end_ip_num,
  asn::bigint,
  NULLIF(country_code, ''),
  NULLIF(as_name, '')
FROM asn_networks_raw
WHERE asn ~ '^[0-9]+$'
  AND range_start ~ '^\d+\.\d+\.\d+\.\d+$'
  AND range_end ~ '^\d+\.\d+\.\d+\.\d+$';

ANALYZE asn_ipv4_ranges;
