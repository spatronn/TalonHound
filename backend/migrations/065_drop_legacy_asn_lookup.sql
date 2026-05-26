-- Remove legacy manual ASN enrichment (replaced by on-demand IPinfo Lite / ioc_ip_enrichment).
-- Does NOT touch: ioc_ip_enrichment, ioc_domain_enrichment, threat_intel_provider_configs.

DELETE FROM integration_feeds WHERE key = 'asn_enrichment';

DROP TABLE IF EXISTS asn_country_overrides;
DROP TABLE IF EXISTS asn_lookup;
DROP TABLE IF EXISTS asn_ipv4_ranges;
DROP TABLE IF EXISTS asn_networks_raw;
