INSERT INTO integration_feeds (key, integration_id, name, source_url, schedule_cron, trust_level, active)
VALUES (
  'asn_enrichment',
  'ASN:geoip-oxl',
  'ASN Enrichment',
  'https://geoip.oxl.app/file/asn_full.json.zip',
  '0 0 * * *',
  'orta',
  TRUE
)
ON CONFLICT (key) DO UPDATE SET
  integration_id = EXCLUDED.integration_id,
  name = EXCLUDED.name,
  source_url = EXCLUDED.source_url,
  schedule_cron = EXCLUDED.schedule_cron,
  trust_level = EXCLUDED.trust_level,
  active = EXCLUDED.active,
  updated_at = NOW();
