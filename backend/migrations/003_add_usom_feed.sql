INSERT INTO integration_feeds (key, name, source_url, schedule_cron, trust_level, active)
VALUES (
  'usom-trcert',
  'USOM TR-CERT',
  'https://www.usom.gov.tr/api/address/index',
  '0 * * * *',
  'guvenilir',
  TRUE
)
ON CONFLICT (key) DO UPDATE
SET name = EXCLUDED.name,
    source_url = EXCLUDED.source_url,
    schedule_cron = EXCLUDED.schedule_cron,
    active = EXCLUDED.active,
    updated_at = NOW();
