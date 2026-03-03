INSERT INTO integration_feeds (key, integration_id, name, source_url, schedule_cron, trust_level, active)
VALUES (
  'threatfox-abusech',
  gen_random_uuid(),
  'ThreatFox abuse.ch',
  'https://threatfox.abuse.ch/export/csv/full/',
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
