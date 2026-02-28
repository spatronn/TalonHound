INSERT INTO integration_feeds (key, name, source_url, schedule_cron, trust_level, active)
VALUES (
  'urlhaus-abusech',
  'URLhaus abuse.ch',
  'https://urlhaus.abuse.ch/downloads/text/',
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
