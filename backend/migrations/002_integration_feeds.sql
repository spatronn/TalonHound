CREATE TABLE IF NOT EXISTS integration_feeds (
  key TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  source_url TEXT NOT NULL,
  schedule_cron TEXT NOT NULL,
  trust_level TEXT NOT NULL DEFAULT 'not_categorized' CHECK (trust_level IN ('guvenilir', 'orta', 'not_categorized')),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO integration_feeds (key, name, source_url, schedule_cron, trust_level, active)
VALUES (
  'et-blockrules',
  'EmergingThreats Blockrules',
  'http://rules.emergingthreats.net/blockrules/',
  '0 * * * *',
  'not_categorized',
  TRUE
)
ON CONFLICT (key) DO UPDATE
SET name = EXCLUDED.name,
    source_url = EXCLUDED.source_url,
    schedule_cron = EXCLUDED.schedule_cron,
    updated_at = NOW();
