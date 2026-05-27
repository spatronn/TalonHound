-- Per-feed credentials (e.g. URLHaus Auth-Key). Non-destructive; defaults to empty object.
ALTER TABLE integration_feeds
  ADD COLUMN IF NOT EXISTS credentials JSONB NOT NULL DEFAULT '{}'::jsonb;
