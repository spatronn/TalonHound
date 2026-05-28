-- Entry-specific confidence on feed memberships (feed default stays on integration_feeds).
SET lock_timeout = '5s';
SET statement_timeout = '120s';

ALTER TABLE ioc_feed_memberships
  ADD COLUMN IF NOT EXISTS explicit_confidence TEXT NULL;
