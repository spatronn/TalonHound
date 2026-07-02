-- Stable per-provider semantic fingerprint for ioc_items.
-- When the fingerprint is unchanged the integration worker skips all lifecycle
-- updates (last_seen_at, last_seen_in_feed, expiration, evidence) so that
-- volatile provider fields (URLHaus last_online, ThreatFox last_seen) no longer
-- cause an IOC to appear "fresh" on every feed run.
ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS provider_fingerprint TEXT NULL;

CREATE INDEX IF NOT EXISTS ioc_items_provider_fingerprint_idx
  ON ioc_items (provider_fingerprint)
  WHERE provider_fingerprint IS NOT NULL;
