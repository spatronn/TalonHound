-- Per-feed source evidence for multi-source IOCs (same observable, multiple feed memberships).

CREATE TABLE IF NOT EXISTS ioc_feed_source_evidence (
  id BIGSERIAL PRIMARY KEY,
  ioc_item_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  feed_id UUID NOT NULL REFERENCES integration_feeds (integration_id) ON DELETE CASCADE,
  source_name TEXT NOT NULL,
  source_url TEXT NULL,
  category TEXT NULL,
  note TEXT NULL,
  confidence TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (ioc_item_id, ioc_observable_type, feed_id),
  FOREIGN KEY (ioc_observable_type, ioc_item_id) REFERENCES ioc_items (observable_type, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ioc_feed_source_evidence_item
  ON ioc_feed_source_evidence (ioc_item_id, ioc_observable_type);

COMMENT ON TABLE ioc_feed_source_evidence IS
  'Per-feed import metadata (note, category, source URL) for IOCs seen from multiple feeds.';
