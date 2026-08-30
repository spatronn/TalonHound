-- Published Feed sliding-window incremental: reconciliation cursor + boundary index.

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS reconciliation_slice integer NOT NULL DEFAULT 0;

COMMENT ON COLUMN published_feeds.reconciliation_slice IS
  'Rolling reconciliation cursor for incremental projection self-healing (hash slice).';

CREATE INDEX IF NOT EXISTS idx_pf_items_feed_all_recency
  ON published_feed_items (feed_id, recency_ts)
  WHERE snapshot_window = 'all';
