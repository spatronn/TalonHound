-- Durable base-projection row count for Published Feeds.
-- Avoids COUNT(*) over published_feed_items on every chunked incremental tick.
-- Maintained by incremental projection deltas; verified on full rebuild / drift.

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS projection_item_count bigint;

COMMENT ON COLUMN published_feeds.projection_item_count IS
  'Cached COUNT of published_feed_items for snapshot_window=all; NULL means unknown (force recount).';

-- Index already created by ops backfill script; ensure it exists for reconciliation.
CREATE INDEX IF NOT EXISTS idx_pf_items_feed_recon_bucket
  ON published_feed_items (feed_id, snapshot_window, reconciliation_bucket, identity_key)
  WHERE snapshot_window = 'all' AND reconciliation_bucket IS NOT NULL;
