-- Durable pagination within each published-feed reconciliation hash slice.

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS reconciliation_cursor text NOT NULL DEFAULT '';

COMMENT ON COLUMN published_feeds.reconciliation_cursor IS
  'Exclusive lower bound (identity_key) for the current reconciliation_slice batch.';
