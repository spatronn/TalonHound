-- Phase 2: Published Feed projection + incremental refresh state.
--
-- Materializes one row per published identity per (feed, snapshot_window) so scheduled
-- refreshes can:
--   * no-op when nothing relevant changed
--   * re-normalize only dirty identities
--   * stream artifacts from the projection (P1 writers) without re-joining millions
--
-- Additive / non-destructive. Existing file-backed and TEXT snapshots remain valid.
-- Projection-based refresh activates only after bootstrap sets projection_status='ready'.
-- Column is snapshot_window (not "window") — WINDOW is a PostgreSQL reserved keyword.

SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

CREATE TABLE IF NOT EXISTS published_feed_items (
  feed_id BIGINT NOT NULL REFERENCES published_feeds(id) ON DELETE CASCADE,
  snapshot_window TEXT NOT NULL,
  identity_key TEXT NOT NULL,
  ioc_item_id BIGINT NOT NULL,
  observable TEXT NOT NULL,
  observable_type TEXT NOT NULL,
  recency_ts TIMESTAMPTZ,
  confidence TEXT,
  category TEXT,
  confidence_rank SMALLINT NOT NULL DEFAULT 0,
  txt_value TEXT NOT NULL,
  item_json JSONB,
  content_fingerprint TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (feed_id, snapshot_window, identity_key)
);

-- Ordered scan for artifact generation from projection.
CREATE INDEX IF NOT EXISTS idx_pf_items_feed_window_order
  ON published_feed_items (feed_id, snapshot_window, recency_ts DESC NULLS LAST, confidence_rank DESC, observable ASC);

CREATE INDEX IF NOT EXISTS idx_pf_items_feed_ioc
  ON published_feed_items (feed_id, ioc_item_id);

-- Feed-level projection / incremental state (additive columns on published_feeds).
ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS projection_status TEXT NOT NULL DEFAULT 'absent';

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS projection_cutoff TIMESTAMPTZ;

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS projection_built_at TIMESTAMPTZ;

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS last_refresh_checked_at TIMESTAMPTZ;

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS last_refresh_mode TEXT;

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS last_refresh_ms INTEGER;

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS last_changed_count INTEGER;

ALTER TABLE published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_projection_status;

ALTER TABLE published_feeds
  ADD CONSTRAINT chk_published_feeds_projection_status
  CHECK (projection_status IN ('absent', 'bootstrapping', 'ready', 'failed', 'stale'));

-- Feature flag default OFF: incremental uses projection only when streaming is also on
-- and projection_status='ready'. Documented in code (PUBLISHED_FEED_INCREMENTAL_ENABLED).

-- ROLLBACK:
--   ALTER TABLE published_feeds
--     DROP CONSTRAINT IF EXISTS chk_published_feeds_projection_status;
--   ALTER TABLE published_feeds
--     DROP COLUMN IF EXISTS projection_status,
--     DROP COLUMN IF EXISTS projection_cutoff,
--     DROP COLUMN IF EXISTS projection_built_at,
--     DROP COLUMN IF EXISTS last_refresh_checked_at,
--     DROP COLUMN IF EXISTS last_refresh_mode,
--     DROP COLUMN IF EXISTS last_refresh_ms,
--     DROP COLUMN IF EXISTS last_changed_count;
--   DROP TABLE IF EXISTS published_feed_items;
