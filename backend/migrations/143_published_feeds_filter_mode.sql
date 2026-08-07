-- Advanced Query mode for Published Feeds.
--
-- Adds a per-feed filter mode alongside the existing Basic Filters columns:
--   * filter_mode   — 'basic' (default) or 'query'
--   * advanced_query — the IOC List DSL text used when filter_mode = 'query'
--
-- Backward compatible / non-destructive:
--   * Existing rows default to filter_mode = 'basic' and behave exactly as before.
--   * No existing filter configuration (ioc_types, time_window, include_feed_keys,
--     safety filters, delivery) is rewritten or dropped.
--   * Advanced query text is validated + normalized by the application using the
--     same IOC List parser; the column only stores it.

SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS filter_mode TEXT NOT NULL DEFAULT 'basic';

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS advanced_query TEXT;

ALTER TABLE published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_filter_mode;

ALTER TABLE published_feeds
  ADD CONSTRAINT chk_published_feeds_filter_mode
  CHECK (filter_mode IN ('basic', 'query'));

-- A 'query' feed must carry a non-empty advanced_query; a 'basic' feed leaves it null.
-- Application validation is the primary gate (it re-parses the DSL); this is a backstop.
ALTER TABLE published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_query_requires_text;

ALTER TABLE published_feeds
  ADD CONSTRAINT chk_published_feeds_query_requires_text
  CHECK (
    filter_mode <> 'query'
    OR (advanced_query IS NOT NULL AND length(btrim(advanced_query)) > 0)
  );
