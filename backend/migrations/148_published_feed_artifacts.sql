-- Phase 1 million-scale Published Feeds: file-backed snapshot artifacts.
--
-- Large TXT/JSON snapshots move OUT of published_feed_snapshots.content (TEXT) and onto a
-- persistent file artifact on disk; the snapshot row keeps only metadata + a pointer.
--
-- Additive / non-destructive:
--   * Existing rows keep content (TEXT) and serve exactly as before (storage_path IS NULL).
--   * content becomes nullable so new file-backed rows can leave it empty.
--   * No backfill, no rewrite of existing snapshots — legacy and file-backed rows coexist.

SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

ALTER TABLE published_feed_snapshots
  ADD COLUMN IF NOT EXISTS storage_path   TEXT,
  ADD COLUMN IF NOT EXISTS file_size      BIGINT,
  ADD COLUMN IF NOT EXISTS artifact_format TEXT,
  ADD COLUMN IF NOT EXISTS generation_id  TEXT;

-- Legacy rows stored the whole feed in content (NOT NULL). File-backed rows leave content
-- empty and point at storage_path instead. Allow NULL so new rows need not carry the bytes.
ALTER TABLE published_feed_snapshots
  ALTER COLUMN content DROP NOT NULL;

-- A successful snapshot must be servable via exactly one mechanism: legacy inline content
-- OR a file artifact. (Failed rows carry neither.) Backstop for application logic.
ALTER TABLE published_feed_snapshots
  DROP CONSTRAINT IF EXISTS chk_pf_snapshots_content_or_artifact;

ALTER TABLE published_feed_snapshots
  ADD CONSTRAINT chk_pf_snapshots_content_or_artifact CHECK (
    status <> 'success'
    OR content IS NOT NULL
    OR storage_path IS NOT NULL
  );

-- Startup reconciliation / retention sweeps read file-backed successful rows by feed.
CREATE INDEX IF NOT EXISTS idx_pf_snapshots_storage_path
  ON published_feed_snapshots (feed_id)
  WHERE storage_path IS NOT NULL;

-- DEPLOYMENT / ROLLBACK
-- --------------------
-- Forward: additive columns + one nullable relaxation + one CHECK (validated against
-- existing rows, all of which have content NOT NULL so the CHECK holds) + one partial
-- index on a mostly-empty predicate. No table rewrite, no long lock.
-- Rollback (no data loss for legacy rows):
--   ALTER TABLE published_feed_snapshots DROP CONSTRAINT IF EXISTS chk_pf_snapshots_content_or_artifact;
--   DROP INDEX IF EXISTS idx_pf_snapshots_storage_path;
--   ALTER TABLE published_feed_snapshots
--     DROP COLUMN IF EXISTS storage_path, DROP COLUMN IF EXISTS file_size,
--     DROP COLUMN IF EXISTS artifact_format, DROP COLUMN IF EXISTS generation_id;
--   -- content can be re-NOT-NULLed only after any file-backed rows are regenerated to inline.
-- On-disk artifacts under the published-feed storage dir are orphaned by a rollback and can
-- be removed manually; they are never web-served except through the authenticated route.
