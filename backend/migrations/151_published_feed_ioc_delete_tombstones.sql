-- Phase 2 caveat: hard IOC DELETE visibility for Published Feed incremental refresh.
--
-- Problem: collectDirtyIocIds only sees living ioc_items.updated_at. A hard DELETE
-- removes the row with no dirty signal, and published_feed_items has no FK cascade,
-- so projection orphans survive until full rebuild.
--
-- Fix: narrow AFTER DELETE tombstones with enough identity to re-evaluate siblings
-- (observable + type) and canonical hash links (artifact_id when present).
-- Watermark = deleted_at; cutoff advances only after successful publish (existing path).
-- Additive; no backfill.

SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

CREATE TABLE IF NOT EXISTS published_feed_ioc_deletes (
  id BIGSERIAL PRIMARY KEY,
  ioc_item_id BIGINT NOT NULL,
  observable TEXT NOT NULL,
  observable_type TEXT NOT NULL,
  artifact_id UUID NULL,
  deleted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pf_ioc_deletes_deleted_at
  ON published_feed_ioc_deletes (deleted_at);

CREATE INDEX IF NOT EXISTS idx_pf_ioc_deletes_ioc_item_id
  ON published_feed_ioc_deletes (ioc_item_id);

CREATE OR REPLACE FUNCTION pf_record_ioc_item_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  art UUID;
BEGIN
  -- Capture artifact link before cascade removes file_artifact_ioc_links.
  SELECT fal.artifact_id
    INTO art
    FROM file_artifact_ioc_links fal
   WHERE fal.ioc_item_id = OLD.id
     AND fal.ioc_observable_type = OLD.observable_type
   ORDER BY fal.is_canonical_ioc DESC NULLS LAST, fal.artifact_id
   LIMIT 1;

  INSERT INTO published_feed_ioc_deletes (
    ioc_item_id, observable, observable_type, artifact_id, deleted_at
  ) VALUES (
    OLD.id, OLD.observable, OLD.observable_type, art, NOW()
  );
  RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS trg_pf_record_ioc_item_delete ON ioc_items;
CREATE TRIGGER trg_pf_record_ioc_item_delete
  BEFORE DELETE ON ioc_items
  FOR EACH ROW
  EXECUTE FUNCTION pf_record_ioc_item_delete();

-- Optional retention (ops): DELETE FROM published_feed_ioc_deletes
--   WHERE deleted_at < NOW() - INTERVAL '14 days';

-- ROLLBACK:
--   DROP TRIGGER IF EXISTS trg_pf_record_ioc_item_delete ON ioc_items;
--   DROP FUNCTION IF EXISTS pf_record_ioc_item_delete();
--   DROP TABLE IF EXISTS published_feed_ioc_deletes;
