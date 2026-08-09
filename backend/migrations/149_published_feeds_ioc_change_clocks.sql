-- Phase 2: reliable IOC change clocks for Published Feed incremental refresh.
--
-- Adds ioc_items.updated_at (missing today) and narrow triggers so tag insert/delete
-- bump the IOC clock. Additive only. No giant backfill — projection bootstrap uses
-- full rebuild; existing rows get updated_at filled on first UPDATE.

SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;

ALTER TABLE ioc_items
  ALTER COLUMN updated_at SET DEFAULT NOW();

CREATE OR REPLACE FUNCTION pf_touch_ioc_items_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := NOW();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_pf_touch_ioc_items_updated_at ON ioc_items;
CREATE TRIGGER trg_pf_touch_ioc_items_updated_at
  BEFORE UPDATE ON ioc_items
  FOR EACH ROW
  EXECUTE FUNCTION pf_touch_ioc_items_updated_at();

-- Tag assignment has no tombstone table — touch the IOC clock on insert/delete.
CREATE OR REPLACE FUNCTION pf_touch_ioc_on_tag_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    UPDATE ioc_items
       SET updated_at = NOW()
     WHERE id = OLD.ioc_id
       AND observable_type = OLD.ioc_observable_type;
    RETURN OLD;
  END IF;
  UPDATE ioc_items
     SET updated_at = NOW()
   WHERE id = NEW.ioc_id
     AND observable_type = NEW.ioc_observable_type;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_pf_touch_ioc_on_tag_ins ON ioc_tags;
CREATE TRIGGER trg_pf_touch_ioc_on_tag_ins
  AFTER INSERT ON ioc_tags
  FOR EACH ROW
  EXECUTE FUNCTION pf_touch_ioc_on_tag_change();

DROP TRIGGER IF EXISTS trg_pf_touch_ioc_on_tag_del ON ioc_tags;
CREATE TRIGGER trg_pf_touch_ioc_on_tag_del
  AFTER DELETE ON ioc_tags
  FOR EACH ROW
  EXECUTE FUNCTION pf_touch_ioc_on_tag_change();

-- Tag catalog rename/enable affects published tags without touching ioc_tags rows.
CREATE TABLE IF NOT EXISTS published_feed_global_watermarks (
  key TEXT PRIMARY KEY,
  watermark TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO published_feed_global_watermarks (key, watermark)
VALUES ('tags_catalog', NOW())
ON CONFLICT (key) DO NOTHING;

CREATE OR REPLACE FUNCTION pf_bump_tags_catalog_watermark()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO published_feed_global_watermarks (key, watermark)
  VALUES ('tags_catalog', NOW())
  ON CONFLICT (key) DO UPDATE SET watermark = EXCLUDED.watermark;
  RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_pf_bump_tags_catalog ON tags;
CREATE TRIGGER trg_pf_bump_tags_catalog
  AFTER UPDATE OF name, enabled ON tags
  FOR EACH STATEMENT
  EXECUTE FUNCTION pf_bump_tags_catalog_watermark();

-- NOTE: Do NOT create idx_ioc_items_updated_at inside this transactional migration.
-- On the partitioned multi-million-row ioc_items table a plain CREATE INDEX takes a
-- ShareLock and scans all partitions. After deploy, create concurrently if needed:
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_items_updated_at
--     ON ioc_items (updated_at) WHERE updated_at IS NOT NULL;
-- Dirty detection remains correct without it (seq/bitmap scan); add the index when
-- updated_at population grows enough to justify it.

-- ROLLBACK (no data loss for Published Feeds artifacts):
--   DROP TRIGGER IF EXISTS trg_pf_touch_ioc_items_updated_at ON ioc_items;
--   DROP TRIGGER IF EXISTS trg_pf_touch_ioc_on_tag_ins ON ioc_tags;
--   DROP TRIGGER IF EXISTS trg_pf_touch_ioc_on_tag_del ON ioc_tags;
--   DROP TRIGGER IF EXISTS trg_pf_bump_tags_catalog ON tags;
--   DROP FUNCTION IF EXISTS pf_touch_ioc_items_updated_at();
--   DROP FUNCTION IF EXISTS pf_touch_ioc_on_tag_change();
--   DROP FUNCTION IF EXISTS pf_bump_tags_catalog_watermark();
--   DROP TABLE IF EXISTS published_feed_global_watermarks;
--   ALTER TABLE ioc_items DROP COLUMN IF EXISTS updated_at;
