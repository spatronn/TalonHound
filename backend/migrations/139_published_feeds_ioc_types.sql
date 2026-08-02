-- Additive multi-value IOC types for published_feeds (deploy-safe expand step).
-- Adds ioc_types JSONB alongside legacy ioc_type. Does NOT drop ioc_type —
-- that is reserved for cleanup migration 140 after the new backend is live.
--
-- Safe deploy order:
--   1) this migration (139)
--   2) backend (reads ioc_types first, falls back to ioc_type; writes ioc_types only)
--   3) frontend
--   4) smoke / regenerate
--   5) cleanup migration 140
SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS ioc_types JSONB;

-- Backfill: every existing single-type row becomes a one-element array.
UPDATE published_feeds
SET ioc_types = to_jsonb(ARRAY[lower(ioc_type)])
WHERE ioc_types IS NULL
  AND ioc_type IS NOT NULL;

-- Defensive default for any unexpected NULL (should not happen in production).
UPDATE published_feeds
SET ioc_types = '["ip"]'::jsonb
WHERE ioc_types IS NULL;

ALTER TABLE published_feeds
  ALTER COLUMN ioc_types SET NOT NULL;

-- New backend INSERT/UPDATE writes only ioc_types; allow legacy column to be null.
ALTER TABLE published_feeds
  ALTER COLUMN ioc_type DROP NOT NULL;

ALTER TABLE published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_ioc_types;

ALTER TABLE published_feeds
  ADD CONSTRAINT chk_published_feeds_ioc_types CHECK (
    jsonb_typeof(ioc_types) = 'array'
    AND jsonb_array_length(ioc_types) >= 1
    AND ioc_types <@ '["domain","hash","ip","url"]'::jsonb
    AND jsonb_array_length(ioc_types) = (
      SELECT COUNT(DISTINCT elem)::int
      FROM jsonb_array_elements_text(ioc_types) AS t(elem)
    )
  );

-- Keep idx_published_feeds_ioc_type intact for the old backend during rollout.

CREATE INDEX IF NOT EXISTS idx_published_feeds_ioc_types
  ON published_feeds USING GIN (ioc_types);

-- Bridge for the short window when migration 139 is applied but the old
-- backend is still running: fill ioc_types from ioc_type when the legacy
-- writer omits ioc_types (INSERT) or changes only ioc_type (UPDATE).
-- Application code does NOT dual-write. Dropped in migration 140.
CREATE OR REPLACE FUNCTION published_feeds_bridge_ioc_types()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.ioc_types IS NULL AND NEW.ioc_type IS NOT NULL THEN
    NEW.ioc_types := to_jsonb(ARRAY[lower(NEW.ioc_type)]);
  ELSIF TG_OP = 'UPDATE'
    AND OLD.ioc_type IS DISTINCT FROM NEW.ioc_type
    AND OLD.ioc_types IS NOT DISTINCT FROM NEW.ioc_types
    AND NEW.ioc_type IS NOT NULL THEN
    -- Legacy UPDATE touched only ioc_type; keep ioc_types in sync.
    NEW.ioc_types := to_jsonb(ARRAY[lower(NEW.ioc_type)]);
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_published_feeds_bridge_ioc_types ON published_feeds;
CREATE TRIGGER trg_published_feeds_bridge_ioc_types
  BEFORE INSERT OR UPDATE ON published_feeds
  FOR EACH ROW
  EXECUTE FUNCTION published_feeds_bridge_ioc_types();

-- Snapshot lookup still uses params->>'ioc_type' as the identity key.
-- Single-type feeds keep scalar values ("ip"). Multi-type feeds write a
-- sorted join key ("domain,url"). Existing snapshot rows remain valid.
UPDATE published_feed_snapshots
SET params = params || jsonb_build_object(
  'ioc_types',
  jsonb_build_array(params->>'ioc_type')
)
WHERE status = 'success'
  AND params ? 'ioc_type'
  AND NOT (params ? 'ioc_types')
  AND params->>'ioc_type' IS NOT NULL
  AND position(',' IN params->>'ioc_type') = 0;
