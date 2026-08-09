-- Multi-output formats for Published Feeds: formats jsonb replaces single format column.
--
-- Backfill: existing format='txt' → ["txt"]; format='json' → ["json"].
-- No feed silently becomes dual-format.
-- Snapshot lookup becomes format-aware via artifact_format (+ params.output_format backfill).

SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

-- 1) Add formats array
ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS formats JSONB;

-- 2) Backfill from legacy format column (only where formats is null)
UPDATE published_feeds
SET formats = CASE
  WHEN lower(coalesce(format, 'txt')) = 'json' THEN '["json"]'::jsonb
  ELSE '["txt"]'::jsonb
END
WHERE formats IS NULL;

ALTER TABLE published_feeds
  ALTER COLUMN formats SET DEFAULT '["txt"]'::jsonb;

ALTER TABLE published_feeds
  ALTER COLUMN formats SET NOT NULL;

ALTER TABLE published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_formats;

ALTER TABLE published_feeds
  ADD CONSTRAINT chk_published_feeds_formats CHECK (
    jsonb_typeof(formats) = 'array'
    AND jsonb_array_length(formats) >= 1
    AND jsonb_array_length(formats) <= 2
    AND formats <@ '["txt","json"]'::jsonb
    -- no duplicates (max 2 elements; CHECK cannot use subqueries)
    AND (
      jsonb_array_length(formats) = 1
      OR (formats->>0) IS DISTINCT FROM (formats->>1)
    )
  );

-- 3) Drop legacy single-format column + constraint
ALTER TABLE published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_format;

ALTER TABLE published_feeds
  DROP COLUMN IF EXISTS format;

-- 4) Backfill snapshot artifact_format from params for legacy/inline rows
UPDATE published_feed_snapshots
SET artifact_format = CASE
  WHEN lower(coalesce(params->>'output_format', 'txt')) = 'json' THEN 'json'
  ELSE 'txt'
END
WHERE status = 'success'
  AND (artifact_format IS NULL OR btrim(artifact_format) = '');

-- 5) Format-aware success lookup index
DROP INDEX IF EXISTS idx_published_feed_snapshots_params_lookup;
CREATE INDEX IF NOT EXISTS idx_pf_snapshots_params_format_lookup
  ON published_feed_snapshots (
    feed_id,
    ((params->>'ioc_type')),
    ((params->>'window')),
    artifact_format,
    generated_at DESC
  )
  WHERE status = 'success';
