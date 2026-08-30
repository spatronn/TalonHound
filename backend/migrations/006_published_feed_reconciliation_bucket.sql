-- Stable reconciliation buckets for index-friendly slice scans.
-- Bucket = abs(hashtext(partition_identity)) % 256 (fixed; independent of slice_count).
-- Logical slices map to contiguous bucket ranges when 256 % slice_count = 0.

CREATE OR REPLACE FUNCTION published_feed_reconciliation_bucket(pid text)
RETURNS smallint
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN pid IS NULL OR btrim(pid) = '' THEN NULL
    ELSE (abs(hashtext(pid)) % 256)::smallint
  END;
$$;

ALTER TABLE published_feed_items
  ADD COLUMN IF NOT EXISTS reconciliation_bucket smallint;

COMMENT ON COLUMN published_feed_items.reconciliation_bucket IS
  'Stable hash bucket (0..255) for indexed reconciliation scans; slice maps to bucket ranges.';
