-- Manual IOC confidence provenance (source default vs explicit entry vs analyst override).

ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS confidence_source TEXT NULL,
  ADD COLUMN IF NOT EXISTS confidence_source_name TEXT NULL;

COMMENT ON COLUMN ioc_items.confidence_source IS
  'Provenance of confidence: manual_entry, ioc_source_default, feed_default, feed_entry, analyst_override, unknown';

-- Backfill manual IOC rows linked to ioc_sources.
UPDATE ioc_items i
SET confidence_source = 'ioc_source_default',
    confidence_source_name = s.name
FROM ioc_sources s
WHERE i.ioc_source_id = s.id
  AND i.confidence_source IS NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_items_confidence_source
  ON ioc_items (confidence_source)
  WHERE confidence_source IS NOT NULL;
