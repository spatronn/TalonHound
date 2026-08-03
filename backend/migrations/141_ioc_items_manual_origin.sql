-- Explicit, durable provenance for manually-created IOCs (the "Add IOC" workflow).
--
-- Documented gap: ioc_items had no authoritative column identifying rows created
-- through the manual Add IOC UI.
--   * ioc_source_id is unreliable — migration 077 backfilled it for EVERY
--     non-integration source_name (including script / API-ingested rows) and
--     labelled them source_type = 'manual'.
--   * source_name is only a human-visible label.
--   * manual_override_by_user_id records whoever last overrode expiration STATUS;
--     it drifts and is also set on feed IOCs when an analyst overrides them.
-- Feed / scheduled-import / background-worker inserts (e.g. customThreatFeedSync)
-- never set any of these columns.
--
-- We therefore add an explicit origin marker plus a durable creator reference,
-- both written ONLY by createManualIoc(). Existing rows are intentionally NOT
-- backfilled: their manual-ness cannot be determined reliably, and guessing would
-- reintroduce feed / API false positives. Only IOCs added after this migration are
-- reported as "manually added".

ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS created_origin TEXT NULL
    CHECK (created_origin IS NULL OR created_origin IN ('manual_add')),
  ADD COLUMN IF NOT EXISTS created_by_user_id UUID NULL;

-- Supports: WHERE created_origin = 'manual_add' ORDER BY created_at DESC LIMIT n
CREATE INDEX IF NOT EXISTS idx_ioc_items_manual_recent
  ON ioc_items (created_at DESC)
  WHERE created_origin = 'manual_add';
