-- API key lifecycle simplification: soft-delete replaces the old revoke/rotate model.
--
-- New lifecycle for published_feed_access_keys (the "API Keys" screen):
--   * ACTIVE   -> Disable / Delete
--   * DISABLED -> Enable  / Delete
--   * Delete is a soft-delete (deleted_at set). Deleted keys are hidden from the
--     main list and are rejected by every auth/validation path. It is irreversible.
--
-- Legacy REVOKED rows are migrated into the soft-deleted state so they disappear
-- from the API Keys list without touching audit history. Safe to re-run.

-- 1) Soft-delete bookkeeping columns. ---------------------------------------------------
ALTER TABLE published_feed_access_keys
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS deleted_by TEXT;

-- 2) One-time, idempotent cleanup: existing REVOKED keys become soft-deleted. -----------
-- Only rows that were revoked and not yet soft-deleted are touched, so re-running is a
-- no-op. revoked_at / audit history are preserved.
UPDATE published_feed_access_keys
SET deleted_at = COALESCE(deleted_at, revoked_at, NOW()),
    deleted_by = COALESCE(deleted_by, 'migration:134_revoked_cleanup')
WHERE revoked_at IS NOT NULL
  AND deleted_at IS NULL;

-- 3) Active-key lookup index that excludes soft-deleted rows (auth hot path). ------------
CREATE INDEX IF NOT EXISTS idx_pf_access_keys_type_not_deleted
  ON published_feed_access_keys (key_type)
  WHERE deleted_at IS NULL;
