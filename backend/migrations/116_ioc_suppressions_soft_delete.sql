-- Soft-delete for suppressions + keep active boolean for enable/disable.
-- Deleted rows must not appear in lists or matching, and must not block re-create.

ALTER TABLE ioc_suppressions
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS deleted_by TEXT NULL;

-- Historical soft-disable left multiple inactive rows for the same key.
-- Keep the preferred live row (prefer active, then newest), soft-delete the rest.
WITH ranked AS (
  SELECT id,
         ROW_NUMBER() OVER (
           PARTITION BY lower(ioc_value), lower(ioc_type), scope, COALESCE(lower(source_name), '')
           ORDER BY active DESC, COALESCE(updated_at, created_at) DESC NULLS LAST, id DESC
         ) AS rn
  FROM ioc_suppressions
  WHERE deleted_at IS NULL
)
UPDATE ioc_suppressions s
SET active = FALSE,
    deleted_at = NOW(),
    deleted_by = 'migration:116',
    updated_at = NOW()
FROM ranked r
WHERE s.id = r.id
  AND r.rn > 1;

DROP INDEX IF EXISTS uq_ioc_suppressions_active_scope;

-- One non-deleted row per (value, type, scope, source). Deleted rows may be re-created.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_suppressions_active_scope
  ON ioc_suppressions (lower(ioc_value), lower(ioc_type), scope, COALESCE(lower(source_name), ''))
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_suppressions_not_deleted
  ON ioc_suppressions (id)
  WHERE deleted_at IS NULL;
