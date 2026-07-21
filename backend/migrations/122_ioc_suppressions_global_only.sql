-- Global-only IOC suppressions.
--
-- Product change: suppressions are now always global (one active suppression per
-- normalized ioc_value + ioc_type). Source-specific scope is retired at the
-- application layer. We KEEP the scope/source_name columns for backward
-- compatibility and to avoid destroying historical rows; matching already
-- ignores scope (see queryIocSuppressedFromDb / export join), so legacy
-- source-specific rows keep working as effectively-global.
--
-- Duplicate prevention (#8) is enforced at the DB level with a partial unique
-- index over (lower(ioc_value), lower(ioc_type)) for active, non-deleted rows.
-- Before creating it we must collapse any pre-existing duplicates (e.g. a global
-- row plus a source-specific row for the same indicator) down to a single active
-- row. We disable — never delete — the redundant rows so no history is lost.

-- 1) Collapse duplicate active rows per (value, type): keep the preferred one
--    (prefer global scope, then most recently touched, then highest id) active;
--    disable the rest. Disabled rows remain visible and auditable.
WITH ranked AS (
  SELECT id,
         ROW_NUMBER() OVER (
           PARTITION BY lower(ioc_value), lower(ioc_type)
           ORDER BY (CASE WHEN lower(COALESCE(scope, 'global')) = 'global' THEN 0 ELSE 1 END) ASC,
                    COALESCE(updated_at, created_at) DESC NULLS LAST,
                    id DESC
         ) AS rn
  FROM ioc_suppressions
  WHERE active = TRUE
    AND deleted_at IS NULL
)
UPDATE ioc_suppressions s
SET active = FALSE,
    updated_at = NOW()
FROM ranked r
WHERE s.id = r.id
  AND r.rn > 1;

-- 2) One active, non-deleted suppression per normalized (value, type), regardless
--    of scope. This is the hard guarantee behind the "An active suppression
--    already exists for this IOC" duplicate check.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_suppressions_one_active_value_type
  ON ioc_suppressions (lower(ioc_value), lower(ioc_type))
  WHERE active = TRUE AND deleted_at IS NULL;
