-- 047_ioc_suppression_file_artifact.sql
--
-- Canonical file-scoped IOC suppressions.
--
-- When an analyst suppresses a file-hash IOC that is linked to a proven
-- file_artifacts identity, the suppression stores file_artifact_id. Matching
-- then covers every proven exact hash (md5/sha1/sha256) of that survivor
-- artifact — including hashes discovered later via enrichment — without
-- creating duplicate suppression rows.
--
-- file_artifact_id IS NULL keeps legacy / manual Suppressions-screen semantics:
-- exact (ioc_type, ioc_value) only. Non-file observables are unchanged.
--
-- Safe backfill: only active, non-deleted hash suppressions whose (type,value)
-- uniquely resolves to exactly one survivor artifact. Ambiguous / unresolved
-- rows are left exact-only.

ALTER TABLE public.ioc_suppressions
  ADD COLUMN IF NOT EXISTS file_artifact_id uuid;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'ioc_suppressions_file_artifact_id_fkey'
  ) THEN
    ALTER TABLE public.ioc_suppressions
      ADD CONSTRAINT ioc_suppressions_file_artifact_id_fkey
      FOREIGN KEY (file_artifact_id) REFERENCES public.file_artifacts(id)
      ON DELETE SET NULL;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_ioc_suppressions_file_artifact_active
  ON public.ioc_suppressions (file_artifact_id)
  WHERE file_artifact_id IS NOT NULL
    AND active = TRUE
    AND deleted_at IS NULL;

COMMENT ON COLUMN public.ioc_suppressions.file_artifact_id IS
  'When set, suppression applies to the canonical file artifact (all proven exact hashes). NULL = exact observable only.';

-- Backfill uniquely-resolvable active hash suppressions.
-- NOTE: Postgres has no MIN(uuid); pick the sole survivor via DISTINCT ON.
WITH resolved AS (
  SELECT
    s.id AS suppression_id,
    COALESCE(
      CASE
        WHEN fa.status = 'merged' AND fa.merged_into_artifact_id IS NOT NULL
          THEN fa.merged_into_artifact_id
        ELSE fa.id
      END,
      fa.id
    ) AS survivor_artifact_id
  FROM public.ioc_suppressions s
  JOIN public.file_artifact_hashes h
    ON h.hash_type = lower(s.ioc_type)
   AND h.normalized_hash_value = lower(s.ioc_value)
  JOIN public.file_artifacts fa ON fa.id = h.artifact_id
  WHERE s.file_artifact_id IS NULL
    AND s.active = TRUE
    AND s.deleted_at IS NULL
    AND (s.expires_at IS NULL OR s.expires_at > NOW())
    AND lower(s.ioc_type) IN ('md5', 'sha1', 'sha256')
),
unique_ids AS (
  SELECT suppression_id
  FROM resolved
  GROUP BY suppression_id
  HAVING COUNT(DISTINCT survivor_artifact_id) = 1
),
unique_resolved AS (
  SELECT DISTINCT ON (r.suppression_id)
         r.suppression_id,
         r.survivor_artifact_id AS artifact_id
  FROM resolved r
  JOIN unique_ids u ON u.suppression_id = r.suppression_id
  ORDER BY r.suppression_id, r.survivor_artifact_id
)
UPDATE public.ioc_suppressions s
   SET file_artifact_id = u.artifact_id,
       updated_at = NOW()
  FROM unique_resolved u
 WHERE s.id = u.suppression_id
   AND s.file_artifact_id IS NULL;
