-- Reparent file_artifact_ioc_links left on merged tombstones.
--
-- Bug: mergeFileArtifacts treated a link's own unique (type, ioc_item_id) row as
-- a collision and skipped the UPDATE, so hashes moved to the canonical artifact
-- while IOC links stayed on status='merged' tombstones. Reads that list links
-- for the surviving artifact then missed MD5/SHA1 aliases — VirusTotal reuse and
-- Threat Context both looked empty from the canonical SHA256 IOC even though the
-- enrichment / matched_ioc_id rows still existed on the alias IOC.
--
-- This migration is additive and idempotent:
--   1) Move links one merged_into hop at a time (up to 5) when the target does
--      not already have the same (type, ioc_item_id).
--   2) Delete remaining tombstone duplicates when the canonical already has them.
--   3) Ensure each touched active artifact has exactly one is_canonical_ioc link
--      (SHA256 > SHA1 > MD5).
--
-- Does not delete ioc_items, ioc_enrichments, or Threat Library rows.

DO $$
DECLARE
  moved integer;
  hop integer := 0;
BEGIN
  LOOP
    hop := hop + 1;
    UPDATE public.file_artifact_ioc_links AS l
       SET artifact_id = a.merged_into_artifact_id,
           is_canonical_ioc = FALSE
      FROM public.file_artifacts AS a
     WHERE l.artifact_id = a.id
       AND a.status = 'merged'
       AND a.merged_into_artifact_id IS NOT NULL
       AND NOT EXISTS (
             SELECT 1
               FROM public.file_artifact_ioc_links AS x
              WHERE x.ioc_observable_type = l.ioc_observable_type
                AND x.ioc_item_id = l.ioc_item_id
                AND x.artifact_id = a.merged_into_artifact_id
           );
    GET DIAGNOSTICS moved = ROW_COUNT;
    EXIT WHEN moved = 0 OR hop >= 5;
  END LOOP;
END $$;

-- Tombstone links that already exist on the surviving artifact are safe to drop.
DELETE FROM public.file_artifact_ioc_links AS l
 USING public.file_artifacts AS a
 WHERE l.artifact_id = a.id
   AND a.status = 'merged'
   AND a.merged_into_artifact_id IS NOT NULL
   AND EXISTS (
         SELECT 1
           FROM public.file_artifact_ioc_links AS x
          WHERE x.ioc_observable_type = l.ioc_observable_type
            AND x.ioc_item_id = l.ioc_item_id
            AND x.artifact_id = a.merged_into_artifact_id
       );

-- Repair canonical flags on active artifacts that have zero or many canonicals
-- after the reparent (moved links always clear is_canonical_ioc).
WITH broken AS (
  SELECT a.id AS artifact_id
    FROM public.file_artifacts a
    JOIN public.file_artifact_ioc_links l ON l.artifact_id = a.id
   WHERE a.status = 'active'
   GROUP BY a.id
  HAVING COUNT(*) FILTER (WHERE l.is_canonical_ioc) <> 1
),
ranked AS (
  SELECT l.id,
         ROW_NUMBER() OVER (
           PARTITION BY l.artifact_id
           ORDER BY CASE l.ioc_observable_type
                      WHEN 'sha256' THEN 0
                      WHEN 'sha1' THEN 1
                      WHEN 'md5' THEN 2
                      ELSE 9
                    END,
                    l.id
         ) AS rn
    FROM public.file_artifact_ioc_links l
    JOIN broken b ON b.artifact_id = l.artifact_id
)
UPDATE public.file_artifact_ioc_links AS l
   SET is_canonical_ioc = (r.rn = 1)
  FROM ranked r
 WHERE l.id = r.id;
