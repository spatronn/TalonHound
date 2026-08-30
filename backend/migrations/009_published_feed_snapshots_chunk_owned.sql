-- Chunked Published Feeds retire legacy monolithic snapshot file pointers after
-- activation. Success rows then have content IS NULL AND storage_path IS NULL,
-- which violated the original chk_pf_snapshots_content_or_artifact invariant
-- (inline content OR legacy artifact path).
--
-- Extend the invariant so a success row is valid when it is explicitly marked
-- as superseded by an active chunk generation (params.chunk_owned = 'true').

ALTER TABLE public.published_feed_snapshots
  DROP CONSTRAINT IF EXISTS chk_pf_snapshots_content_or_artifact;

-- Repair already-retired success rows that lost storage_path during chunk
-- activation before this migration (left both content and storage_path null).
UPDATE public.published_feed_snapshots
SET params = COALESCE(params, '{}'::jsonb) || '{"chunk_owned":"true"}'::jsonb
WHERE status = 'success'
  AND content IS NULL
  AND storage_path IS NULL
  AND COALESCE(params->>'chunk_owned', 'false') <> 'true';

ALTER TABLE public.published_feed_snapshots
  ADD CONSTRAINT chk_pf_snapshots_content_or_artifact CHECK (
    (status <> 'success'::text)
    OR (content IS NOT NULL)
    OR (storage_path IS NOT NULL)
    OR (COALESCE(params->>'chunk_owned', 'false') = 'true')
  );
