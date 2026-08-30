-- Production installs that predated the generation_id FK on published_feed_generation_chunks
-- could accumulate orphan manifest rows when superseded generations were deleted, which in
-- turn kept chunk files reachable forever. Repair links, then enforce CASCADE.

DELETE FROM public.published_feed_generation_chunks gc
WHERE NOT EXISTS (
  SELECT 1 FROM public.published_feed_generations g WHERE g.id = gc.generation_id
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'published_feed_generation_chunks_generation_id_fkey'
  ) THEN
    ALTER TABLE public.published_feed_generation_chunks
      ADD CONSTRAINT published_feed_generation_chunks_generation_id_fkey
      FOREIGN KEY (generation_id)
      REFERENCES public.published_feed_generations(id)
      ON DELETE CASCADE;
  END IF;
END $$;
