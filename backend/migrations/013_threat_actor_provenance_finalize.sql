-- Finalize Threat Actor provenance: separate collision review state from catalog memberships.

ALTER TABLE public.threat_actors
  ADD COLUMN IF NOT EXISTS bundled_catalog_collision_pending boolean DEFAULT false NOT NULL;

COMMENT ON COLUMN public.threat_actors.bundled_catalog_collision_pending IS
  'True when a manual-only actor collides with a bundled canonical actor and awaits explicit operator confirmation.';

-- Migrate legacy fake membership marker into the dedicated collision flag.
UPDATE public.threat_actors
SET bundled_catalog_collision_pending = true
WHERE catalog_sources @> ARRAY['bundled-collision']::text[]
  AND bundled_catalog_collision_pending IS NOT TRUE;

UPDATE public.threat_actors
SET catalog_sources = array_remove(catalog_sources, 'bundled-collision')
WHERE catalog_sources @> ARRAY['bundled-collision']::text[];

COMMENT ON COLUMN public.threat_actors.catalog_sources IS
  'Catalog origin memberships: manual, bundled, legacy-seed, system.';
