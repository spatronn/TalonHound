-- Threat Actor catalog source memberships (manual vs bundled provenance).
-- Supports safe handling when a manual actor collides with a bundled canonical actor.

ALTER TABLE public.threat_actors
  ADD COLUMN IF NOT EXISTS catalog_sources text[] DEFAULT NULL;

COMMENT ON COLUMN public.threat_actors.catalog_sources IS
  'Catalog origin memberships: manual, bundled, legacy-seed, system, bundled-collision (pending review).';

-- Unknown sentinel
UPDATE public.threat_actors
SET catalog_sources = ARRAY['system']::text[]
WHERE slug = 'unknown'
  AND (catalog_sources IS NULL OR catalog_sources = '{}'::text[]);

-- Legacy TalonHound seed rows (reviewed bundled equivalents)
UPDATE public.threat_actors
SET catalog_sources = ARRAY['legacy-seed', 'bundled']::text[]
WHERE id IN (
  '8bd4f10c-0904-43cb-acdf-02aa0b0a81e6'::uuid,
  '92e08e97-5e84-4d29-920f-df0428d35dc7'::uuid,
  '364117ec-9e72-4531-956a-ba7f013f1b45'::uuid
)
AND (catalog_sources IS NULL OR catalog_sources = '{}'::text[]);

-- Rows created/updated by bundled or Malpedia import operators
UPDATE public.threat_actors
SET catalog_sources = ARRAY['bundled']::text[]
WHERE (catalog_sources IS NULL OR catalog_sources = '{}'::text[])
  AND (
    created_by IN ('bundled-seed', 'malpedia-bootstrap', 'system-seed')
    OR updated_by IN ('bundled-seed', 'malpedia-bootstrap')
  );

-- Explicit admin-created rows (email/user label present, not import operators)
UPDATE public.threat_actors
SET catalog_sources = ARRAY['manual']::text[]
WHERE catalog_sources IS NULL
  AND created_by IS NOT NULL
  AND created_by NOT IN ('bundled-seed', 'malpedia-bootstrap', 'system-seed');
