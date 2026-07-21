-- Unify manual + feed tags into a shared catalog with assignment-level origin.
-- Idempotent where practical. Fail-fast on unsafe duplicate merges.
SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

-- ---------------------------------------------------------------------------
-- 1) Normalize existing tag names (whitespace collapse) when conflict-free
-- ---------------------------------------------------------------------------
UPDATE tags t
SET name = lower(trim(regexp_replace(t.name, '\s+', ' ', 'g'))),
    updated_at = NOW()
WHERE t.name IS DISTINCT FROM lower(trim(regexp_replace(t.name, '\s+', ' ', 'g')))
  AND NOT EXISTS (
    SELECT 1
    FROM tags o
    WHERE o.id <> t.id
      AND o.name = lower(trim(regexp_replace(t.name, '\s+', ' ', 'g')))
  );

-- ---------------------------------------------------------------------------
-- 2) Merge remaining case/whitespace duplicates into one canonical tag
--    Winner: prefer enabled, then lowest id. Never flip enabled on winner.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  r RECORD;
  winner_id BIGINT;
  loser_id BIGINT;
  loser_ids BIGINT[];
  conflict_slug TEXT;
BEGIN
  FOR r IN
    SELECT lower(trim(regexp_replace(name, '\s+', ' ', 'g'))) AS norm_name,
           array_agg(id ORDER BY enabled DESC, id ASC) AS ids
    FROM tags
    GROUP BY lower(trim(regexp_replace(name, '\s+', ' ', 'g')))
    HAVING COUNT(*) > 1
  LOOP
    winner_id := r.ids[1];
    loser_ids := r.ids[2:array_length(r.ids, 1)];

    -- Ensure winner name is canonical.
    UPDATE tags
    SET name = r.norm_name,
        updated_at = NOW()
    WHERE id = winner_id
      AND name IS DISTINCT FROM r.norm_name;

    FOREACH loser_id IN ARRAY loser_ids LOOP
      -- Fail-fast if loser slug would collide with a third unrelated tag after merge.
      SELECT t.slug INTO conflict_slug
      FROM tags t
      WHERE t.id = loser_id;

      IF conflict_slug IS NOT NULL AND EXISTS (
        SELECT 1 FROM tags w
        WHERE w.id = winner_id
          AND w.slug = conflict_slug
          AND w.id <> loser_id
      ) THEN
        -- Winner already owns same slug — fine; loser will be deleted.
        NULL;
      ELSIF conflict_slug IS NOT NULL AND EXISTS (
        SELECT 1 FROM tags o
        WHERE o.id NOT IN (winner_id, loser_id)
          AND o.slug = conflict_slug
      ) THEN
        RAISE EXCEPTION 'Cannot merge tag id % into %: slug % conflicts with another tag',
          loser_id, winner_id, conflict_slug;
      END IF;

      -- Move assignments to winner; drop duplicates.
      UPDATE ioc_tags
      SET tag_id = winner_id
      WHERE tag_id = loser_id
        AND NOT EXISTS (
          SELECT 1 FROM ioc_tags keep
          WHERE keep.ioc_id = ioc_tags.ioc_id
            AND keep.tag_id = winner_id
        );

      DELETE FROM ioc_tags WHERE tag_id = loser_id;
      DELETE FROM tags WHERE id = loser_id;
    END LOOP;
  END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 3) Catalog provenance
-- ---------------------------------------------------------------------------
ALTER TABLE tags
  ADD COLUMN IF NOT EXISTS created_origin TEXT;

UPDATE tags
SET created_origin = 'manual'
WHERE created_origin IS NULL OR btrim(created_origin) = '';

ALTER TABLE tags
  ALTER COLUMN created_origin SET DEFAULT 'manual';

ALTER TABLE tags
  ALTER COLUMN created_origin SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'tags_created_origin_chk'
  ) THEN
    ALTER TABLE tags
      ADD CONSTRAINT tags_created_origin_chk
      CHECK (created_origin IN ('manual', 'integration'));
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 4) Assignment origin / source
-- ---------------------------------------------------------------------------
ALTER TABLE ioc_tags
  ADD COLUMN IF NOT EXISTS origin TEXT;

ALTER TABLE ioc_tags
  ADD COLUMN IF NOT EXISTS source_name TEXT;

ALTER TABLE ioc_tags
  ADD COLUMN IF NOT EXISTS source_key TEXT;

UPDATE ioc_tags
SET origin = 'manual'
WHERE origin IS NULL OR btrim(origin) = '';

UPDATE ioc_tags
SET source_name = NULL,
    source_key = ''
WHERE origin = 'manual';

UPDATE ioc_tags
SET source_key = lower(source_name)
WHERE origin = 'integration'
  AND source_name IS NOT NULL
  AND (source_key IS NULL OR source_key = '');

ALTER TABLE ioc_tags
  ALTER COLUMN origin SET DEFAULT 'manual';

ALTER TABLE ioc_tags
  ALTER COLUMN origin SET NOT NULL;

ALTER TABLE ioc_tags
  ALTER COLUMN source_key SET DEFAULT '';

UPDATE ioc_tags SET source_key = '' WHERE source_key IS NULL;

ALTER TABLE ioc_tags
  ALTER COLUMN source_key SET NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'ioc_tags_origin_chk'
  ) THEN
    ALTER TABLE ioc_tags
      ADD CONSTRAINT ioc_tags_origin_chk
      CHECK (origin IN ('manual', 'integration'));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'ioc_tags_origin_source_chk'
  ) THEN
    ALTER TABLE ioc_tags
      ADD CONSTRAINT ioc_tags_origin_source_chk
      CHECK (
        (origin = 'manual' AND source_name IS NULL AND source_key = '')
        OR (origin = 'integration' AND source_name IS NOT NULL AND btrim(source_name) <> '' AND source_key = lower(source_name))
      );
  END IF;
END $$;

-- Replace composite PK with origin-aware unique key.
ALTER TABLE ioc_tags DROP CONSTRAINT IF EXISTS ioc_tags_pkey;

DROP INDEX IF EXISTS uq_ioc_tags_assignment;
CREATE UNIQUE INDEX uq_ioc_tags_assignment
  ON ioc_tags (ioc_id, tag_id, origin, source_key);

-- ---------------------------------------------------------------------------
-- 5) Backfill integration assignments from feed evidence notes (tags=...)
--    Does NOT re-enable inactive catalog tags.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  rec RECORD;
  tag_id BIGINT;
  base_slug TEXT;
  candidate_slug TEXT;
  i INT;
BEGIN
  FOR rec IN
    SELECT DISTINCT
      lower(trim(regexp_replace(raw_tag, '\s+', ' ', 'g'))) AS tag_name
    FROM ioc_feed_source_evidence e
    CROSS JOIN LATERAL (
      SELECT trim(both FROM x) AS raw_tag
      FROM unnest(
        string_to_array(
          NULLIF(trim(substring(e.note FROM 'tags=([^|]+)')), ''),
          ','
        )
      ) AS x
    ) parts
    WHERE e.note IS NOT NULL
      AND e.note ~* 'tags='
      AND raw_tag IS NOT NULL
      AND btrim(raw_tag) <> ''
  LOOP
    IF rec.tag_name IS NULL OR rec.tag_name = '' OR char_length(rec.tag_name) > 100 THEN
      CONTINUE;
    END IF;

    SELECT t.id INTO tag_id FROM tags t WHERE t.name = rec.tag_name LIMIT 1;
    IF tag_id IS NOT NULL THEN
      CONTINUE;
    END IF;

    base_slug := regexp_replace(regexp_replace(rec.tag_name, '[^a-z0-9]+', '-', 'g'), '^-+|-+$', '', 'g');
    IF base_slug IS NULL OR base_slug = '' THEN
      base_slug := 'tag';
    END IF;

    candidate_slug := base_slug;
    i := 0;
    WHILE EXISTS (SELECT 1 FROM tags WHERE slug = candidate_slug) LOOP
      i := i + 1;
      candidate_slug := base_slug || '-' || i::text;
      IF i > 50 THEN
        candidate_slug := base_slug || '-' || substr(md5(rec.tag_name), 1, 8);
        EXIT;
      END IF;
    END LOOP;

    INSERT INTO tags (name, slug, type, category, enabled, created_origin, updated_at)
    VALUES (rec.tag_name, candidate_slug, 'context'::tag_type, 'custom', TRUE, 'integration', NOW())
    ON CONFLICT (name) DO NOTHING;
  END LOOP;
END $$;

INSERT INTO ioc_tags (ioc_id, ioc_observable_type, tag_id, origin, source_name, source_key)
SELECT DISTINCT
  e.ioc_item_id,
  e.ioc_observable_type,
  t.id,
  'integration',
  e.source_name,
  lower(e.source_name)
FROM ioc_feed_source_evidence e
CROSS JOIN LATERAL (
  SELECT trim(both FROM x) AS raw_tag
  FROM unnest(
    string_to_array(
      NULLIF(trim(substring(e.note FROM 'tags=([^|]+)')), ''),
      ','
    )
  ) AS x
) parts
JOIN tags t
  ON t.name = lower(trim(regexp_replace(parts.raw_tag, '\s+', ' ', 'g')))
WHERE e.note IS NOT NULL
  AND e.note ~* 'tags='
  AND e.source_name IS NOT NULL
  AND btrim(e.source_name) <> ''
  AND parts.raw_tag IS NOT NULL
  AND btrim(parts.raw_tag) <> ''
  AND char_length(lower(trim(regexp_replace(parts.raw_tag, '\s+', ' ', 'g')))) BETWEEN 1 AND 100
ON CONFLICT (ioc_id, tag_id, origin, source_key) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 6) Keep name uniqueness / lower check (already present); refresh name index
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS uq_tags_name ON tags (name);
