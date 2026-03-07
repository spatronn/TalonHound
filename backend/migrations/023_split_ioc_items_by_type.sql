-- Split unified ioc_items table into per-type partitions (ioc_ip, ioc_domain, etc.)
-- while keeping the logical API/table name as ioc_items so existing code continues
-- to work without changes.
--
-- This migration assumes earlier IOC-related migrations (008, 009, 014, 018, 021, 022)
-- have already been applied on the existing ioc_items table.

-- 1) Rename existing table to keep data during migration.
ALTER TABLE ioc_items RENAME TO ioc_items_old;

-- 2) Recreate ioc_items as a partitioned parent table with the same logical schema.
--    public_id uses gen_random_uuid(); pgcrypto extension was created in migration 018.
CREATE TABLE ioc_items (
  id BIGSERIAL PRIMARY KEY,
  observable TEXT NOT NULL,
  observable_type TEXT NOT NULL,
  source_name TEXT NOT NULL,
  source_url TEXT,
  confidence TEXT NOT NULL DEFAULT 'medium',
  category TEXT,
  note TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  public_id UUID NOT NULL DEFAULT gen_random_uuid()
)
PARTITION BY LIST (observable_type);

-- 3) Create per-type partitions so IOC'ler fiziksel olarak ayrı tablolarda dursun.
CREATE TABLE ioc_ip PARTITION OF ioc_items
  FOR VALUES IN ('ip');

CREATE TABLE ioc_ip6 PARTITION OF ioc_items
  FOR VALUES IN ('ip6');

CREATE TABLE ioc_domain PARTITION OF ioc_items
  FOR VALUES IN ('domain');

CREATE TABLE ioc_url PARTITION OF ioc_items
  FOR VALUES IN ('url');

-- Tüm dosya hash tiplerini tek tabloda grupla (md5, sha1, sha256, ssdeep, imphash, tlsh).
CREATE TABLE ioc_file_hash PARTITION OF ioc_items
  FOR VALUES IN ('md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh');

-- Gelecekte eklenebilecek yeni observable_type degerleri icin default partition.
CREATE TABLE ioc_items_other PARTITION OF ioc_items
  DEFAULT;

-- 4) Move existing data into the new partitioned structure.
INSERT INTO ioc_items (
  id,
  observable,
  observable_type,
  source_name,
  source_url,
  confidence,
  category,
  note,
  first_seen_at,
  last_seen_at,
  created_at,
  public_id
)
SELECT
  id,
  observable,
  observable_type,
  source_name,
  source_url,
  confidence,
  category,
  note,
  first_seen_at,
  last_seen_at,
  created_at,
  public_id
FROM ioc_items_old;

-- 5) Drop old table and its old indexes; from this point forward only the new
--    partitioned layout is used.
DROP TABLE IF EXISTS ioc_items_old CASCADE;

-- 6) Reset sequence so new inserts continue from the correct id.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'S'
      AND c.relname = 'ioc_items_id_seq'
  ) THEN
    PERFORM setval(
      'ioc_items_id_seq',
      (SELECT COALESCE(MAX(id), 0) + 1 FROM ioc_items),
      false
    );
  END IF;
END
$$;

-- 7) Recreate critical indexes and constraints on the new structure.

-- Same logical uniqueness as uq_ioc_items_dedup in migration 008.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_items_dedup
ON ioc_items (
  observable,
  observable_type,
  source_name,
  confidence,
  COALESCE(category, ''),
  COALESCE(source_url, '')
);

-- Same logical uniqueness as uq_ioc_items_public_id in migration 018.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_items_public_id
ON ioc_items (public_id);

-- Core btree indexes for common filters/sorting.
CREATE INDEX IF NOT EXISTS idx_ioc_items_created_at
ON ioc_items (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_items_observable_type_observable
ON ioc_items (observable_type, observable);

CREATE INDEX IF NOT EXISTS idx_ioc_items_source
ON ioc_items (source_name);

CREATE INDEX IF NOT EXISTS idx_ioc_items_confidence
ON ioc_items (confidence);

-- GIN trigram indexes for text search (migration 009 equivalent).
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_ioc_items_observable_trgm
ON ioc_items USING gin (observable gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_ioc_items_source_trgm
ON ioc_items USING gin (source_name gin_trgm_ops);

-- Scale-oriented indexes (migration 021 equivalents).

-- IP-only index used by geo cache refresh and IP lookups: create it directly
-- on the IP partition instead of a partial index on the parent.
CREATE INDEX IF NOT EXISTS idx_ioc_ip_observable
ON ioc_ip (observable);

-- Covering index for "ORDER BY created_at DESC LIMIT N" list queries.
CREATE INDEX IF NOT EXISTS idx_ioc_items_created_at_desc_covering
ON ioc_items (created_at DESC)
INCLUDE (id, public_id, observable, observable_type, source_name, confidence, category);

CREATE INDEX IF NOT EXISTS idx_ioc_items_source_created_at_desc
ON ioc_items (source_name, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_items_confidence_created_at_desc
ON ioc_items (confidence, created_at DESC);

-- Planner statistics for better cardinality estimates at high row counts.
ALTER TABLE ioc_items ALTER COLUMN observable SET STATISTICS 500;
ALTER TABLE ioc_items ALTER COLUMN source_name SET STATISTICS 500;
ALTER TABLE ioc_items ALTER COLUMN created_at SET STATISTICS 500;

-- Hash-prefixed IOC searches from note (migration 022 equivalents).
CREATE INDEX IF NOT EXISTS idx_ioc_items_md5_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'md5=', 2), '|', 1), ''))));

CREATE INDEX IF NOT EXISTS idx_ioc_items_sha1_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'sha1=', 2), '|', 1), ''))));

CREATE INDEX IF NOT EXISTS idx_ioc_items_sha256_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'sha256=', 2), '|', 1), ''))));

CREATE INDEX IF NOT EXISTS idx_ioc_items_ssdeep_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'ssdeep=', 2), '|', 1), ''))));

CREATE INDEX IF NOT EXISTS idx_ioc_items_imphash_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'imphash=', 2), '|', 1), ''))));

CREATE INDEX IF NOT EXISTS idx_ioc_items_tlsh_from_note
ON ioc_items ((LOWER(NULLIF(SPLIT_PART(SPLIT_PART(REPLACE(COALESCE(note, ''), ' ', ''), 'tlsh=', 2), '|', 1), ''))));

ANALYZE ioc_items;

