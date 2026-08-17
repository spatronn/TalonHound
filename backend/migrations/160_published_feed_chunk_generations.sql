-- Stable Published Feed chunks + immutable logical generations.
--
-- This migration is deliberately additive. It does not backfill the million-row
-- projection and it does not create the large projection/dirty-clock indexes inside
-- the transactional migration runner. The chunk bootstrap command performs a bounded
-- per-feed backfill and creates those indexes CONCURRENTLY before chunk activation.

SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

ALTER TABLE published_feed_items
  ADD COLUMN IF NOT EXISTS partition_identity TEXT,
  ADD COLUMN IF NOT EXISTS chunk_key INTEGER;

ALTER TABLE published_feeds
  ADD COLUMN IF NOT EXISTS chunk_count INTEGER,
  ADD COLUMN IF NOT EXISTS chunk_algo_version INTEGER,
  ADD COLUMN IF NOT EXISTS chunk_backfill_status TEXT NOT NULL DEFAULT 'absent',
  ADD COLUMN IF NOT EXISTS projection_pending_cutoff TIMESTAMPTZ;

ALTER TABLE published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_chunk_count;
ALTER TABLE published_feeds
  ADD CONSTRAINT chk_published_feeds_chunk_count CHECK (
    chunk_count IS NULL
    OR (chunk_count >= 64 AND chunk_count <= 512 AND (chunk_count & (chunk_count - 1)) = 0)
  );

ALTER TABLE published_feeds
  DROP CONSTRAINT IF EXISTS chk_published_feeds_chunk_backfill_status;
ALTER TABLE published_feeds
  ADD CONSTRAINT chk_published_feeds_chunk_backfill_status CHECK (
    chunk_backfill_status IN ('absent', 'backfilling', 'ready', 'failed', 'stale')
  );

CREATE TABLE IF NOT EXISTS published_feed_generations (
  id TEXT PRIMARY KEY,
  feed_id BIGINT NOT NULL REFERENCES published_feeds(id) ON DELETE CASCADE,
  snapshot_window TEXT NOT NULL,
  ioc_type_key TEXT NOT NULL,
  parent_generation_id TEXT REFERENCES published_feed_generations(id) ON DELETE SET NULL,
  state TEXT NOT NULL,
  candidate_cutoff TIMESTAMPTZ NOT NULL,
  generated_at TIMESTAMPTZ NOT NULL,
  activated_at TIMESTAMPTZ,
  superseded_at TIMESTAMPTZ,
  item_count BIGINT NOT NULL,
  chunk_count INTEGER NOT NULL,
  chunk_algo_version INTEGER NOT NULL,
  formats JSONB NOT NULL,
  config_hash TEXT NOT NULL,
  full_rebuild_reason TEXT,
  generation_metrics JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_pf_generations_state CHECK (
    state IN ('building', 'ready', 'active', 'superseded', 'failed')
  ),
  CONSTRAINT chk_pf_generations_formats CHECK (
    jsonb_typeof(formats) = 'array' AND jsonb_array_length(formats) > 0
  )
);

CREATE INDEX IF NOT EXISTS idx_pf_generations_feed_state
  ON published_feed_generations (feed_id, snapshot_window, ioc_type_key, state, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS uq_pf_generations_active
  ON published_feed_generations (feed_id, snapshot_window, ioc_type_key)
  WHERE state = 'active';

CREATE TABLE IF NOT EXISTS published_feed_generation_formats (
  generation_id TEXT NOT NULL REFERENCES published_feed_generations(id) ON DELETE CASCADE,
  format TEXT NOT NULL,
  serializer_version INTEGER NOT NULL,
  header_bytes TEXT NOT NULL DEFAULT '',
  footer_bytes TEXT NOT NULL DEFAULT '',
  separator_bytes TEXT NOT NULL DEFAULT '',
  item_count BIGINT NOT NULL,
  byte_length BIGINT NOT NULL,
  strong_etag TEXT NOT NULL,
  recency_head_path TEXT,
  recency_head_hash TEXT,
  recency_head_item_count INTEGER,
  recency_head_byte_length BIGINT,
  PRIMARY KEY (generation_id, format),
  CONSTRAINT chk_pf_generation_formats_format CHECK (format IN ('txt', 'json', 'stix'))
);

CREATE TABLE IF NOT EXISTS published_feed_chunks (
  id BIGSERIAL PRIMARY KEY,
  feed_id BIGINT NOT NULL REFERENCES published_feeds(id) ON DELETE CASCADE,
  snapshot_window TEXT NOT NULL,
  chunk_algo_version INTEGER NOT NULL,
  chunk_count INTEGER NOT NULL,
  chunk_key INTEGER NOT NULL,
  format TEXT NOT NULL,
  serializer_version INTEGER NOT NULL,
  content_hash TEXT NOT NULL,
  byte_length BIGINT NOT NULL,
  item_count BIGINT NOT NULL,
  storage_path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_pf_chunks_format CHECK (format IN ('txt', 'json', 'stix')),
  CONSTRAINT chk_pf_chunks_key CHECK (chunk_key >= 0 AND chunk_key < chunk_count),
  CONSTRAINT uq_pf_chunks_storage_path UNIQUE (storage_path),
  CONSTRAINT uq_pf_chunks_content UNIQUE (
    feed_id, snapshot_window, chunk_algo_version, chunk_count,
    chunk_key, format, serializer_version, content_hash
  )
);

CREATE INDEX IF NOT EXISTS idx_pf_chunks_feed_created
  ON published_feed_chunks (feed_id, created_at);

CREATE TABLE IF NOT EXISTS published_feed_generation_chunks (
  generation_id TEXT NOT NULL REFERENCES published_feed_generations(id) ON DELETE CASCADE,
  format TEXT NOT NULL,
  chunk_key INTEGER NOT NULL,
  chunk_id BIGINT NOT NULL REFERENCES published_feed_chunks(id) ON DELETE RESTRICT,
  ordinal INTEGER NOT NULL,
  PRIMARY KEY (generation_id, format, chunk_key),
  CONSTRAINT uq_pf_generation_chunks_ordinal UNIQUE (generation_id, format, ordinal),
  CONSTRAINT chk_pf_generation_chunks_format CHECK (format IN ('txt', 'json', 'stix'))
);

CREATE INDEX IF NOT EXISTS idx_pf_generation_chunks_chunk
  ON published_feed_generation_chunks (chunk_id);

CREATE TABLE IF NOT EXISTS published_feed_active_generations (
  feed_id BIGINT NOT NULL REFERENCES published_feeds(id) ON DELETE CASCADE,
  snapshot_window TEXT NOT NULL,
  ioc_type_key TEXT NOT NULL,
  generation_id TEXT NOT NULL REFERENCES published_feed_generations(id) ON DELETE RESTRICT,
  activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (feed_id, snapshot_window, ioc_type_key),
  CONSTRAINT uq_pf_active_generation UNIQUE (generation_id)
);

-- Deployment, after this transaction:
--   1. Run the chunk backfill command per allowlisted feed.
--   2. The command creates these indexes CONCURRENTLY (IF NOT EXISTS):
--        idx_pf_items_feed_window_chunk_order
--        idx_ioc_items_updated_at
--        idx_ioc_feed_memberships_updated_at
--        idx_file_artifacts_updated_at
--   3. Chunk activation refuses feeds whose chunk_backfill_status is not 'ready'.
--
-- Rollback: disable PUBLISHED_FEED_CHUNKED_ENABLED. Legacy snapshot rows/files are
-- untouched. Tables/columns are intentionally retained for a later cleanup release.
