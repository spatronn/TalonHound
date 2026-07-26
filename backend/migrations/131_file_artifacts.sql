-- File Artifacts: exact-hash identity layer for md5/sha1/sha256 IOCs.
-- Additive only. Does not rewrite/delete ioc_items or dependent FK rows.
-- Backfill is a separate idempotent script (integration/backfill-file-artifacts.js).

-- ---------------------------------------------------------------------------
-- file_artifacts: one logical/physical file
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_artifacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  primary_hash_id UUID NULL,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'merged')),
  merged_into_artifact_id UUID NULL REFERENCES file_artifacts (id),
  file_name TEXT NULL,
  file_type TEXT NULL,
  mime_type TEXT NULL,
  size_bytes BIGINT NULL,
  first_seen_at TIMESTAMPTZ NULL,
  last_seen_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT file_artifacts_merged_requires_target CHECK (
    (status = 'merged' AND merged_into_artifact_id IS NOT NULL)
    OR (status = 'active' AND merged_into_artifact_id IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_file_artifacts_status_active
  ON file_artifacts (created_at)
  WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_file_artifacts_merged_into
  ON file_artifacts (merged_into_artifact_id)
  WHERE merged_into_artifact_id IS NOT NULL;

COMMENT ON TABLE file_artifacts IS
  'Logical file identity. Exact hashes (md5/sha1/sha256) are identifiers; IOC rows link via file_artifact_ioc_links.';

-- ---------------------------------------------------------------------------
-- file_artifact_hashes: exact identity hashes only
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_artifact_hashes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id UUID NOT NULL REFERENCES file_artifacts (id) ON DELETE CASCADE,
  hash_type TEXT NOT NULL
    CHECK (hash_type IN ('md5', 'sha1', 'sha256')),
  normalized_hash_value TEXT NOT NULL,
  is_primary BOOLEAN NOT NULL DEFAULT FALSE,
  first_seen_at TIMESTAMPTZ NULL,
  last_seen_at TIMESTAMPTZ NULL,
  verification_source TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT file_artifact_hashes_value_format CHECK (
    (hash_type = 'md5' AND normalized_hash_value ~ '^[a-f0-9]{32}$')
    OR (hash_type = 'sha1' AND normalized_hash_value ~ '^[a-f0-9]{40}$')
    OR (hash_type = 'sha256' AND normalized_hash_value ~ '^[a-f0-9]{64}$')
  )
);

-- Global uniqueness: same exact hash cannot belong to two artifacts
CREATE UNIQUE INDEX IF NOT EXISTS uq_file_artifact_hashes_type_value
  ON file_artifact_hashes (hash_type, normalized_hash_value);

-- One value per hash_type per artifact
CREATE UNIQUE INDEX IF NOT EXISTS uq_file_artifact_hashes_artifact_type
  ON file_artifact_hashes (artifact_id, hash_type);

-- One primary hash per artifact
CREATE UNIQUE INDEX IF NOT EXISTS uq_file_artifact_hashes_one_primary
  ON file_artifact_hashes (artifact_id)
  WHERE is_primary = TRUE;

CREATE INDEX IF NOT EXISTS idx_file_artifact_hashes_artifact
  ON file_artifact_hashes (artifact_id);

-- Deferrable FK from artifacts.primary_hash_id → hashes.id (set after hashes exist)
ALTER TABLE file_artifacts
  DROP CONSTRAINT IF EXISTS file_artifacts_primary_hash_id_fkey;

ALTER TABLE file_artifacts
  ADD CONSTRAINT file_artifacts_primary_hash_id_fkey
  FOREIGN KEY (primary_hash_id) REFERENCES file_artifact_hashes (id)
  ON DELETE SET NULL;

COMMENT ON TABLE file_artifact_hashes IS
  'Exact cryptographic hashes that identify a file_artifact. IMPHASH/TLSH/SSDEEP are not stored here.';

-- ---------------------------------------------------------------------------
-- file_artifact_ioc_links: preserve existing IOC UUIDs / public_ids
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_artifact_ioc_links (
  id BIGSERIAL PRIMARY KEY,
  artifact_id UUID NOT NULL REFERENCES file_artifacts (id) ON DELETE CASCADE,
  ioc_item_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  ioc_public_id UUID NOT NULL,
  linked_hash_id UUID NULL REFERENCES file_artifact_hashes (id) ON DELETE SET NULL,
  is_canonical_ioc BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (ioc_observable_type, ioc_item_id),
  FOREIGN KEY (ioc_observable_type, ioc_item_id)
    REFERENCES ioc_items (observable_type, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_file_artifact_ioc_links_artifact
  ON file_artifact_ioc_links (artifact_id);

CREATE INDEX IF NOT EXISTS idx_file_artifact_ioc_links_public_id
  ON file_artifact_ioc_links (ioc_public_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_file_artifact_ioc_links_one_canonical
  ON file_artifact_ioc_links (artifact_id)
  WHERE is_canonical_ioc = TRUE;

COMMENT ON TABLE file_artifact_ioc_links IS
  'Maps legacy ioc_items rows to file_artifacts without rewriting dependent FK tables.';

-- ---------------------------------------------------------------------------
-- file_artifact_source_observations: raw source attribution (observed-as)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_artifact_source_observations (
  id BIGSERIAL PRIMARY KEY,
  artifact_id UUID NOT NULL REFERENCES file_artifacts (id) ON DELETE CASCADE,
  source_name TEXT NOT NULL,
  feed_id UUID NULL,
  source_membership_id BIGINT NULL,
  source_record_id TEXT NULL,
  observed_hash_id UUID NULL REFERENCES file_artifact_hashes (id) ON DELETE SET NULL,
  observed_hash_type TEXT NOT NULL
    CHECK (observed_hash_type IN ('md5', 'sha1', 'sha256')),
  observed_hash_value TEXT NOT NULL,
  observation_type TEXT NOT NULL
    CHECK (observation_type IN (
      'direct_source_observation',
      'provider_hash_mapping',
      'enrichment_derived',
      'manual_verified',
      'migration_backfill'
    )),
  relation_method TEXT NOT NULL
    CHECK (relation_method IN (
      'same_source_record',
      'provider_exact_hash_set',
      'enrichment_result',
      'manual_merge',
      'migration_seed'
    )),
  confidence TEXT NULL,
  first_seen_in_source TIMESTAMPTZ NULL,
  last_seen_in_source TIMESTAMPTZ NULL,
  last_changed_in_source TIMESTAMPTZ NULL,
  raw_ref JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_file_artifact_source_observations_artifact
  ON file_artifact_source_observations (artifact_id);

CREATE INDEX IF NOT EXISTS idx_file_artifact_source_observations_feed
  ON file_artifact_source_observations (feed_id)
  WHERE feed_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_file_artifact_source_observations_lookup
  ON file_artifact_source_observations (
    artifact_id,
    source_name,
    observed_hash_type,
    observed_hash_value,
    observation_type
  );

COMMENT ON TABLE file_artifact_source_observations IS
  'Preserves which hash each source actually provided. Never attribute unobserved hashes to a source.';

-- ---------------------------------------------------------------------------
-- file_artifact_non_identity_attrs: imphash/tlsh/ssdeep (NOT merge evidence)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_artifact_non_identity_attrs (
  id BIGSERIAL PRIMARY KEY,
  artifact_id UUID NOT NULL REFERENCES file_artifacts (id) ON DELETE CASCADE,
  attr_type TEXT NOT NULL
    CHECK (attr_type IN ('imphash', 'tlsh', 'ssdeep')),
  attr_value TEXT NOT NULL,
  source_name TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (artifact_id, attr_type, attr_value)
);

CREATE INDEX IF NOT EXISTS idx_file_artifact_non_identity_attrs_artifact
  ON file_artifact_non_identity_attrs (artifact_id);

COMMENT ON TABLE file_artifact_non_identity_attrs IS
  'Structural/similarity attributes. Never used alone as automatic merge evidence.';

-- ---------------------------------------------------------------------------
-- file_artifact_merge_conflicts: conflicting exact-hash mappings
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS file_artifact_merge_conflicts (
  id BIGSERIAL PRIMARY KEY,
  conflicting_hash_type TEXT NOT NULL
    CHECK (conflicting_hash_type IN ('md5', 'sha1', 'sha256')),
  conflicting_hash_value TEXT NOT NULL,
  candidate_artifact_ids UUID[] NOT NULL DEFAULT '{}',
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'resolved', 'ignored')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ NULL,
  resolution_metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_file_artifact_merge_conflicts_open
  ON file_artifact_merge_conflicts (created_at)
  WHERE status = 'open';

CREATE INDEX IF NOT EXISTS idx_file_artifact_merge_conflicts_hash
  ON file_artifact_merge_conflicts (conflicting_hash_type, conflicting_hash_value);

COMMENT ON TABLE file_artifact_merge_conflicts IS
  'Records conflicting exact-hash mappings that block automatic merge (e.g. MD5 X → two SHA256s).';
