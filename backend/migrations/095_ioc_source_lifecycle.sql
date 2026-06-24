-- IOC source archive lifecycle + manual source move provenance history

ALTER TABLE ioc_sources
  ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS archived_by UUID NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_sources_archived_at
  ON ioc_sources (archived_at)
  WHERE archived_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS ioc_manual_source_memberships (
  id BIGSERIAL PRIMARY KEY,
  ioc_item_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  ioc_source_id BIGINT NOT NULL REFERENCES ioc_sources(id) ON DELETE RESTRICT,
  source_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'moved'
    CHECK (status IN ('active', 'moved', 'superseded', 'inactive')),
  confidence TEXT NULL,
  confidence_source TEXT NULL,
  confidence_source_name TEXT NULL,
  manual_expires_at TIMESTAMPTZ NULL,
  moved_to_source_id BIGINT NULL REFERENCES ioc_sources(id) ON DELETE SET NULL,
  moved_at TIMESTAMPTZ NULL,
  moved_by UUID NULL,
  move_reason TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  first_seen_at TIMESTAMPTZ NULL,
  last_seen_at TIMESTAMPTZ NULL,
  UNIQUE (ioc_item_id, ioc_observable_type, ioc_source_id)
);

CREATE INDEX IF NOT EXISTS idx_ioc_manual_source_memberships_ioc
  ON ioc_manual_source_memberships (ioc_item_id, ioc_observable_type);

CREATE INDEX IF NOT EXISTS idx_ioc_manual_source_memberships_source
  ON ioc_manual_source_memberships (ioc_source_id);

CREATE INDEX IF NOT EXISTS idx_ioc_manual_source_memberships_moved_to
  ON ioc_manual_source_memberships (moved_to_source_id)
  WHERE moved_to_source_id IS NOT NULL;
