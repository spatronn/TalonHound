-- Additive state for identity-preserving USOM incremental ingestion.
-- Deliberately does not seed cursors: the first incremental request must
-- bootstrap from a complete reconciliation.

CREATE TABLE IF NOT EXISTS usom_import_cursors (
  feed_id UUID NOT NULL REFERENCES integration_feeds (integration_id) ON DELETE CASCADE,
  ioc_type TEXT NOT NULL,
  cursor_timestamp TIMESTAMPTZ NOT NULL,
  cursor_provider_id TEXT NOT NULL,
  last_incremental_started_at TIMESTAMPTZ NULL,
  last_incremental_completed_at TIMESTAMPTZ NULL,
  cursor_version INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (feed_id, ioc_type),
  CONSTRAINT usom_import_cursors_ioc_type_check
    CHECK (ioc_type IN ('domain', 'url', 'ip', 'ip6', 'ip6net'))
);

CREATE TABLE IF NOT EXISTS usom_import_state (
  feed_id UUID PRIMARY KEY REFERENCES integration_feeds (integration_id) ON DELETE CASCADE,
  full_snapshot_hash TEXT NULL,
  full_type_highwaters JSONB NOT NULL DEFAULT '{}'::jsonb,
  last_full_reconciliation_at TIMESTAMPTZ NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE ioc_feed_source_evidence
  ADD COLUMN IF NOT EXISTS provider_fingerprint TEXT NULL;

ALTER TABLE integration_runs
  ADD COLUMN IF NOT EXISTS run_mode TEXT NULL;

COMMENT ON TABLE usom_import_cursors IS
  'Per-USOM-feed/type successful high-water marks. Rows are created only after a complete successful fetch.';

COMMENT ON TABLE usom_import_state IS
  'USOM reconciliation state. Snapshot hash is an optimization and never replaces seen-row merging.';

COMMENT ON COLUMN ioc_feed_source_evidence.provider_fingerprint IS
  'Provider-scoped semantic fingerprint used to avoid evidence updates for volatile-only metadata changes.';

COMMENT ON COLUMN integration_runs.run_mode IS
  'Execution mode such as incremental, full_reconciliation, or dry_run.';
