-- Spamhaus DROP CIDR dataset (hard-replace on each successful sync)
CREATE TABLE IF NOT EXISTS spamhaus_drop_entries (
  id          BIGSERIAL PRIMARY KEY,
  list_type   TEXT NOT NULL,           -- 'drop_v4' | 'drop_v6'
  cidr        CIDR NOT NULL,
  sblid       TEXT NULL,
  rir         TEXT NULL,
  raw_json    JSONB NULL,
  synced_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_spamhaus_drop_entries_list_cidr
  ON spamhaus_drop_entries (list_type, cidr);

-- GiST index enables fast containment queries ($ip::inet << cidr)
CREATE INDEX IF NOT EXISTS idx_spamhaus_drop_entries_cidr
  ON spamhaus_drop_entries USING gist (cidr inet_ops);

-- Per-list-type operational sync state
CREATE TABLE IF NOT EXISTS spamhaus_drop_sync_state (
  list_type            TEXT PRIMARY KEY,
  last_success_at      TIMESTAMPTZ NULL,
  last_attempt_at      TIMESTAMPTZ NULL,
  next_run_at          TIMESTAMPTZ NULL,
  status               TEXT NOT NULL DEFAULT 'never_synced',
  entry_count          INTEGER NOT NULL DEFAULT 0,
  added_count          INTEGER NULL,
  removed_count        INTEGER NULL,
  source_url           TEXT NULL,
  dataset_sha256       TEXT NULL,
  error_message        TEXT NULL,
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO spamhaus_drop_sync_state (list_type, status, updated_at)
VALUES
  ('drop_v4', 'never_synced', NOW()),
  ('drop_v6', 'never_synced', NOW())
ON CONFLICT (list_type) DO NOTHING;

-- Global provider config (enabled, sync_interval_hours, timeout)
INSERT INTO threat_intel_provider_configs (provider, enabled, ttl_hours, timeout_ms, config)
VALUES (
  'spamhaus_drop',
  false,
  24,
  30000,
  '{"sync_interval_hours":24}'::jsonb
)
ON CONFLICT (provider) DO NOTHING;
