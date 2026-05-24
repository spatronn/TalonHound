CREATE TABLE IF NOT EXISTS ioc_suppressions (
  id BIGSERIAL PRIMARY KEY,
  ioc_value TEXT NOT NULL,
  ioc_type TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'global',
  source_name TEXT NULL,
  reason TEXT NOT NULL,
  created_by TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_ioc_suppressions_ioc
  ON ioc_suppressions (ioc_value, ioc_type);

CREATE INDEX IF NOT EXISTS idx_ioc_suppressions_active_expires
  ON ioc_suppressions (active, expires_at);

CREATE INDEX IF NOT EXISTS idx_ioc_suppressions_scope_source
  ON ioc_suppressions (scope, source_name);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_suppressions_active_scope
  ON ioc_suppressions (lower(ioc_value), lower(ioc_type), scope, COALESCE(lower(source_name), ''))
  WHERE active = TRUE;
