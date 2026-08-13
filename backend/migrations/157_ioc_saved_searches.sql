-- Personal saved IOC Search DSL queries.
-- Ownership is users.id (not recyclable username). Names are unique per owner
-- case-insensitively. No sharing in v1.

CREATE TABLE IF NOT EXISTS ioc_saved_searches (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT NULL,
  original_query TEXT NOT NULL,
  normalized_query TEXT NOT NULL,
  normalized_ast JSONB NOT NULL,
  owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  owner_username TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_saved_searches_owner_name
  ON ioc_saved_searches (owner_id, lower(name));

CREATE INDEX IF NOT EXISTS idx_ioc_saved_searches_owner_updated
  ON ioc_saved_searches (owner_id, updated_at DESC);

-- DEPLOYMENT / ROLLBACK
-- ---------------------
-- Forward: additive table + indexes. Transaction-safe (no CONCURRENTLY).
-- Rollback: DROP TABLE IF EXISTS ioc_saved_searches;
