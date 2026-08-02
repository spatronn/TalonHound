-- Multi-value threat actors per IOC (junction table + legacy FK backfill).
SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

CREATE TABLE IF NOT EXISTS ioc_threat_actors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ioc_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  threat_actor_id UUID NOT NULL REFERENCES threat_actors(id),
  source_type TEXT NOT NULL DEFAULT 'analyst',
  source_name TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT NULL,
  updated_by TEXT NULL,
  CONSTRAINT uq_ioc_threat_actors_ioc_actor UNIQUE (ioc_id, ioc_observable_type, threat_actor_id),
  CONSTRAINT fk_ioc_threat_actors_ioc
    FOREIGN KEY (ioc_observable_type, ioc_id)
    REFERENCES ioc_items (observable_type, id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ioc_threat_actors_ioc
  ON ioc_threat_actors (ioc_id, ioc_observable_type);

CREATE INDEX IF NOT EXISTS idx_ioc_threat_actors_actor
  ON ioc_threat_actors (threat_actor_id);

-- Backfill single FK into junction (idempotent).
INSERT INTO ioc_threat_actors (
  ioc_id, ioc_observable_type, threat_actor_id, source_type, source_name
)
SELECT
  i.id,
  i.observable_type,
  i.threat_actor_id,
  'legacy',
  'migration_138'
FROM ioc_items i
WHERE i.threat_actor_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM threat_actors ta WHERE ta.id = i.threat_actor_id)
ON CONFLICT (ioc_id, ioc_observable_type, threat_actor_id) DO NOTHING;
