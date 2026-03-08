-- Observable-centric index: one IOC (ioc_items row) can have many searchable observables.
-- Replaces legacy ioc_observables (004) which was migrated into ioc_items in 008.
-- Link by ioc_public_id (ioc_items.public_id) since ioc_items is partitioned by (observable_type, id).

DROP TABLE IF EXISTS ioc_observables CASCADE;

CREATE TABLE ioc_observables (
  id BIGSERIAL PRIMARY KEY,
  ioc_public_id UUID NOT NULL,
  observable_type TEXT NOT NULL,
  observable_value TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_observable_type CHECK (observable_type IN (
    'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh',
    'ip', 'ip6', 'domain', 'url'
  ))
);

CREATE INDEX idx_ioc_observables_value
ON ioc_observables (observable_value);

CREATE INDEX idx_ioc_observables_type_value
ON ioc_observables (observable_type, observable_value);

CREATE UNIQUE INDEX uq_ioc_observables_ioc_type_value
ON ioc_observables (ioc_public_id, observable_type, observable_value);

COMMENT ON TABLE ioc_observables IS 'Index of all observables per IOC for fast lookup; observable_value stored normalized (lowercase).';
