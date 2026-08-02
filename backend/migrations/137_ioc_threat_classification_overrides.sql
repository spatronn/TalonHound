-- Analyst overrides for IOC threat classifications.
-- Feed/source evidence is never mutated. Adds are mirrored into ioc_threat_classifications
-- for backward-compatible list/export paths; suppresses soft-hide feed classifications
-- from the effective set until cleared.

CREATE TABLE IF NOT EXISTS ioc_threat_classification_overrides (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ioc_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  classification_slug TEXT NOT NULL,
  action TEXT NOT NULL
    CHECK (action IN ('add', 'suppress')),
  -- Optional provenance for suppress: NULL = suppress slug for all feed sources
  source_name TEXT NULL,
  created_by TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  cleared_at TIMESTAMPTZ NULL,
  cleared_by TEXT NULL,
  CONSTRAINT fk_ioc_threat_classification_overrides_ioc
    FOREIGN KEY (ioc_observable_type, ioc_id)
    REFERENCES ioc_items (observable_type, id)
    ON DELETE CASCADE
);

-- One active override per (ioc, slug, action, source key)
CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_tc_override_active
  ON ioc_threat_classification_overrides (
    ioc_id,
    ioc_observable_type,
    classification_slug,
    action,
    lower(COALESCE(source_name, ''))
  )
  WHERE cleared_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_tc_overrides_ioc_active
  ON ioc_threat_classification_overrides (ioc_id, ioc_observable_type)
  WHERE cleared_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_tc_overrides_slug
  ON ioc_threat_classification_overrides (classification_slug)
  WHERE cleared_at IS NULL;
