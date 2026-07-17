-- IOC-scoped hide overrides for feed/integration (source) tags.
-- Does not delete catalog tags or mutate feed source evidence.

CREATE TABLE IF NOT EXISTS ioc_source_tag_overrides (
  id BIGSERIAL PRIMARY KEY,
  ioc_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  tag_value TEXT NOT NULL,
  tag_normalized TEXT NOT NULL,
  source_name TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT 'hidden'
    CHECK (action = 'hidden'),
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  restored_at TIMESTAMPTZ NULL,
  restored_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_ioc_source_tag_overrides_ioc
    FOREIGN KEY (ioc_observable_type, ioc_id)
    REFERENCES ioc_items(observable_type, id)
    ON DELETE CASCADE
);

-- One active hide per IOC + tag + source (restore soft-closes the row)
CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_source_tag_override_active
  ON ioc_source_tag_overrides (ioc_id, tag_normalized, lower(source_name))
  WHERE restored_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_source_tag_overrides_ioc_active
  ON ioc_source_tag_overrides (ioc_id)
  WHERE restored_at IS NULL;
