DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tag_type') THEN
    CREATE TYPE tag_type AS ENUM ('threat', 'actor', 'technique', 'context');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS tags (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  type tag_type NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT tags_name_lower_chk CHECK (name = lower(name))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_tags_name ON tags (name);
CREATE INDEX IF NOT EXISTS idx_tags_enabled_type_name ON tags (enabled, type, name);

CREATE TABLE IF NOT EXISTS ioc_tags (
  ioc_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  tag_id BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  PRIMARY KEY (ioc_id, tag_id),
  CONSTRAINT fk_ioc_tags_ioc_item
    FOREIGN KEY (ioc_observable_type, ioc_id)
    REFERENCES ioc_items(observable_type, id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ioc_tags_ioc_id ON ioc_tags (ioc_id);
CREATE INDEX IF NOT EXISTS idx_ioc_tags_tag_id ON ioc_tags (tag_id);
