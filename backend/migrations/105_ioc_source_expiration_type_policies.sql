-- IOC-type-level expiration overrides for IOC Sources.
-- Allows per-type TTL different from the source default (e.g. hashes never expire,
-- domains expire after 30 days) using the same three-mode scheme as feed type policies.
CREATE TABLE ioc_source_expiration_type_policies (
  id         BIGSERIAL PRIMARY KEY,
  source_id  BIGINT    NOT NULL REFERENCES ioc_sources(id) ON DELETE CASCADE,
  ioc_type   TEXT      NOT NULL CHECK (ioc_type IN ('domain', 'ip', 'url', 'file_hash')),
  mode       TEXT      NOT NULL CHECK (mode IN ('inherit', 'no_expire', 'fixed_ttl')),
  ttl_days   INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (source_id, ioc_type),
  CHECK (mode != 'fixed_ttl' OR (ttl_days IS NOT NULL AND ttl_days > 0))
);

CREATE INDEX ON ioc_source_expiration_type_policies (source_id);
