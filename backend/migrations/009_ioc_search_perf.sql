CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_ioc_items_observable_trgm
ON ioc_items USING gin (observable gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_ioc_items_source_trgm
ON ioc_items USING gin (source_name gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_ioc_items_created_at_desc
ON ioc_items (created_at DESC);
