CREATE TABLE IF NOT EXISTS integration_source_state (
  source_name TEXT PRIMARY KEY,
  content_hash TEXT,
  items_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
