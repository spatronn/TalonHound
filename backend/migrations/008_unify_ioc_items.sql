CREATE TABLE IF NOT EXISTS ioc_items (
  id BIGSERIAL PRIMARY KEY,
  observable TEXT NOT NULL,
  observable_type TEXT NOT NULL,
  source_name TEXT NOT NULL,
  source_url TEXT,
  confidence TEXT NOT NULL DEFAULT 'medium',
  category TEXT,
  note TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_items_created_at ON ioc_items (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_items_type ON ioc_items (observable_type);
CREATE INDEX IF NOT EXISTS idx_ioc_items_source ON ioc_items (source_name);
CREATE INDEX IF NOT EXISTS idx_ioc_items_confidence ON ioc_items (confidence);
CREATE INDEX IF NOT EXISTS idx_ioc_items_observable ON ioc_items (observable);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_items_dedup
ON ioc_items (
  observable,
  observable_type,
  source_name,
  confidence,
  COALESCE(category, ''),
  COALESCE(source_url, '')
);

INSERT INTO ioc_items (observable, observable_type, source_name, source_url, confidence, category, note, first_seen_at, last_seen_at, created_at)
SELECT host(ip::inet), 'ip', source_name, source_url, confidence, category, note, first_seen_at, last_seen_at, created_at
FROM ioc_ips
ON CONFLICT DO NOTHING;

INSERT INTO ioc_items (observable, observable_type, source_name, source_url, confidence, category, note, first_seen_at, last_seen_at, created_at)
SELECT observable, observable_type, source_name, source_url, confidence, category, note, created_at, created_at, created_at
FROM ioc_observables
ON CONFLICT DO NOTHING;
