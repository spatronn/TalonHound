CREATE TABLE IF NOT EXISTS ioc_observables (
  id BIGSERIAL PRIMARY KEY,
  observable TEXT NOT NULL,
  observable_type TEXT NOT NULL,
  source_name TEXT NOT NULL,
  source_url TEXT,
  confidence TEXT NOT NULL DEFAULT 'medium',
  category TEXT,
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_observables_created_at ON ioc_observables (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_observables_type ON ioc_observables (observable_type);
CREATE INDEX IF NOT EXISTS idx_ioc_observables_source ON ioc_observables (source_name);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_observables_dedup
ON ioc_observables (
  observable,
  observable_type,
  source_name,
  confidence,
  COALESCE(category, ''),
  COALESCE(source_url, '')
);
