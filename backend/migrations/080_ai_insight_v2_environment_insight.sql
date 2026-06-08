ALTER TABLE incident_ai_insights
  ADD COLUMN IF NOT EXISTS structured_output_json JSONB,
  ADD COLUMN IF NOT EXISTS context_pack_json JSONB;

CREATE INDEX IF NOT EXISTS idx_incident_ai_insights_structured_threat_class
  ON incident_ai_insights ((structured_output_json->>'threat_class'))
  WHERE structured_output_json IS NOT NULL;

ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS primary_threat_classification TEXT NULL
    CHECK (
      primary_threat_classification IS NULL
      OR primary_threat_classification IN ('phishing', 'malware', 'c2', 'scanner', 'suspicious_infra', 'test', 'unknown')
    );

CREATE INDEX IF NOT EXISTS idx_ioc_items_primary_threat_classification
  ON ioc_items (primary_threat_classification)
  WHERE primary_threat_classification IS NOT NULL;

ALTER TABLE ioc_sources
  ADD COLUMN IF NOT EXISTS default_threat_classification TEXT NULL
    CHECK (
      default_threat_classification IS NULL
      OR default_threat_classification IN ('phishing', 'malware', 'c2', 'scanner', 'suspicious_infra', 'test', 'unknown')
    );

CREATE TABLE IF NOT EXISTS environment_ai_insights (
  id BIGSERIAL PRIMARY KEY,
  range_days INTEGER NOT NULL CHECK (range_days IN (7, 30, 90)),
  period_start TIMESTAMPTZ NOT NULL,
  period_end TIMESTAMPTZ NOT NULL,
  generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  model TEXT,
  input_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  output_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by UUID NULL,
  triggered_by TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_environment_ai_insights_range_generated
  ON environment_ai_insights (range_days, generated_at DESC);
