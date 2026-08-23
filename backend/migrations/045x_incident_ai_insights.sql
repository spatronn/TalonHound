-- Runs after 045_ioc_activity_layer.sql on greenfield installs.
-- Existing installations may already have this schema under 045_incident_ai_insights.sql
-- or may have dropped the analytics tables in migration 110.
DO $$
BEGIN
  IF to_regclass('public.ioc_activity') IS NULL THEN
    RETURN;
  END IF;

  CREATE TABLE IF NOT EXISTS incident_ai_insights (
    id BIGSERIAL PRIMARY KEY,
    activity_id UUID NOT NULL REFERENCES ioc_activity(id) ON DELETE CASCADE,
    incident_id BIGINT,
    insight_version TEXT NOT NULL,
    llm_risk_adjustment INTEGER,
    llm_risk_confidence DOUBLE PRECISION,
    llm_risk_reason TEXT,
    llm_related_evidence JSONB,
    raw_model_adjustment INTEGER,
    normalization_reason TEXT,
    llm_last_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(activity_id, insight_version)
  );

  CREATE INDEX IF NOT EXISTS idx_incident_ai_insights_activity_updated
    ON incident_ai_insights (activity_id, llm_last_updated_at DESC);

  CREATE INDEX IF NOT EXISTS idx_incident_ai_insights_incident_id
    ON incident_ai_insights (incident_id);
END $$;
