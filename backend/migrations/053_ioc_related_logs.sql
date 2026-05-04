CREATE TABLE IF NOT EXISTS ioc_match_event_related_logs (
  id BIGSERIAL PRIMARY KEY,
  activity_id UUID NOT NULL REFERENCES ioc_activity(id) ON DELETE CASCADE,
  match_event_id BIGINT NULL REFERENCES ioc_match_events(id) ON DELETE SET NULL,
  evidence_hash TEXT NOT NULL,
  observable_value TEXT,
  observable_type TEXT,
  source_table TEXT,
  log_ts TIMESTAMPTZ,
  log_host TEXT,
  observed_host TEXT,
  parser_source TEXT,
  source_type TEXT,
  context_type TEXT,
  raw_message_hash TEXT,
  raw_message_sample TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_rel_logs_activity_evidence
  ON ioc_match_event_related_logs (activity_id, evidence_hash);

CREATE INDEX IF NOT EXISTS idx_ioc_rel_logs_activity
  ON ioc_match_event_related_logs (activity_id);

CREATE INDEX IF NOT EXISTS idx_ioc_rel_logs_match_event
  ON ioc_match_event_related_logs (match_event_id);
