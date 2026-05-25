-- Central audit log for security and operational actions
CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_user_id UUID NULL,
  actor_username TEXT NULL,
  actor_email TEXT NULL,
  actor_role TEXT NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NULL,
  entity_display TEXT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  status TEXT NOT NULL DEFAULT 'success',
  ip_address INET NULL,
  user_agent TEXT NULL,
  request_id TEXT NULL,
  source TEXT NOT NULL DEFAULT 'web',
  before_data JSONB NULL,
  after_data JSONB NULL,
  metadata JSONB NULL
);

CREATE INDEX IF NOT EXISTS audit_logs_created_at_desc_idx ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_actor_user_id_idx ON audit_logs (actor_user_id);
CREATE INDEX IF NOT EXISTS audit_logs_action_idx ON audit_logs (action);
CREATE INDEX IF NOT EXISTS audit_logs_entity_type_idx ON audit_logs (entity_type);
CREATE INDEX IF NOT EXISTS audit_logs_entity_id_idx ON audit_logs (entity_id);
CREATE INDEX IF NOT EXISTS audit_logs_severity_idx ON audit_logs (severity);
CREATE INDEX IF NOT EXISTS audit_logs_status_idx ON audit_logs (status);
CREATE INDEX IF NOT EXISTS audit_logs_metadata_gin_idx ON audit_logs USING GIN (metadata);
