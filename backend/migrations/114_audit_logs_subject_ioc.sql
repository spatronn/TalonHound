-- Subject IOC vs enrichment target for IOC Details audit scoping.
-- Keep entity_id / entity_display / metadata for backward compatibility.

ALTER TABLE audit_logs
  ADD COLUMN IF NOT EXISTS subject_ioc_id BIGINT NULL,
  ADD COLUMN IF NOT EXISTS subject_ioc_type TEXT NULL,
  ADD COLUMN IF NOT EXISTS subject_ioc_value TEXT NULL,
  ADD COLUMN IF NOT EXISTS target_type TEXT NULL,
  ADD COLUMN IF NOT EXISTS target_value TEXT NULL;

-- No FK: IOC delete must not erase audit history (snapshot columns remain).

CREATE INDEX IF NOT EXISTS audit_logs_subject_ioc_id_idx
  ON audit_logs (subject_ioc_id)
  WHERE subject_ioc_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS audit_logs_enrichment_subject_ioc_idx
  ON audit_logs (entity_type, subject_ioc_id, created_at DESC)
  WHERE entity_type = 'enrichment' AND subject_ioc_id IS NOT NULL;
