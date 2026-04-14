CREATE SEQUENCE IF NOT EXISTS ioc_activity_incident_id_seq;

ALTER TABLE ioc_activity
  ADD COLUMN IF NOT EXISTS incident_id BIGINT;

ALTER TABLE ioc_activity
  ALTER COLUMN incident_id SET DEFAULT nextval('ioc_activity_incident_id_seq');

UPDATE ioc_activity
SET incident_id = nextval('ioc_activity_incident_id_seq')
WHERE incident_id IS NULL;

SELECT setval(
  'ioc_activity_incident_id_seq',
  GREATEST((SELECT COALESCE(MAX(incident_id), 1) FROM ioc_activity), 1),
  true
);

ALTER TABLE ioc_activity
  ALTER COLUMN incident_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_activity_incident_id
  ON ioc_activity (incident_id);
