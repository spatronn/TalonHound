-- Multi-value threat classifications per IOC (junction table + legacy column backfill).
SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

CREATE TABLE IF NOT EXISTS ioc_threat_classifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ioc_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  classification_slug TEXT NOT NULL,
  source_type TEXT NOT NULL DEFAULT 'analyst',
  source_name TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT NULL,
  updated_by TEXT NULL,
  CONSTRAINT uq_ioc_threat_classifications_ioc_slug UNIQUE (ioc_id, ioc_observable_type, classification_slug),
  CONSTRAINT fk_ioc_threat_classifications_ioc
    FOREIGN KEY (ioc_observable_type, ioc_id)
    REFERENCES ioc_items (observable_type, id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ioc_threat_classifications_ioc
  ON ioc_threat_classifications (ioc_id, ioc_observable_type);

CREATE INDEX IF NOT EXISTS idx_ioc_threat_classifications_slug
  ON ioc_threat_classifications (classification_slug);

-- Backfill non-unknown single values into junction (idempotent, no full-table UPDATE on ioc_items).
INSERT INTO ioc_threat_classifications (
  ioc_id, ioc_observable_type, classification_slug, source_type, source_name
)
SELECT
  i.id,
  i.observable_type,
  CASE
    WHEN lower(replace(replace(btrim(i.threat_classification), ' ', '_'), '-', '_')) IN ('c2', 'command_and_control') THEN 'command_and_control'
    WHEN lower(btrim(i.threat_classification)) IN ('scanner', 'scanner_recon') THEN 'scanner_recon'
    WHEN lower(btrim(i.threat_classification)) IN ('suspicious_infra', 'suspicious_infrastructure') THEN 'suspicious_infrastructure'
    WHEN lower(btrim(i.threat_classification)) IN ('test', 'benign_test') THEN 'benign_test'
    ELSE lower(replace(replace(btrim(i.threat_classification), ' ', '_'), '-', '_'))
  END AS classification_slug,
  'legacy',
  'migration_085'
FROM ioc_items i
WHERE i.threat_classification IS NOT NULL
  AND btrim(i.threat_classification) <> ''
  AND lower(btrim(i.threat_classification)) NOT IN ('unknown', 'not selected', '— not selected —')
  AND EXISTS (
    SELECT 1 FROM threat_classifications tc
    WHERE tc.slug = CASE
      WHEN lower(replace(replace(btrim(i.threat_classification), ' ', '_'), '-', '_')) IN ('c2', 'command_and_control') THEN 'command_and_control'
      WHEN lower(btrim(i.threat_classification)) IN ('scanner', 'scanner_recon') THEN 'scanner_recon'
      WHEN lower(btrim(i.threat_classification)) IN ('suspicious_infra', 'suspicious_infrastructure') THEN 'suspicious_infrastructure'
      WHEN lower(btrim(i.threat_classification)) IN ('test', 'benign_test') THEN 'benign_test'
      ELSE lower(replace(replace(btrim(i.threat_classification), ' ', '_'), '-', '_'))
    END
  )
ON CONFLICT (ioc_id, ioc_observable_type, classification_slug) DO NOTHING;
