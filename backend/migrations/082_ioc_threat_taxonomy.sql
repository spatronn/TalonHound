-- IOC threat taxonomy refactor: canonical classification, threat actors, tag legacy migration.
-- Idempotent where practical; safe for single-user controlled migration.
-- Large-table deploys: disable per-statement timeout for this migration transaction.
SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

CREATE TABLE IF NOT EXISTS threat_actors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  aliases TEXT[] NULL,
  description TEXT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT NULL,
  updated_by TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_threat_actors_active_name
  ON threat_actors (active, name);

-- Rename primary_threat_classification → threat_classification on partitioned parent.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'ioc_items' AND column_name = 'primary_threat_classification'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'ioc_items' AND column_name = 'threat_classification'
  ) THEN
    ALTER TABLE ioc_items RENAME COLUMN primary_threat_classification TO threat_classification;
  END IF;
END $$;

ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS threat_classification TEXT;

ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS threat_actor_id UUID NULL REFERENCES threat_actors(id);

CREATE INDEX IF NOT EXISTS idx_ioc_items_threat_classification
  ON ioc_items (threat_classification);

CREATE INDEX IF NOT EXISTS idx_ioc_items_threat_actor_id
  ON ioc_items (threat_actor_id)
  WHERE threat_actor_id IS NOT NULL;

-- Drop legacy check constraints if present.
ALTER TABLE ioc_items DROP CONSTRAINT IF EXISTS ioc_items_primary_threat_classification_check;
ALTER TABLE ioc_items DROP CONSTRAINT IF EXISTS ioc_items_threat_classification_check;

-- Normalize legacy classification values before NOT NULL + new check.
UPDATE ioc_items SET threat_classification = 'unknown' WHERE threat_classification IS NULL OR btrim(threat_classification) = '';

UPDATE ioc_items SET threat_classification = 'command_and_control'
  WHERE lower(replace(replace(threat_classification, ' ', '_'), '-', '_')) IN ('c2', 'command_and_control');

UPDATE ioc_items SET threat_classification = 'scanner_recon'
  WHERE lower(threat_classification) IN ('scanner', 'scanner_recon');

UPDATE ioc_items SET threat_classification = 'suspicious_infrastructure'
  WHERE lower(threat_classification) IN ('suspicious_infra', 'suspicious_infrastructure');

UPDATE ioc_items SET threat_classification = 'benign_test'
  WHERE lower(threat_classification) IN ('test', 'benign_test');

UPDATE ioc_items SET threat_classification = 'unknown'
  WHERE threat_classification IS NOT NULL
    AND lower(threat_classification) NOT IN (
      'unknown', 'phishing', 'credential_theft', 'malware', 'ransomware', 'command_and_control',
      'botnet', 'exploit', 'scanner_recon', 'suspicious_infrastructure', 'spam_abuse',
      'dropper_downloader', 'payload_hosting', 'data_exfiltration', 'cryptomining',
      'fraud_scam', 'typosquatting_impersonation', 'benign_test'
    );

ALTER TABLE ioc_items ALTER COLUMN threat_classification SET DEFAULT 'unknown';
ALTER TABLE ioc_items ALTER COLUMN threat_classification SET NOT NULL;

ALTER TABLE ioc_items ADD CONSTRAINT ioc_items_threat_classification_check
  CHECK (threat_classification IN (
    'unknown', 'phishing', 'credential_theft', 'malware', 'ransomware', 'command_and_control',
    'botnet', 'exploit', 'scanner_recon', 'suspicious_infrastructure', 'spam_abuse',
    'dropper_downloader', 'payload_hosting', 'data_exfiltration', 'cryptomining',
    'fraud_scam', 'typosquatting_impersonation', 'benign_test'
  ));

DROP INDEX IF EXISTS idx_ioc_items_primary_threat_classification;
CREATE INDEX IF NOT EXISTS idx_ioc_items_threat_classification_active
  ON ioc_items (threat_classification)
  WHERE threat_classification <> 'unknown';

-- IOC sources default classification constraint refresh.
ALTER TABLE ioc_sources DROP CONSTRAINT IF EXISTS ioc_sources_default_threat_classification_check;

UPDATE ioc_sources SET default_threat_classification = 'unknown'
  WHERE default_threat_classification IS NULL OR btrim(default_threat_classification) = '';

UPDATE ioc_sources SET default_threat_classification = 'command_and_control'
  WHERE lower(default_threat_classification) IN ('c2', 'command_and_control');

UPDATE ioc_sources SET default_threat_classification = 'scanner_recon'
  WHERE lower(default_threat_classification) IN ('scanner', 'scanner_recon');

UPDATE ioc_sources SET default_threat_classification = 'suspicious_infrastructure'
  WHERE lower(default_threat_classification) IN ('suspicious_infra', 'suspicious_infrastructure');

UPDATE ioc_sources SET default_threat_classification = 'benign_test'
  WHERE lower(default_threat_classification) IN ('test', 'benign_test');

UPDATE ioc_sources SET default_threat_classification = 'unknown'
  WHERE default_threat_classification IS NOT NULL
    AND lower(default_threat_classification) NOT IN (
      'unknown', 'phishing', 'credential_theft', 'malware', 'ransomware', 'command_and_control',
      'botnet', 'exploit', 'scanner_recon', 'suspicious_infrastructure', 'spam_abuse',
      'dropper_downloader', 'payload_hosting', 'data_exfiltration', 'cryptomining',
      'fraud_scam', 'typosquatting_impersonation', 'benign_test'
    );

ALTER TABLE ioc_sources ADD CONSTRAINT ioc_sources_default_threat_classification_check
  CHECK (
    default_threat_classification IS NULL
    OR default_threat_classification IN (
      'unknown', 'phishing', 'credential_theft', 'malware', 'ransomware', 'command_and_control',
      'botnet', 'exploit', 'scanner_recon', 'suspicious_infrastructure', 'spam_abuse',
      'dropper_downloader', 'payload_hosting', 'data_exfiltration', 'cryptomining',
      'fraud_scam', 'typosquatting_impersonation', 'benign_test'
    )
  );

-- Seed canonical threat actors for legacy actor tags.
INSERT INTO threat_actors (name, slug, aliases, description, active)
VALUES
  ('APT29', 'apt29', ARRAY['Cozy Bear', 'Midnight Blizzard', 'Nobelium'], 'Legacy tag migration seed', TRUE),
  ('APT28', 'apt28', ARRAY['Fancy Bear', 'Sofacy'], 'Legacy tag migration seed', TRUE),
  ('Lazarus', 'lazarus', ARRAY['Lazarus Group', 'HIDDEN COBRA'], 'Legacy tag migration seed', TRUE)
ON CONFLICT (slug) DO UPDATE SET
  active = EXCLUDED.active,
  updated_at = NOW();

-- Migrate IOC classification from legacy threat tags (only when still unknown).
UPDATE ioc_items i
SET threat_classification = v.new_class
FROM (
  SELECT DISTINCT ON (it.ioc_item_id, it.ioc_observable_type)
    it.ioc_item_id,
    it.ioc_observable_type,
    CASE lower(t.slug)
      WHEN 'phishing' THEN 'phishing'
      WHEN 'ransomware' THEN 'ransomware'
      WHEN 'c2' THEN 'command_and_control'
      WHEN 'malware' THEN 'malware'
    END AS new_class
  FROM ioc_tags it
  INNER JOIN tags t ON t.id = it.tag_id
  WHERE lower(t.slug) IN ('phishing', 'ransomware', 'c2', 'malware')
  ORDER BY it.ioc_item_id, it.ioc_observable_type, t.slug
) v
WHERE i.id = v.ioc_item_id
  AND i.observable_type = v.ioc_observable_type
  AND v.new_class IS NOT NULL
  AND COALESCE(i.threat_classification, 'unknown') = 'unknown';

-- Migrate IOC threat actor from legacy actor tags.
UPDATE ioc_items i
SET threat_actor_id = ta.id
FROM ioc_tags it
INNER JOIN tags t ON t.id = it.tag_id
INNER JOIN threat_actors ta ON ta.slug = lower(t.slug)
WHERE it.ioc_item_id = i.id
  AND it.ioc_observable_type = i.observable_type
  AND lower(t.slug) IN ('apt29', 'apt28', 'lazarus')
  AND i.threat_actor_id IS NULL;

-- Remove legacy tag assignments migrated to classification/actor.
DELETE FROM ioc_tags it
USING tags t
WHERE it.tag_id = t.id
  AND lower(t.slug) IN ('phishing', 'ransomware', 'c2', 'malware', 'apt29', 'apt28', 'lazarus');

-- Mark legacy tags inactive with migration note.
UPDATE tags
SET enabled = FALSE,
    description = CASE
      WHEN lower(slug) IN ('phishing', 'ransomware', 'c2', 'malware')
        THEN COALESCE(NULLIF(btrim(description), ''), 'legacy-migrated-to-threat-classification')
      WHEN lower(slug) IN ('apt29', 'apt28', 'lazarus')
        THEN COALESCE(NULLIF(btrim(description), ''), 'legacy-migrated-to-threat-actor')
      ELSE description
    END,
    updated_at = NOW()
WHERE lower(slug) IN ('phishing', 'ransomware', 'c2', 'malware', 'apt29', 'apt28', 'lazarus');

-- Normalize operational tags (examples).
UPDATE tags SET category = 'behavior', updated_at = NOW()
  WHERE lower(slug) = 'clickfix' AND (category IS NULL OR category IN ('malware', 'actor', ''));
