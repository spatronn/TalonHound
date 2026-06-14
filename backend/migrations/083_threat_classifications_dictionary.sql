-- Threat classifications: platform-seeded, admin-managed dictionary (replaces hardcoded enum CHECK).
SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

CREATE TABLE IF NOT EXISTS threat_classifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  description TEXT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  sort_order INTEGER NOT NULL DEFAULT 100,
  system_default BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT NULL,
  updated_by TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_threat_classifications_active_sort
  ON threat_classifications (active, sort_order, name);

CREATE INDEX IF NOT EXISTS idx_threat_classifications_slug
  ON threat_classifications (slug);

-- Idempotent seed of platform defaults.
INSERT INTO threat_classifications (name, slug, description, active, sort_order, system_default)
VALUES
  ('Unknown', 'unknown', 'Default when classification is unset or unrecognized', TRUE, 0, TRUE),
  ('Phishing', 'phishing', NULL, TRUE, 10, TRUE),
  ('Credential Theft', 'credential_theft', NULL, TRUE, 20, TRUE),
  ('Malware', 'malware', NULL, TRUE, 30, TRUE),
  ('Ransomware', 'ransomware', NULL, TRUE, 40, TRUE),
  ('Command and Control (C2)', 'command_and_control', NULL, TRUE, 50, TRUE),
  ('Botnet', 'botnet', NULL, TRUE, 60, TRUE),
  ('Exploit', 'exploit', NULL, TRUE, 70, TRUE),
  ('Scanner / Reconnaissance', 'scanner_recon', NULL, TRUE, 80, TRUE),
  ('Suspicious Infrastructure', 'suspicious_infrastructure', NULL, TRUE, 90, TRUE),
  ('Spam / Abuse', 'spam_abuse', NULL, TRUE, 100, TRUE),
  ('Dropper / Downloader', 'dropper_downloader', NULL, TRUE, 110, TRUE),
  ('Payload Hosting', 'payload_hosting', NULL, TRUE, 120, TRUE),
  ('Data Exfiltration', 'data_exfiltration', NULL, TRUE, 130, TRUE),
  ('Cryptomining', 'cryptomining', NULL, TRUE, 140, TRUE),
  ('Fraud / Scam', 'fraud_scam', NULL, TRUE, 150, TRUE),
  ('Typosquatting / Impersonation', 'typosquatting_impersonation', NULL, TRUE, 160, TRUE),
  ('Benign / Test', 'benign_test', NULL, TRUE, 170, TRUE)
ON CONFLICT (slug) DO UPDATE SET
  name = EXCLUDED.name,
  sort_order = EXCLUDED.sort_order,
  system_default = TRUE,
  updated_at = NOW();

-- Unknown must always remain active.
UPDATE threat_classifications SET active = TRUE, updated_at = NOW() WHERE slug = 'unknown';

-- Drop hardcoded enum CHECK constraints; dictionary is source of truth.
ALTER TABLE ioc_items DROP CONSTRAINT IF EXISTS ioc_items_threat_classification_check;
ALTER TABLE ioc_items DROP CONSTRAINT IF EXISTS ioc_items_primary_threat_classification_check;
ALTER TABLE ioc_sources DROP CONSTRAINT IF EXISTS ioc_sources_default_threat_classification_check;

-- Normalize legacy slug values on IOC rows before dictionary alignment.
UPDATE ioc_items SET threat_classification = 'unknown'
  WHERE threat_classification IS NULL OR btrim(threat_classification) = '';

UPDATE ioc_items SET threat_classification = 'command_and_control'
  WHERE lower(replace(replace(threat_classification, ' ', '_'), '-', '_')) IN ('c2', 'command_and_control');

UPDATE ioc_items SET threat_classification = 'scanner_recon'
  WHERE lower(threat_classification) IN ('scanner', 'scanner_recon');

UPDATE ioc_items SET threat_classification = 'suspicious_infrastructure'
  WHERE lower(threat_classification) IN ('suspicious_infra', 'suspicious_infrastructure');

UPDATE ioc_items SET threat_classification = 'benign_test'
  WHERE lower(threat_classification) IN ('test', 'benign_test');

-- Orphan slugs → unknown (custom admin entries added later remain if present in dictionary).
UPDATE ioc_items i
SET threat_classification = 'unknown'
WHERE NOT EXISTS (
  SELECT 1 FROM threat_classifications tc WHERE tc.slug = i.threat_classification
);

UPDATE ioc_sources s
SET default_threat_classification = 'unknown'
WHERE default_threat_classification IS NULL OR btrim(default_threat_classification) = '';

UPDATE ioc_sources s
SET default_threat_classification = 'command_and_control'
  WHERE lower(default_threat_classification) IN ('c2', 'command_and_control');

UPDATE ioc_sources s
SET default_threat_classification = 'unknown'
WHERE default_threat_classification IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM threat_classifications tc WHERE tc.slug = s.default_threat_classification
  );

ALTER TABLE ioc_items ALTER COLUMN threat_classification SET DEFAULT 'unknown';
ALTER TABLE ioc_items ALTER COLUMN threat_classification SET NOT NULL;
