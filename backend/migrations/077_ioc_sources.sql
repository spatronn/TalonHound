-- Managed manual IOC sources + link from ioc_items.

CREATE TABLE IF NOT EXISTS ioc_sources (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  display_name TEXT NULL,
  description TEXT NULL,
  source_type TEXT NOT NULL DEFAULT 'manual'
    CHECK (source_type IN ('manual', 'internal_hunting', 'external_report', 'feed', 'test')),
  default_confidence TEXT NULL
    CHECK (default_confidence IS NULL OR default_confidence IN ('low', 'medium', 'high')),
  default_expire_policy TEXT NULL
    CHECK (default_expire_policy IS NULL OR default_expire_policy IN ('never', 'expire_after_days', 'custom_date')),
  default_expire_days INTEGER NULL
    CHECK (default_expire_days IS NULL OR (default_expire_days > 0 AND default_expire_days <= 3650)),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_ioc_sources_name UNIQUE (name),
  CONSTRAINT chk_ioc_sources_name_format CHECK (name ~ '^[A-Za-z0-9_-]{3,64}$')
);

CREATE INDEX IF NOT EXISTS idx_ioc_sources_active ON ioc_sources (active) WHERE active = TRUE;

ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS ioc_source_id BIGINT NULL REFERENCES ioc_sources (id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_items_ioc_source_id
  ON ioc_items (ioc_source_id) WHERE ioc_source_id IS NOT NULL;

-- Backfill manual sources from distinct non-integration source_name values.
DO $$
DECLARE
  rec RECORD;
  norm TEXT;
  candidate TEXT;
  suffix INT;
BEGIN
  FOR rec IN
    SELECT DISTINCT btrim(source_name) AS original_name
    FROM ioc_items
    WHERE source_name IS NOT NULL
      AND btrim(source_name) <> ''
      AND source_name <> 'USOM:TR-CERT'
      AND source_name <> 'URLhaus:abuse.ch'
      AND source_name <> 'ThreatFox:abuse.ch'
      AND source_name <> 'MalwareBazaar:abuse.ch'
      AND source_name NOT LIKE 'EmergingThreats:%'
      AND source_name NOT ILIKE '%phishtank%'
      AND source_name NOT ILIKE '%PhishTank%'
  LOOP
    norm := regexp_replace(rec.original_name, '\s+', '_', 'g');
    norm := regexp_replace(norm, '[^A-Za-z0-9_-]', '', 'g');
    IF length(norm) < 3 THEN
      norm := 'src_' || substr(md5(rec.original_name), 1, 8);
    END IF;
    IF length(norm) > 64 THEN
      norm := substr(norm, 1, 64);
    END IF;

    candidate := norm;
    suffix := 2;
    WHILE EXISTS (SELECT 1 FROM ioc_sources WHERE name = candidate) LOOP
      candidate := left(norm, 60) || '_' || suffix::text;
      suffix := suffix + 1;
    END LOOP;

    INSERT INTO ioc_sources (name, display_name, source_type, active)
    VALUES (candidate, rec.original_name, 'manual', TRUE)
    ON CONFLICT (name) DO NOTHING;
  END LOOP;
END $$;

UPDATE ioc_items i
SET ioc_source_id = s.id
FROM ioc_sources s
WHERE i.ioc_source_id IS NULL
  AND i.source_name IS NOT NULL
  AND s.display_name = btrim(i.source_name);

UPDATE ioc_items i
SET ioc_source_id = s.id
FROM ioc_sources s
WHERE i.ioc_source_id IS NULL
  AND i.source_name IS NOT NULL
  AND s.name = btrim(i.source_name);
