-- Safe IOC confidence columns (no NOT NULL DEFAULT, no CHECK, no ioc_items backfill).
-- Run explicitly via: docker compose run --rm backend npm run migrate
-- Quarantined unsafe version: migrations_disabled/071_ioc_confidence_model.sql.disabled

SET lock_timeout = '5s';
SET statement_timeout = '120s';

-- Small table: nullable column + targeted feed default seeds only.
ALTER TABLE integration_feeds
  ADD COLUMN IF NOT EXISTS default_confidence TEXT NULL;

UPDATE integration_feeds
SET default_confidence = 'high'
WHERE key IN ('malwarebazaar-abusech', 'urlhaus-abusech', 'threatfox-abusech', 'usom-trcert')
  AND default_confidence IS NULL;

UPDATE integration_feeds
SET default_confidence = 'medium'
WHERE key IN ('et-blockrules', 'phishtank-opendnsrr')
  AND default_confidence IS NULL;

-- Partitioned ioc_items: nullable ADD COLUMN only (fast metadata change, no table rewrite).
ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS source_confidence TEXT NULL,
  ADD COLUMN IF NOT EXISTS feed_default_confidence TEXT NULL,
  ADD COLUMN IF NOT EXISTS analyst_confidence_override TEXT NULL,
  ADD COLUMN IF NOT EXISTS analyst_confidence_override_reason TEXT NULL,
  ADD COLUMN IF NOT EXISTS analyst_confidence_overridden_by UUID NULL,
  ADD COLUMN IF NOT EXISTS analyst_confidence_overridden_at TIMESTAMPTZ NULL;

-- Partial index: empty until overrides exist; avoids scanning/backfilling ioc_items.
CREATE INDEX IF NOT EXISTS idx_ioc_items_analyst_confidence_override
  ON ioc_items (analyst_confidence_override)
  WHERE analyst_confidence_override IS NOT NULL;
