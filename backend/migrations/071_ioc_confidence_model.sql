-- IOC confidence model: feed defaults, source confidence, analyst override.

ALTER TABLE integration_feeds
  ADD COLUMN IF NOT EXISTS default_confidence TEXT NOT NULL DEFAULT 'medium'
    CHECK (default_confidence IN ('low', 'medium', 'high'));

UPDATE integration_feeds SET default_confidence = 'high'
WHERE key IN ('malwarebazaar-abusech', 'urlhaus-abusech', 'threatfox-abusech', 'usom-trcert');

UPDATE integration_feeds SET default_confidence = 'medium'
WHERE key IN ('et-blockrules', 'phishtank-opendnsrr');

ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS source_confidence TEXT NULL
    CHECK (source_confidence IS NULL OR source_confidence IN ('low', 'medium', 'high')),
  ADD COLUMN IF NOT EXISTS feed_default_confidence TEXT NULL
    CHECK (feed_default_confidence IS NULL OR feed_default_confidence IN ('low', 'medium', 'high')),
  ADD COLUMN IF NOT EXISTS analyst_confidence_override TEXT NULL
    CHECK (analyst_confidence_override IS NULL OR analyst_confidence_override IN ('low', 'medium', 'high')),
  ADD COLUMN IF NOT EXISTS analyst_confidence_override_reason TEXT NULL,
  ADD COLUMN IF NOT EXISTS analyst_confidence_overridden_by UUID NULL,
  ADD COLUMN IF NOT EXISTS analyst_confidence_overridden_at TIMESTAMPTZ NULL;

-- Backfill structured fields from legacy confidence column (preserve existing effective values).
UPDATE ioc_items i
SET feed_default_confidence = f.default_confidence
FROM integration_feeds f
WHERE i.feed_default_confidence IS NULL
  AND (
    (f.key = 'usom-trcert' AND i.source_name = 'USOM:TR-CERT')
    OR (f.key = 'urlhaus-abusech' AND i.source_name = 'URLhaus:abuse.ch')
    OR (f.key = 'threatfox-abusech' AND i.source_name = 'ThreatFox:abuse.ch')
    OR (f.key = 'malwarebazaar-abusech' AND i.source_name = 'MalwareBazaar:abuse.ch')
    OR (f.key = 'et-blockrules' AND i.source_name LIKE 'EmergingThreats:%')
    OR (f.key = 'phishtank-opendnsrr' AND (i.source_name ILIKE '%phishtank%' OR i.source_name ILIKE '%PhishTank%'))
  );

UPDATE ioc_items
SET source_confidence = confidence
WHERE source_confidence IS NULL
  AND confidence IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_items_analyst_confidence_override
  ON ioc_items (analyst_confidence_override)
  WHERE analyst_confidence_override IS NOT NULL;
