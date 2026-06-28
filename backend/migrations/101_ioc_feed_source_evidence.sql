-- Per-feed source evidence for multi-source IOCs (same observable, multiple feed memberships).

CREATE TABLE IF NOT EXISTS ioc_feed_source_evidence (
  id BIGSERIAL PRIMARY KEY,
  ioc_item_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  feed_id UUID NOT NULL REFERENCES integration_feeds (integration_id) ON DELETE CASCADE,
  source_name TEXT NOT NULL,
  source_url TEXT NULL,
  category TEXT NULL,
  note TEXT NULL,
  confidence TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (ioc_item_id, ioc_observable_type, feed_id),
  FOREIGN KEY (ioc_observable_type, ioc_item_id) REFERENCES ioc_items (observable_type, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ioc_feed_source_evidence_item
  ON ioc_feed_source_evidence (ioc_item_id, ioc_observable_type);

COMMENT ON TABLE ioc_feed_source_evidence IS
  'Per-feed import metadata (note, category, source URL) for IOCs seen from multiple feeds.';

-- Backfill primary ioc_items metadata where source_name matches the feed membership.
INSERT INTO ioc_feed_source_evidence (
  ioc_item_id,
  ioc_observable_type,
  feed_id,
  source_name,
  source_url,
  category,
  note,
  confidence,
  created_at,
  updated_at
)
SELECT
  i.id,
  i.observable_type,
  f.integration_id,
  i.source_name,
  i.source_url,
  i.category,
  i.note,
  i.confidence,
  COALESCE(i.first_seen_at, i.created_at),
  COALESCE(i.first_seen_at, i.created_at)
FROM ioc_items i
INNER JOIN ioc_feed_memberships m
  ON m.ioc_item_id = i.id AND m.ioc_observable_type = i.observable_type
INNER JOIN integration_feeds f ON f.integration_id = m.feed_id
WHERE (
  (f.key = 'urlhaus-abusech' AND i.source_name = 'URLhaus:abuse.ch')
  OR (f.key = 'threatfox-abusech' AND i.source_name = 'ThreatFox:abuse.ch')
  OR (f.key = 'malwarebazaar-abusech' AND i.source_name = 'MalwareBazaar:abuse.ch')
  OR (f.key = 'usom-trcert' AND i.source_name = 'USOM:TR-CERT')
  OR (f.key = 'et-blockrules' AND i.source_name LIKE 'EmergingThreats:%')
  OR (f.key = 'phishtank-opendnsrr' AND (i.source_name ILIKE '%PhishTank%' OR i.source_name ILIKE '%phishtank%'))
)
ON CONFLICT (ioc_item_id, ioc_observable_type, feed_id) DO NOTHING;
