-- Feed-based IOC expiration (memberships + policies). Expired IOCs are retained, not deleted.

ALTER TABLE integration_feeds
  ADD COLUMN IF NOT EXISTS feed_update_mode TEXT NOT NULL DEFAULT 'incremental'
    CHECK (feed_update_mode IN ('incremental', 'snapshot'));

UPDATE integration_feeds SET feed_update_mode = 'snapshot'
WHERE key IN ('usom-trcert', 'urlhaus-abusech', 'threatfox-abusech', 'malwarebazaar-abusech');

UPDATE integration_feeds SET feed_update_mode = 'incremental'
WHERE key IN ('et-blockrules', 'phishtank-opendnsrr');

CREATE TABLE IF NOT EXISTS threat_feed_expiration_policies (
  id BIGSERIAL PRIMARY KEY,
  feed_id UUID NOT NULL REFERENCES integration_feeds (integration_id) ON DELETE CASCADE,
  observable_type TEXT NOT NULL DEFAULT 'all',
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  expiration_mode TEXT NOT NULL DEFAULT 'never'
    CHECK (expiration_mode IN ('never', 'fixed_ttl', 'last_seen_ttl', 'missing_from_feed_ttl')),
  ttl_days INTEGER NULL,
  grace_days INTEGER NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (feed_id, observable_type)
);

CREATE INDEX IF NOT EXISTS idx_threat_feed_expiration_policies_feed
  ON threat_feed_expiration_policies (feed_id);

CREATE TABLE IF NOT EXISTS ioc_feed_memberships (
  id BIGSERIAL PRIMARY KEY,
  ioc_item_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  feed_id UUID NOT NULL REFERENCES integration_feeds (integration_id) ON DELETE CASCADE,
  first_seen_in_feed TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_in_feed TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  missing_since TIMESTAMPTZ NULL,
  policy_expires_at TIMESTAMPTZ NULL,
  expires_at TIMESTAMPTZ NULL,
  expired_at TIMESTAMPTZ NULL,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'expired')),
  expiration_reason TEXT NULL,
  override_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  override_expires_at TIMESTAMPTZ NULL,
  override_status TEXT NULL CHECK (override_status IS NULL OR override_status IN ('active', 'expired')),
  override_reason TEXT NULL,
  override_by_user_id UUID NULL,
  override_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (ioc_item_id, ioc_observable_type, feed_id),
  FOREIGN KEY (ioc_observable_type, ioc_item_id) REFERENCES ioc_items (observable_type, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ioc_feed_memberships_feed_status
  ON ioc_feed_memberships (feed_id, status);
CREATE INDEX IF NOT EXISTS idx_ioc_feed_memberships_ioc
  ON ioc_feed_memberships (ioc_item_id, ioc_observable_type);
CREATE INDEX IF NOT EXISTS idx_ioc_feed_memberships_expires_at
  ON ioc_feed_memberships (expires_at) WHERE status = 'active' AND expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ioc_feed_memberships_policy_expires_at
  ON ioc_feed_memberships (policy_expires_at);
CREATE INDEX IF NOT EXISTS idx_ioc_feed_memberships_override_enabled
  ON ioc_feed_memberships (override_enabled) WHERE override_enabled = TRUE;

ALTER TABLE ioc_items
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'expired', 'disabled', 'suppressed')),
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS expired_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS expiration_reason TEXT NULL,
  ADD COLUMN IF NOT EXISTS manual_status_override BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS manual_status TEXT NULL
    CHECK (manual_status IS NULL OR manual_status IN ('active', 'expired')),
  ADD COLUMN IF NOT EXISTS manual_expires_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS manual_override_reason TEXT NULL,
  ADD COLUMN IF NOT EXISTS manual_override_by_user_id UUID NULL,
  ADD COLUMN IF NOT EXISTS manual_override_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_ioc_items_status ON ioc_items (status);
CREATE INDEX IF NOT EXISTS idx_ioc_items_expires_at ON ioc_items (expires_at) WHERE status = 'active' AND expires_at IS NOT NULL;

-- Safe defaults: expiration disabled for every integration feed
INSERT INTO threat_feed_expiration_policies (feed_id, observable_type, enabled, expiration_mode)
SELECT integration_id, 'all', FALSE, 'never'
FROM integration_feeds
ON CONFLICT (feed_id, observable_type) DO NOTHING;

-- Best-effort membership backfill from source_name → feed key mapping
INSERT INTO ioc_feed_memberships (
  ioc_item_id,
  ioc_observable_type,
  feed_id,
  first_seen_in_feed,
  last_seen_in_feed,
  status
)
SELECT
  i.id,
  i.observable_type,
  f.integration_id,
  COALESCE(i.first_seen_at, i.created_at),
  COALESCE(i.last_seen_at, i.created_at),
  'active'
FROM ioc_items i
INNER JOIN integration_feeds f ON (
  (f.key = 'usom-trcert' AND i.source_name = 'USOM:TR-CERT')
  OR (f.key = 'urlhaus-abusech' AND i.source_name = 'URLhaus:abuse.ch')
  OR (f.key = 'threatfox-abusech' AND i.source_name = 'ThreatFox:abuse.ch')
  OR (f.key = 'malwarebazaar-abusech' AND i.source_name = 'MalwareBazaar:abuse.ch')
  OR (f.key = 'et-blockrules' AND i.source_name LIKE 'EmergingThreats:%')
  OR (f.key = 'phishtank-opendnsrr' AND (i.source_name ILIKE '%phishtank%' OR i.source_name ILIKE '%PhishTank%'))
)
ON CONFLICT (ioc_item_id, ioc_observable_type, feed_id) DO NOTHING;

UPDATE ioc_items SET status = 'active' WHERE status IS NULL OR status = '';
