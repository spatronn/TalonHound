-- Convert legacy last_seen_ttl feed expiration policies to fixed_ttl.
--
-- WHY: Last seen TTL is removed from the product policy set. Remaining modes:
--   never | fixed_ttl | missing_from_feed_ttl
--
-- WHAT:
--   1. Snapshot last_seen_ttl policy rows (typically AlienVault OTX default from
--      migration 102: enabled, ttl_days=30).
--   2. Rewrite those rows to fixed_ttl, keeping ttl_days / enabled / grace_days.
--   3. Recompute membership policy_expires_at / expires_at from first_seen_in_feed
--      for converted feeds only (unchanged-row imports no longer rewrite last_seen).
--   4. Tighten the CHECK constraint to the 3 remaining modes.
--
-- VERIFY converted policy count (before / after):
--   SELECT COUNT(*) FROM threat_feed_expiration_policies
--    WHERE expiration_mode = 'last_seen_ttl';
--   After this migration the count must be 0.
--
--   SELECT f.key, p.observable_type, p.enabled, p.expiration_mode, p.ttl_days
--     FROM threat_feed_expiration_policies p
--     JOIN integration_feeds f ON f.integration_id = p.feed_id
--    WHERE f.key = 'alienvault-otx';
--
-- IDEMPOTENT: re-running is a no-op once no last_seen_ttl rows remain.
-- Does not change membership status; the expiration worker expires due dates.

SET LOCAL statement_timeout = 0;
SET LOCAL lock_timeout = '120s';

CREATE TEMP TABLE tmp_last_seen_ttl_policies ON COMMIT DROP AS
SELECT id, feed_id, observable_type, enabled, ttl_days
FROM threat_feed_expiration_policies
WHERE expiration_mode = 'last_seen_ttl';

DO $$
DECLARE
  n bigint;
BEGIN
  SELECT COUNT(*) INTO n FROM tmp_last_seen_ttl_policies;
  RAISE NOTICE 'expiration policy last_seen_ttl → fixed_ttl: % row(s)', n;
END $$;

UPDATE threat_feed_expiration_policies p
SET expiration_mode = 'fixed_ttl',
    updated_at = NOW()
WHERE expiration_mode = 'last_seen_ttl';

UPDATE ioc_feed_memberships m
SET
  policy_expires_at = computed.policy_expires_at,
  expires_at = computed.expires_at,
  updated_at = NOW()
FROM (
  SELECT
    m2.id,
    CASE
      WHEN ovr.mode = 'no_expire' THEN NULL
      WHEN ovr.mode = 'fixed_ttl' AND ovr.ttl_days IS NOT NULL AND ovr.ttl_days > 0
        THEN m2.first_seen_in_feed + (ovr.ttl_days * INTERVAL '1 day')
      WHEN t.enabled AND t.ttl_days IS NOT NULL AND t.ttl_days > 0
        THEN m2.first_seen_in_feed + (t.ttl_days * INTERVAL '1 day')
      ELSE NULL
    END AS policy_expires_at,
    CASE
      WHEN m2.override_enabled AND m2.override_status = 'expired' THEN 'epoch'::timestamptz
      WHEN m2.override_enabled AND m2.override_status = 'active' THEN NULL
      WHEN m2.override_enabled THEN m2.override_expires_at
      WHEN ovr.mode = 'no_expire' THEN NULL
      WHEN ovr.mode = 'fixed_ttl' AND ovr.ttl_days IS NOT NULL AND ovr.ttl_days > 0
        THEN m2.first_seen_in_feed + (ovr.ttl_days * INTERVAL '1 day')
      WHEN t.enabled AND t.ttl_days IS NOT NULL AND t.ttl_days > 0
        THEN m2.first_seen_in_feed + (t.ttl_days * INTERVAL '1 day')
      ELSE NULL
    END AS expires_at
  FROM ioc_feed_memberships m2
  JOIN LATERAL (
    SELECT p.feed_id, p.observable_type, p.enabled, p.ttl_days
    FROM threat_feed_expiration_policies p
    WHERE p.feed_id = m2.feed_id
      AND p.observable_type IN (m2.ioc_observable_type, 'all')
    ORDER BY CASE WHEN p.observable_type = m2.ioc_observable_type THEN 0 ELSE 1 END
    LIMIT 1
  ) eff ON TRUE
  JOIN tmp_last_seen_ttl_policies t
    ON t.feed_id = eff.feed_id
   AND t.observable_type = eff.observable_type
  LEFT JOIN integration_feed_expiration_type_policies ovr
    ON ovr.feed_id = m2.feed_id
   AND ovr.ioc_type = CASE
     WHEN m2.ioc_observable_type IN ('ip', 'ip6', 'ipv4', 'ipv6') THEN 'ip'
     WHEN m2.ioc_observable_type IN ('hash', 'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh', 'file_hash') THEN 'file_hash'
     ELSE m2.ioc_observable_type
   END
) computed
WHERE m.id = computed.id
  AND (
    m.policy_expires_at IS DISTINCT FROM computed.policy_expires_at
    OR m.expires_at IS DISTINCT FROM computed.expires_at
  );

ALTER TABLE threat_feed_expiration_policies
  DROP CONSTRAINT IF EXISTS threat_feed_expiration_policies_expiration_mode_check;

ALTER TABLE threat_feed_expiration_policies
  ADD CONSTRAINT threat_feed_expiration_policies_expiration_mode_check
  CHECK (expiration_mode IN ('never', 'fixed_ttl', 'missing_from_feed_ttl'));
