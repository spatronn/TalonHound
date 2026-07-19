-- Migration 120: Rename canonical IPv6 IOC type from 'ip6' to 'ipv6'
--
-- WHAT: All ioc_items rows with observable_type = 'ip6' are renamed to 'ipv6'.
--       The ioc_ip6 partition is replaced by ioc_ipv6.
--       All FK-referencing tables and ioc_observables are updated consistently.
--
-- NOTE: usom_import_cursors.ioc_type keeps 'ip6' — that column tracks USOM external
--       API pagination types, not canonical stored IOC types. USOM API itself uses 'ip6'.
--
-- IDEMPOTENCY: Safe to run multiple times.

BEGIN;

-- 1. Create ipv6 partition (no-op if already exists).
CREATE TABLE IF NOT EXISTS ioc_ipv6 PARTITION OF ioc_items
  FOR VALUES IN ('ipv6');

-- 2. Collision check: verify no row already exists with observable_type='ipv6' sharing
--    the same dedup key as an existing 'ip6' row.
DO $$
DECLARE
  collision_count BIGINT;
BEGIN
  SELECT COUNT(*) INTO collision_count
  FROM ioc_items a
  JOIN ioc_items b
    ON  a.observable    = b.observable
    AND a.source_name   = b.source_name
    AND COALESCE(a.confidence, '')  = COALESCE(b.confidence, '')
    AND COALESCE(a.category, '')    = COALESCE(b.category, '')
    AND COALESCE(a.source_url, '')  = COALESCE(b.source_url, '')
  WHERE a.observable_type = 'ip6'
    AND b.observable_type = 'ipv6';
  IF collision_count > 0 THEN
    RAISE EXCEPTION
      'ip6→ipv6 migration: % collision(s) detected. Resolve duplicates manually before running this migration.',
      collision_count;
  END IF;
  RAISE NOTICE 'ip6→ipv6 migration: collision check passed (0 collisions).';
END
$$;

-- 3. Disable FK-check triggers on ioc_items so the partition key update is not blocked
--    by NO ACTION referential checks from child tables.
ALTER TABLE ioc_items DISABLE TRIGGER ALL;

-- 4. Move rows from ioc_ip6 → ioc_ipv6 by updating the partition key.
--    PostgreSQL 14+ transparently moves rows across partitions on UPDATE.
UPDATE ioc_items
SET observable_type = 'ipv6'
WHERE observable_type = 'ip6';

-- 5. Re-enable triggers.
ALTER TABLE ioc_items ENABLE TRIGGER ALL;

-- 6. Update all FK-referencing tables that store ioc_observable_type = 'ip6'.
--    These updates are now safe: ioc_items already has the 'ipv6' rows.

UPDATE ioc_feed_memberships
   SET ioc_observable_type = 'ipv6'
 WHERE ioc_observable_type = 'ip6';

UPDATE ioc_feed_source_evidence
   SET ioc_observable_type = 'ipv6'
 WHERE ioc_observable_type = 'ip6';

UPDATE ioc_tags
   SET ioc_observable_type = 'ipv6'
 WHERE ioc_observable_type = 'ip6';

UPDATE ioc_threat_classifications
   SET ioc_observable_type = 'ipv6'
 WHERE ioc_observable_type = 'ip6';

UPDATE ioc_analyst_intelligence
   SET ioc_observable_type = 'ipv6'
 WHERE ioc_observable_type = 'ip6';

UPDATE ioc_manual_source_memberships
   SET ioc_observable_type = 'ipv6'
 WHERE ioc_observable_type = 'ip6';

UPDATE ioc_source_tag_overrides
   SET ioc_observable_type = 'ipv6'
 WHERE ioc_observable_type = 'ip6';

-- 7. Operational tables: ioc_type field (no FK — safe to update directly).

UPDATE ioc_suppressions
   SET ioc_type = 'ipv6'
 WHERE ioc_type = 'ip6';

UPDATE ioc_enrichments
   SET ioc_type = 'ipv6'
 WHERE ioc_type = 'ip6';

-- 8. Drop the now-empty ioc_ip6 partition.
DROP TABLE IF EXISTS ioc_ip6 CASCADE;

-- 9. Update ioc_observables: rename type first (avoids CHECK violation), then update constraint.
UPDATE ioc_observables
   SET observable_type = 'ipv6'
 WHERE observable_type = 'ip6';

ALTER TABLE ioc_observables DROP CONSTRAINT IF EXISTS chk_observable_type;
ALTER TABLE ioc_observables ADD CONSTRAINT chk_observable_type CHECK (observable_type IN (
  'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'tlsh',
  'ip', 'ipv6', 'domain', 'url'
));

-- 10. Verification.
DO $$
DECLARE
  remaining_items      BIGINT;
  remaining_observables BIGINT;
BEGIN
  SELECT COUNT(*) INTO remaining_items      FROM ioc_items      WHERE observable_type = 'ip6';
  SELECT COUNT(*) INTO remaining_observables FROM ioc_observables WHERE observable_type = 'ip6';

  IF remaining_items > 0 THEN
    RAISE WARNING 'ip6→ipv6: % ioc_items rows still have observable_type=ip6', remaining_items;
  ELSE
    RAISE NOTICE  'ip6→ipv6: ioc_items — OK, 0 ip6 rows remain';
  END IF;

  IF remaining_observables > 0 THEN
    RAISE WARNING 'ip6→ipv6: % ioc_observables rows still have observable_type=ip6', remaining_observables;
  ELSE
    RAISE NOTICE  'ip6→ipv6: ioc_observables — OK, 0 ip6 rows remain';
  END IF;
END
$$;

COMMIT;

-- Post-migration verification queries (run manually):
--   SELECT observable_type, COUNT(*) FROM ioc_items GROUP BY observable_type ORDER BY observable_type;
--   SELECT COUNT(*) FROM ioc_items WHERE observable_type = 'ip6';   -- Expected: 0
--   SELECT COUNT(*) FROM ioc_items WHERE observable_type = 'ipv6';  -- Expected: former ip6 count
