-- Source-level IOC removal: manual/custom source can be detached from an IOC
-- while its membership history is preserved as a truthful tombstone.
--
-- ioc_manual_source_memberships (95_ioc_source_lifecycle.sql) already records
-- historical manual source memberships with statuses 'moved' / 'superseded' /
-- 'inactive'. A manual "Remove from source" is a distinct lifecycle event, so it
-- gets its own 'removed' status rather than being faked as expired/moved. The
-- existing moved_at / moved_by / move_reason columns carry when/who/why (with
-- moved_to_source_id NULL, since a removal has no destination source).
--
-- This migration ONLY widens the status CHECK constraint. No rows are rewritten
-- and no data is deleted. The constraint is added NOT VALID then validated so the
-- brief exclusive lock is limited to the catalog swap, not a full-table rewrite
-- (VALIDATE takes only SHARE UPDATE EXCLUSIVE and never blocks reads/writes).

ALTER TABLE ioc_manual_source_memberships
  DROP CONSTRAINT IF EXISTS ioc_manual_source_memberships_status_check;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'ioc_manual_source_memberships_status_check'
  ) THEN
    ALTER TABLE ioc_manual_source_memberships
      ADD CONSTRAINT ioc_manual_source_memberships_status_check
      CHECK (status IN ('active', 'moved', 'superseded', 'inactive', 'removed'))
      NOT VALID;
    ALTER TABLE ioc_manual_source_memberships
      VALIDATE CONSTRAINT ioc_manual_source_memberships_status_check;
  END IF;
END $$;
