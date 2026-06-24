-- Migration 096 set ON DELETE SET NULL but ioc_source_id was NOT NULL, causing delete to crash.
-- Preserve move history rows with denormalized source_name when the source row is deleted.

ALTER TABLE ioc_manual_source_memberships
  ALTER COLUMN ioc_source_id DROP NOT NULL;
