-- Migration 121: Separate analyst-visible membership timestamps from technical presence.
--
-- WHY
-- ---
-- ioc_feed_memberships.last_seen_in_feed carried two unrelated meanings at once:
--   1. technical: "the importer saw this IOC in the source during the last run"
--   2. analyst-facing: rendered in the UI as "Last confirmed in source"
-- Because the USOM bulk import path (integration/lib/usomImportStore.js) rewrote
-- last_seen_in_feed on EVERY run with no change guard, an unchanged re-import
-- advanced a timestamp the analyst reads as meaningful. This migration splits the
-- two meanings into distinct columns so the importer can record presence without
-- touching anything an analyst sees.
--
-- WHAT
-- ----
-- ioc_feed_memberships gains two nullable columns:
--   content_fingerprint     - canonical hash of source-controlled normalized content.
--                             Drives the conditional upsert: no fingerprint change
--                             => no physical UPDATE.
--   last_changed_in_source  - ANALYST-VISIBLE. Advances only when the source-controlled
--                             content genuinely changed, or on reactivation.
--
-- NO separate presence column is added, deliberately. Full-snapshot presence is already
-- derived transactionally from the usom_import_stage anti-join, which costs zero
-- membership writes. The only configuration that genuinely needs a per-row presence
-- write is expiration_mode = 'last_seen_ttl', whose expiry is computed as
-- `last_seen_in_feed + ttl` — so the importer writes that existing column directly for
-- those feeds only. Adding a parallel "observed at" column would mean UPDATEing hundreds
-- of thousands of membership rows on every snapshot while changing no behaviour.
--
-- last_seen_in_feed is therefore LEFT IN PLACE and reclassified as legacy/technical:
-- still the last_seen_ttl input, still indexed for internal recency sorting, but it must
-- never be surfaced in API or UI as an analyst fact.
--
-- NO BACKFILL (deliberate)
-- ------------------------
-- All three columns are left NULL rather than backfilled. This is a correctness
-- decision, not just a locking one:
--
--   * last_changed_in_source: the true historical "last real change" time CANNOT be
--     reliably reconstructed. Past unchanged re-imports already advanced
--     last_seen_in_feed, so copying it would bake in exactly the wrong values this
--     work exists to fix. Readers COALESCE(last_changed_in_source, first_seen_in_feed)
--     instead, making first_seen_in_feed the documented migration baseline. Rows adopt
--     a real value the first time genuine content change is observed after deploy.
--
--   * content_fingerprint: NULL means "not yet adopted". The importer treats a NULL
--     existing fingerprint as a silent one-time adoption: it stores the computed
--     fingerprint but classifies the row as UNCHANGED, writes no audit entry and does
--     not advance last_changed_in_source. This prevents the entire membership table
--     from being reported as "changed" on the first run after deploy.
--
-- Leaving the columns NULL also means ADD COLUMN is metadata-only on PostgreSQL 11+
-- (no table rewrite, no long lock) even on a large membership table.
--
-- INDEXES / CONCURRENTLY
-- ----------------------
-- The migration runner (backend/migrate.js) wraps every migration file in a single
-- BEGIN/COMMIT, and CREATE INDEX CONCURRENTLY cannot run inside a transaction block.
-- No index is created here: all membership reads affected by this change are already
-- served by the existing unique key (ioc_item_id, ioc_observable_type, feed_id) or by
-- per-IOC filtered lookups, so no new index is required. If a global sort on
-- last_changed_in_source is added later, build it out of band:
--
--   CREATE INDEX CONCURRENTLY idx_ioc_feed_memberships_last_changed
--     ON ioc_feed_memberships (last_changed_in_source DESC NULLS LAST);
--
-- ROLLBACK
-- --------
-- Fully reversible with no data loss, because nothing existing was modified:
--   ALTER TABLE ioc_feed_memberships
--     DROP COLUMN IF EXISTS content_fingerprint,
--     DROP COLUMN IF EXISTS last_changed_in_source;
--   ALTER TABLE integration_runs
--     DROP COLUMN IF EXISTS records_unchanged,
--     DROP COLUMN IF EXISTS records_reactivated,
--     DROP COLUMN IF EXISTS records_removed;
-- Reverting the code alone is also safe: the old importer ignores these columns and
-- last_seen_in_feed was never stopped being maintained.

ALTER TABLE ioc_feed_memberships
  ADD COLUMN IF NOT EXISTS content_fingerprint TEXT NULL,
  ADD COLUMN IF NOT EXISTS last_changed_in_source TIMESTAMPTZ NULL;

COMMENT ON COLUMN ioc_feed_memberships.content_fingerprint IS
  'Canonical sha256 of source-controlled normalized content. NULL = not yet adopted (treated as unchanged on first observation).';
COMMENT ON COLUMN ioc_feed_memberships.last_changed_in_source IS
  'ANALYST-VISIBLE. Advances only on genuine source content change or reactivation. NULL falls back to first_seen_in_feed.';
COMMENT ON COLUMN ioc_feed_memberships.last_seen_in_feed IS
  'LEGACY/TECHNICAL. Written only for last_seen_ttl expiration policies and internal recency sorting. Do NOT surface in API or UI; use last_changed_in_source instead.';

-- Run counters with explicit, non-overlapping semantics.
-- records_duplicate is DEPRECATED but intentionally retained for backward
-- compatibility: it is now populated with the same value as records_unchanged.
-- Do not drop it in this change set; frontend reads records_unchanged.
ALTER TABLE integration_runs
  ADD COLUMN IF NOT EXISTS records_unchanged INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS records_reactivated INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS records_removed INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN integration_runs.records_unchanged IS
  'Rows seen again with identical canonical content fingerprint. No physical UPDATE was issued for these.';
COMMENT ON COLUMN integration_runs.records_reactivated IS
  'Previously inactive/expired/missing memberships that returned in a successful run.';
COMMENT ON COLUMN integration_runs.records_removed IS
  'Memberships marked missing/inactive by a successful FULL snapshot reconciliation only.';
COMMENT ON COLUMN integration_runs.records_duplicate IS
  'DEPRECATED alias of records_unchanged, retained for API backward compatibility. Use records_unchanged.';
