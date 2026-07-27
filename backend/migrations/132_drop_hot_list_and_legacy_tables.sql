-- Migration 132: Drop Hot IOC List residue and legacy map/bootstrap tables.
--
-- Removed features leaving schema residue:
--   * Hot IOC List / correlation: ioc_items.match_count + its partial hot-list index.
--     No application code reads or writes match_count (verified repo-wide); the external
--     ClickHouse sync that once populated it no longer exists.
--   * ioc_ips: pre-unification bootstrap table (0 rows), fully superseded by ioc_items.
--   * dashboard_map_*: Threat World Map backing tables. Absent in prod and created by no
--     tracked migration; dropped IF EXISTS for idempotency on any environment that still
--     has them. (Backend still contains error-swallowed no-op writers/readers for these;
--     that dead code is removed separately.)
--
-- Forward-only; migration history is immutable. migrate.js wraps this file in a single
-- transaction and sets lock_timeout/statement_timeout, so no explicit BEGIN/COMMIT here.
-- KEEP idx_ioc_items_last_seen: last_seen_log is still read (feed publisher, match
-- reactivation). DROP COLUMN on ioc_items is metadata-only (no table rewrite); the brief
-- AccessExclusiveLock is bounded by migrate.js lock_timeout.

-- Hot IOC List partial index (its predicate references match_count).
DROP INDEX IF EXISTS idx_ioc_items_hot_partial;

-- Standalone match_count index (absent on prod; harmless IF EXISTS elsewhere).
DROP INDEX IF EXISTS idx_ioc_items_match_count;

-- Unused column (0 readers/writers in application code).
ALTER TABLE ioc_items DROP COLUMN IF EXISTS match_count;

-- Legacy pre-ioc_items bootstrap table (0 rows, no code references).
DROP TABLE IF EXISTS ioc_ips;

-- Threat World Map backing tables (removed feature; absent in prod).
DROP TABLE IF EXISTS dashboard_map_pending_events;
DROP TABLE IF EXISTS dashboard_map_display_snapshot;
DROP TABLE IF EXISTS dashboard_map_job_state;
