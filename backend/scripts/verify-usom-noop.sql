-- Two-run USOM no-op verification (migration 121 / membership dedup).
--
-- HOW TO USE
--   psql -U postgres -d talonhound -v ioc="'bumuhgudereteyse.lol'" -f verify-usom-noop.sql
--
-- Run section A, then trigger a USOM import, then run section A again and diff.
-- Section B is the authoritative check: it proves whether PostgreSQL emitted physical
-- row updates, independently of what the application reports.

\set ioc :ioc
\if :{?ioc}
\else
  \set ioc '''bumuhgudereteyse.lol'''
\endif

-- ============================================================================
-- A. Per-IOC state. Every value here MUST be identical across two unchanged runs.
-- ============================================================================
SELECT
  i.id                             AS ioc_row_id,
  i.public_id,
  i.observable,
  i.observable_type,
  i.status                         AS ioc_status,
  i.updated_at                     AS ioc_updated_at,
  m.id                             AS membership_id,
  m.updated_at                     AS membership_updated_at,
  m.first_seen_in_feed             AS first_seen_in_source,
  COALESCE(m.last_changed_in_source, m.first_seen_in_feed)
                                   AS last_changed_in_source,   -- analyst-visible
  m.last_seen_in_feed              AS technical_presence,       -- may move; not shown in UI
  m.last_observed_in_source        AS technical_observed,       -- may move; not shown in UI
  m.content_fingerprint,
  m.status                         AS membership_status,
  m.missing_since
FROM ioc_items i
JOIN ioc_feed_memberships m
  ON m.ioc_item_id = i.id AND m.ioc_observable_type = i.observable_type
JOIN integration_feeds f ON f.integration_id = m.feed_id
WHERE i.observable = :ioc
  AND f.key = 'usom-trcert';

-- Audit row count for this IOC. MUST NOT increase across an unchanged run.
SELECT COUNT(*) AS audit_rows
FROM audit_logs a
WHERE a.subject_type = 'ioc'
  AND a.subject_id IN (
    SELECT public_id::text FROM ioc_items WHERE observable = :ioc
  );

-- ============================================================================
-- B. Physical UPDATE proof. Snapshot n_tup_upd BEFORE and AFTER the second run.
--    On a fully unchanged snapshot the delta for ioc_feed_memberships and
--    ioc_items must be 0 (or only reflect genuinely changed rows).
-- ============================================================================
SELECT relname,
       n_tup_ins,
       n_tup_upd,
       n_tup_hot_upd,
       n_dead_tup
FROM pg_stat_user_tables
WHERE relname IN ('ioc_items', 'ioc_feed_memberships', 'ioc_feed_source_evidence')
ORDER BY relname;

-- ============================================================================
-- C. Run counters. unchanged should carry the volume; changed/reactivated/removed
--    should be 0 on a genuinely unchanged snapshot. records_duplicate is the
--    deprecated alias and must equal records_unchanged.
-- ============================================================================
SELECT r.id,
       r.status,
       r.run_mode,
       r.started_at,
       r.finished_at,
       r.records_processed,
       r.records_inserted   AS created,
       r.records_updated    AS changed,
       r.records_unchanged  AS unchanged,
       r.records_reactivated,
       r.records_removed,
       r.records_duplicate  AS deprecated_alias,
       r.records_failed
FROM integration_runs r
JOIN integration_feeds f ON f.integration_id = r.feed_id
WHERE f.key = 'usom-trcert'
ORDER BY r.started_at DESC
LIMIT 5;

-- ============================================================================
-- D. Feed-level "last successfully checked". THIS is the timestamp that should
--    advance on every successful run — it is the correct home for presence.
-- ============================================================================
SELECT source_name, updated_at AS feed_last_successful_check
FROM integration_source_state
WHERE source_name = 'USOM:TR-CERT';

-- ============================================================================
-- E. Configured expiration policy. Determines whether technical presence writes
--    happen at all (only expiration_mode = 'last_seen_ttl' triggers them).
-- ============================================================================
SELECT p.observable_type, p.enabled, p.expiration_mode, p.ttl_days, p.grace_days
FROM threat_feed_expiration_policies p
JOIN integration_feeds f ON f.integration_id = p.feed_id
WHERE f.key = 'usom-trcert';
