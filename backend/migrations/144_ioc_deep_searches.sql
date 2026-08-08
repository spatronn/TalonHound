-- Asynchronous IOC "Deep Search".
--
-- An interactive IOC List search that the server classifies as too expensive to run under
-- the interactive statement timeout (broad / non-index-friendly predicates such as
-- `source contains "..."`, negations, short leading-wildcards, wide OR groups) — or one
-- that was classified interactive but hit the real statement timeout — is enqueued here
-- instead of failing. The ioc-deep-search worker (BullMQ queue "ioc-deep-search")
-- re-parses normalized_query under the same DSL validators, materializes the canonical
-- result set once via a database-native INSERT ... SELECT into ioc_deep_search_results,
-- and records match_count/duration. The user browses the completed result set from the
-- IOC List (keyset pagination over the spool) and Action Center.
--
-- Ownership is keyed on requested_by_email (always present), mirroring ioc_search_exports,
-- so "my searches" scoping works for sessions carrying no numeric user id.

CREATE TABLE IF NOT EXISTS ioc_deep_searches (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  original_query TEXT NOT NULL,
  normalized_query TEXT NOT NULL,
  normalized_ast JSONB NOT NULL,
  -- SHA-256 of normalized_query. Used for per-user in-flight de-duplication and for safe
  -- logging (a fingerprint is logged, never the raw query, matching audit policy).
  query_fingerprint TEXT NOT NULL,
  -- Why the query was routed to Deep Search (classifier reason code or the timeout-fallback
  -- reason). Diagnostic only; never exposes SQL internals.
  classification_reason TEXT NULL,
  origin TEXT NOT NULL DEFAULT 'classified'
    CHECK (origin IN ('classified', 'timeout_fallback')),
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'expired', 'cancelled')),
  -- users.id is BIGSERIAL; keep the search row (audit trail) if the user is deleted.
  requested_by_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL,
  requested_by_email TEXT NOT NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at TIMESTAMPTZ NULL,
  completed_at TIMESTAMPTZ NULL,
  -- Stable pagination boundary (NOT a transactional snapshot): rows created after this
  -- instant are excluded so the materialized set is deterministic.
  snapshot_cutoff TIMESTAMPTZ NULL,
  -- Exact number of canonical IOC identities materialized into the spool. There is no
  -- artificial row cap: the materialization is bounded only by the configured background DB
  -- execution timeout (IOC_DEEP_SEARCH_QUERY_TIMEOUT_MS) and available storage, so a
  -- completed search always holds the COMPLETE matching result set (never a silent subset).
  match_count BIGINT NULL,
  duration_ms BIGINT NULL,
  progress INTEGER NOT NULL DEFAULT 0
    CHECK (progress >= 0 AND progress <= 100),
  -- Result-set retention: after this instant the spool rows are swept and the row flips to
  -- 'expired' (metadata kept until the terminal-metadata retention window).
  expires_at TIMESTAMPTZ NULL,
  failure_reason TEXT NULL,
  cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
  cancelled_at TIMESTAMPTZ NULL,
  job_id TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_deep_searches_owner
  ON ioc_deep_searches (requested_by_email, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ioc_deep_searches_status_created
  ON ioc_deep_searches (status, created_at DESC);

-- Per-user in-flight de-dup lookup (same normalized query already queued/running).
CREATE INDEX IF NOT EXISTS idx_ioc_deep_searches_dedup
  ON ioc_deep_searches (requested_by_email, query_fingerprint)
  WHERE status IN ('queued', 'running');

-- Result-set expiry sweep (completed rows past expires_at).
CREATE INDEX IF NOT EXISTS idx_ioc_deep_searches_expiry
  ON ioc_deep_searches (expires_at)
  WHERE status = 'completed' AND expires_at IS NOT NULL;

-- Terminal-metadata cleanup sweep.
CREATE INDEX IF NOT EXISTS idx_ioc_deep_searches_metadata_cleanup
  ON ioc_deep_searches (status, updated_at)
  WHERE status IN ('expired', 'failed', 'cancelled');

-- Result spool: one row per canonical IOC identity in the materialized set, at a dense
-- 1-based `position` in the canonical order (created_at DESC, id DESC). The scalar display
-- columns (observable/status/timestamps) are the SAME canonical representative values the
-- interactive page SQL would emit, so browsing needs no re-aggregation — only per-id
-- enrichment (tags/classifications/counts), identical to the interactive list path.
--
-- Deliberately NO foreign key to ioc_deep_searches: the spool can hold millions of rows and
-- a per-row FK check would tax the bulk INSERT ... SELECT, while ON DELETE CASCADE of a
-- multi-million-row child risks a long lock. Retention instead deletes by deep_search_id in
-- bounded batches (idempotent, restart-safe). Orphan rows (parent gone) are impossible in
-- practice because cleanup always deletes children before the parent metadata row.
CREATE TABLE IF NOT EXISTS ioc_deep_search_results (
  deep_search_id UUID NOT NULL,
  position BIGINT NOT NULL,
  ioc_item_id BIGINT NOT NULL,
  ioc_observable_type TEXT NOT NULL,
  public_id UUID NOT NULL,
  observable TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  first_seen_at TIMESTAMPTZ NULL,
  artifact_id UUID NULL,
  PRIMARY KEY (deep_search_id, position)
);

-- Keyset pagination in canonical order, and bounded batch delete by deep_search_id.
CREATE INDEX IF NOT EXISTS idx_ioc_deep_search_results_keyset
  ON ioc_deep_search_results (deep_search_id, created_at DESC, ioc_item_id DESC);

-- DEPLOYMENT / ROLLBACK
-- ---------------------
-- Forward: purely additive — two new tables + their indexes. No existing table is altered,
-- so it is safe to apply before or during the backend/worker rollout. The migrate runner
-- wraps each file in a single transaction; every statement here is transaction-safe (no
-- CREATE INDEX CONCURRENTLY). All indexes are plain B-tree on new/empty tables, so there is
-- no long lock or table rewrite even on a multi-million-row production database (the new
-- tables start empty; ioc_items is untouched).
--
-- The ioc-deep-search worker tolerates these tables being absent (bounded wait + graceful
-- per-job failure), so ordering between "npm run migrate" and worker start is not fragile.
-- Recommended deploy order: apply migrations, then (re)start backend + workers.
--
-- Rollback (no data loss for any other table):
--   DROP TABLE IF EXISTS ioc_deep_search_results;
--   DROP TABLE IF EXISTS ioc_deep_searches;
