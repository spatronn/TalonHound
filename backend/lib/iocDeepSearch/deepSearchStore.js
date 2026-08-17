// Data-access layer for ioc_deep_searches + ioc_deep_search_results, shared by the HTTP
// routes and the worker. Keeps all Deep Search lifecycle SQL in one place. Mirrors
// iocSearchExport/exportStore.js conventions.

import { ACTIVE_BULK_QUERY_STATUSES } from '../iocBulkQueryJob/status.js';

const SELECT_COLUMNS = `
  id, original_query, normalized_query, normalized_ast, query_fingerprint,
  classification_reason, origin, status, requested_by_id, requested_by_email,
  requested_at, started_at, completed_at, snapshot_cutoff, match_count,
  duration_ms, progress, expires_at, failure_reason, cancel_requested, cancelled_at,
  job_id, created_at, updated_at`;

/**
 * Keep the materialized spool while a query-wide bulk job is still queued or
 * processing. Expiry may still hide the result from new HTTP jobs (isBrowsable);
 * cleanup must not delete rows out from under an in-flight mutation.
 */
const ACTIVE_BULK_STATUS_SQL = ACTIVE_BULK_QUERY_STATUSES.map((s) => `'${s}'`).join(', ');

export const DEEP_SEARCH_ACTIVE_BULK_JOB_EXISTS_SQL = `EXISTS (
  SELECT 1 FROM ioc_bulk_query_jobs j
   WHERE j.status IN (${ACTIVE_BULK_STATUS_SQL})
     AND j.payload->>'deep_search_id' = ioc_deep_searches.id::text
)`;

export async function createDeepSearch(db, {
  originalQuery,
  normalizedQuery,
  normalizedAst,
  queryFingerprint,
  classificationReason,
  origin = 'classified',
  requestedById,
  requestedByEmail
}) {
  const { rows } = await db.query(
    `INSERT INTO ioc_deep_searches
       (original_query, normalized_query, normalized_ast, query_fingerprint,
        classification_reason, origin, requested_by_id, requested_by_email)
     VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8)
     RETURNING ${SELECT_COLUMNS}`,
    [
      originalQuery,
      normalizedQuery,
      JSON.stringify(normalizedAst),
      queryFingerprint,
      classificationReason,
      origin,
      requestedById,
      requestedByEmail
    ]
  );
  return rows[0];
}

export async function getDeepSearchById(db, id) {
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM ioc_deep_searches WHERE id = $1`,
    [id]
  );
  return rows[0] || null;
}

/**
 * Find a still-active (queued/running) Deep Search for the same user + normalized query, so
 * repeated submits reuse the in-flight job instead of spawning duplicates. Scoped to the
 * requesting user — never dedupes across users (that would leak one user's search activity
 * to another).
 */
export async function findActiveDuplicate(db, { userId, queryFingerprint }) {
  const id = Number(userId);
  if (!Number.isFinite(id) || id <= 0) return null;
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM ioc_deep_searches
      WHERE requested_by_id = $1 AND query_fingerprint = $2
        AND status IN ('queued', 'running')
      ORDER BY created_at DESC
      LIMIT 1`,
    [id, queryFingerprint]
  );
  return rows[0] || null;
}

export async function countActiveForUser(db, userId) {
  const id = Number(userId);
  if (!Number.isFinite(id) || id <= 0) return 0;
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS n FROM ioc_deep_searches
      WHERE requested_by_id = $1 AND status IN ('queued', 'running')`,
    [id]
  );
  return rows[0]?.n || 0;
}

function buildListWhere({ userId, includeAll, statuses }) {
  const params = [];
  const clauses = [];
  if (!includeAll) {
    const id = Number(userId);
    if (Number.isFinite(id) && id > 0) {
      params.push(id);
      clauses.push(`requested_by_id = $${params.length}`);
    } else {
      clauses.push('FALSE');
    }
  }
  if (Array.isArray(statuses) && statuses.length) {
    const onlyExpired = statuses.length === 1 && statuses[0] === 'expired';
    const onlyCompleted = statuses.length === 1 && statuses[0] === 'completed';
    if (onlyExpired) {
      clauses.push(`(status = 'expired' OR (status = 'completed' AND expires_at IS NOT NULL AND expires_at <= NOW()))`);
    } else if (onlyCompleted) {
      clauses.push(`status = 'completed' AND (expires_at IS NULL OR expires_at > NOW())`);
    } else {
      params.push(statuses);
      clauses.push(`status = ANY($${params.length}::text[])`);
      if (statuses.includes('completed') && !statuses.includes('expired')) {
        clauses.push(`NOT (status = 'completed' AND expires_at IS NOT NULL AND expires_at <= NOW())`);
      }
    }
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  return { where, params };
}

export async function listDeepSearches(db, { userId, includeAll = false, limit = 50, offset = 0, statuses = null } = {}) {
  const { where, params } = buildListWhere({ userId, includeAll, statuses });
  params.push(Math.min(Math.max(limit, 1), 200));
  const limitIdx = params.length;
  params.push(Math.max(offset, 0));
  const offsetIdx = params.length;
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM ioc_deep_searches
     ${where}
     ORDER BY created_at DESC
     LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
    params
  );
  return rows;
}

export async function countDeepSearches(db, { userId, includeAll = false, statuses = null } = {}) {
  const { where, params } = buildListWhere({ userId, includeAll, statuses });
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS n FROM ioc_deep_searches ${where}`,
    params
  );
  return rows[0]?.n || 0;
}

export async function setJobId(db, id, jobId) {
  await db.query(`UPDATE ioc_deep_searches SET job_id = $2, updated_at = NOW() WHERE id = $1`, [id, jobId]);
}

// Atomically claim a queued search for processing. Returns the row if this call won the
// claim (status flipped to 'running'), else null.
export async function claimForProcessing(db, id, snapshotCutoff) {
  const { rows } = await db.query(
    `UPDATE ioc_deep_searches
        SET status = 'running',
            started_at = COALESCE(started_at, NOW()),
            snapshot_cutoff = $2::timestamptz,
            progress = 0,
            failure_reason = NULL,
            updated_at = NOW()
      WHERE id = $1 AND status = 'queued'
      RETURNING ${SELECT_COLUMNS}`,
    [id, snapshotCutoff]
  );
  return rows[0] || null;
}

/**
 * Flip a running search to completed — but ONLY if it is still 'running' and no cancel has
 * been requested. Returns true iff the row was updated. The cancel guard makes completion
 * lose any race against a concurrent cancel: a cancelled search can never be overwritten as
 * completed. The caller cleans up spool rows when this returns false.
 */
export async function markCompleted(db, id, { matchCount, durationMs, expiresAt }) {
  const { rowCount } = await db.query(
    `UPDATE ioc_deep_searches
        SET status = 'completed', progress = 100, match_count = $2,
            duration_ms = $3, expires_at = $4::timestamptz, completed_at = NOW(), updated_at = NOW()
      WHERE id = $1 AND status = 'running' AND cancel_requested = FALSE`,
    [id, matchCount, durationMs, expiresAt]
  );
  return rowCount > 0;
}

export async function markFailed(db, id, reason) {
  await db.query(
    `UPDATE ioc_deep_searches
        SET status = 'failed', failure_reason = $2, updated_at = NOW()
      WHERE id = $1`,
    [id, String(reason || 'Deep search failed').slice(0, 2000)]
  );
}

export async function markCancelled(db, id) {
  await db.query(
    `UPDATE ioc_deep_searches
        SET status = 'cancelled', cancelled_at = NOW(), updated_at = NOW()
      WHERE id = $1`,
    [id]
  );
}

// Request cancellation. Queued searches cancel immediately; running searches set the flag so
// the worker stops at its next checkpoint.
export async function requestCancel(db, id) {
  const { rows } = await db.query(
    `UPDATE ioc_deep_searches
        SET cancel_requested = TRUE,
            status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE status END,
            cancelled_at = CASE WHEN status = 'queued' THEN NOW() ELSE cancelled_at END,
            updated_at = NOW()
      WHERE id = $1 AND status IN ('queued', 'running')
      RETURNING ${SELECT_COLUMNS}`,
    [id]
  );
  return rows[0] || null;
}

export async function isCancelRequested(db, id) {
  const { rows } = await db.query(`SELECT cancel_requested FROM ioc_deep_searches WHERE id = $1`, [id]);
  return Boolean(rows[0]?.cancel_requested);
}

// ---- result spool ---------------------------------------------------------

/**
 * Read one keyset page of materialized results in canonical order (created_at DESC,
 * ioc_item_id DESC). cursor is { t, id } from the previous page's last row, or null.
 */
export async function getResultsPage(db, deepSearchId, { cursor = null, limit = 25 } = {}) {
  const params = [deepSearchId];
  let keyset = '';
  if (cursor) {
    params.push(cursor.t);
    params.push(String(cursor.id));
    keyset = ` AND (created_at, ioc_item_id) < ($${params.length - 1}::timestamptz, $${params.length}::bigint)`;
  }
  params.push(Math.min(Math.max(limit, 1), 100));
  const limitIdx = params.length;
  const { rows } = await db.query(
    `SELECT position, ioc_item_id, ioc_observable_type, public_id, observable, status,
            created_at, first_seen_at, artifact_id
       FROM ioc_deep_search_results
      WHERE deep_search_id = $1${keyset}
      ORDER BY created_at DESC, ioc_item_id DESC
      LIMIT $${limitIdx}`,
    params
  );
  return rows;
}

/**
 * Bounded ID page over the complete Deep Search spool. Used by query-wide bulk so
 * mutations target every materialized match, not the 2,000-row UI display window.
 * Pages by `position` (primary key) rather than ioc_item_id so the 2,000 display
 * cap cannot shrink the mutation set and the PK can serve the scan.
 */
export async function listDeepSearchIocIdPage(db, deepSearchId, { afterPosition = 0, limit = 100 } = {}) {
  const fetchSize = Math.min(Math.max(Math.trunc(Number(limit) || 100), 1), 100);
  const after = Number.isInteger(Number(afterPosition)) && Number(afterPosition) > 0
    ? Number(afterPosition)
    : 0;
  const { rows } = await db.query(
    `SELECT position, ioc_item_id FROM ioc_deep_search_results
      WHERE deep_search_id = $1 AND position > $2
      ORDER BY position
      LIMIT $3`,
    [deepSearchId, after, fetchSize]
  );
  return {
    ids: rows
      .map((r) => Number(r.ioc_item_id))
      .filter((id) => Number.isInteger(id) && id > 0),
    lastPosition: rows.length ? Number(rows[rows.length - 1].position) : after
  };
}

// ---- retention / cleanup --------------------------------------------------

// Find completed searches whose result-set retention window has elapsed.
export async function findExpiredCompleted(db, limit = 100) {
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM ioc_deep_searches
      WHERE status = 'completed' AND expires_at IS NOT NULL AND expires_at <= NOW()
        AND NOT ${DEEP_SEARCH_ACTIVE_BULK_JOB_EXISTS_SQL}
      ORDER BY expires_at ASC
      LIMIT $1`,
    [limit]
  );
  return rows;
}

/**
 * Delete spool rows for one Deep Search in bounded batches to avoid a long lock on a large
 * result set. Returns the number of rows deleted in this call; the caller loops until 0.
 */
export async function deleteResultsBatch(db, deepSearchId, batchSize = 10_000) {
  const { rowCount } = await db.query(
    `DELETE FROM ioc_deep_search_results
      WHERE ctid IN (
        SELECT ctid FROM ioc_deep_search_results
         WHERE deep_search_id = $1
         LIMIT $2
      )`,
    [deepSearchId, Math.min(Math.max(batchSize, 1), 200_000)]
  );
  return rowCount || 0;
}

export async function markExpired(db, id) {
  const { rows } = await db.query(
    `UPDATE ioc_deep_searches
        SET status = 'expired', match_count = NULL, updated_at = NOW()
      WHERE id = $1 AND status IN ('completed', 'expired')
      RETURNING ${SELECT_COLUMNS}`,
    [id]
  );
  return rows[0] || null;
}

// Find terminal metadata rows older than the retention window for hard deletion. Idempotent:
// only expired/failed/cancelled rows are candidates; completed/active are never deleted here.
export async function findStaleMetadata(db, { olderThanDays = 7, limit = 200 } = {}) {
  const days = Math.min(Math.max(Math.trunc(Number(olderThanDays) || 7), 1), 90);
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM ioc_deep_searches
      WHERE status IN ('expired', 'failed', 'cancelled')
        AND COALESCE(completed_at, cancelled_at, updated_at, created_at)
            <= NOW() - ($1::int * INTERVAL '1 day')
        AND NOT ${DEEP_SEARCH_ACTIVE_BULK_JOB_EXISTS_SQL}
      ORDER BY created_at ASC
      LIMIT $2`,
    [days, Math.min(Math.max(limit, 1), 500)]
  );
  return rows;
}

export async function deleteMetadataRow(db, id) {
  const { rows } = await db.query(
    `DELETE FROM ioc_deep_searches
      WHERE id = $1 AND status IN ('expired', 'failed', 'cancelled')
      RETURNING id`,
    [id]
  );
  return rows[0] || null;
}
