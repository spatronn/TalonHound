// Data-access layer for ioc_search_exports, shared by the HTTP routes and the worker.
// Keeps all SQL for the export lifecycle in one place.

const SELECT_COLUMNS = `
  id, original_query, normalized_query, normalized_ast, format, selected_columns, scope,
  status, requested_by_id, requested_by_email, requested_at, started_at, completed_at,
  snapshot_cutoff, record_count, file_size, storage_path, progress, expires_at,
  failure_reason, cancel_requested, cancelled_at, retry_count, job_id, created_at, updated_at`;

export async function createExport(db, {
  originalQuery,
  normalizedQuery,
  normalizedAst,
  format,
  selectedColumns,
  scope,
  requestedById,
  requestedByEmail
}) {
  const { rows } = await db.query(
    `INSERT INTO ioc_search_exports
       (original_query, normalized_query, normalized_ast, format, selected_columns, scope,
        requested_by_id, requested_by_email)
     VALUES ($1, $2, $3::jsonb, $4, $5::text[], $6, $7, $8)
     RETURNING ${SELECT_COLUMNS}`,
    [
      originalQuery,
      normalizedQuery,
      JSON.stringify(normalizedAst),
      format,
      selectedColumns,
      scope,
      requestedById,
      requestedByEmail
    ]
  );
  return rows[0];
}

export async function getExportById(db, id) {
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM ioc_search_exports WHERE id = $1`,
    [id]
  );
  return rows[0] || null;
}

/**
 * Build WHERE clause fragments for list/count. statuses is null (all) or a non-empty
 * array of concrete statuses. When filtering "ready", also exclude rows whose
 * expires_at has elapsed so they surface under the expired bucket instead.
 * When filtering "expired", include both stored-expired and ready-past-expiry rows.
 */
function buildListWhere({ userId, includeAll, statuses }) {
  const params = [];
  const clauses = [];
  if (!includeAll) {
    const id = Number(userId);
    if (Number.isFinite(id) && id > 0) {
      params.push(id);
      clauses.push(`requested_by_id = $${params.length}`);
    } else {
      // No immutable owner id → empty scope (never fall back to recyclable email).
      clauses.push('FALSE');
    }
  }
  if (Array.isArray(statuses) && statuses.length) {
    const onlyExpired = statuses.length === 1 && statuses[0] === 'expired';
    const onlyReady = statuses.length === 1 && statuses[0] === 'ready';
    if (onlyExpired) {
      clauses.push(`(status = 'expired' OR (status = 'ready' AND expires_at IS NOT NULL AND expires_at <= NOW()))`);
    } else if (onlyReady) {
      clauses.push(`status = 'ready' AND (expires_at IS NULL OR expires_at > NOW())`);
    } else if (statuses.includes('expired') && statuses.includes('ready')) {
      params.push(statuses);
      clauses.push(`status = ANY($${params.length}::text[])`);
    } else {
      params.push(statuses);
      clauses.push(`status = ANY($${params.length}::text[])`);
      if (statuses.includes('ready') && !statuses.includes('expired')) {
        // Keep ready filter free of already-elapsed artifacts when mixed with others.
        clauses.push(`NOT (status = 'ready' AND expires_at IS NOT NULL AND expires_at <= NOW())`);
      }
    }
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  return { where, params };
}

export async function listExports(db, { userId, includeAll = false, limit = 50, offset = 0, statuses = null } = {}) {
  const { where, params } = buildListWhere({ userId, includeAll, statuses });
  params.push(Math.min(Math.max(limit, 1), 200));
  const limitIdx = params.length;
  params.push(Math.max(offset, 0));
  const offsetIdx = params.length;
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM ioc_search_exports
     ${where}
     ORDER BY created_at DESC
     LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
    params
  );
  return rows;
}

export async function countExports(db, { userId, includeAll = false, statuses = null } = {}) {
  const { where, params } = buildListWhere({ userId, includeAll, statuses });
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS n FROM ioc_search_exports ${where}`,
    params
  );
  return rows[0]?.n || 0;
}

export async function countActiveForUser(db, userId) {
  const id = Number(userId);
  if (!Number.isFinite(id) || id <= 0) return 0;
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS n FROM ioc_search_exports
     WHERE requested_by_id = $1 AND status IN ('queued', 'processing')`,
    [id]
  );
  return rows[0]?.n || 0;
}

export async function setJobId(db, id, jobId) {
  await db.query(`UPDATE ioc_search_exports SET job_id = $2, updated_at = NOW() WHERE id = $1`, [id, jobId]);
}

// Atomically claim a queued/failed export for processing. Returns the row if this call
// won the claim (status flipped to 'processing'), else null.
export async function claimForProcessing(db, id, snapshotCutoff) {
  const { rows } = await db.query(
    `UPDATE ioc_search_exports
        SET status = 'processing',
            started_at = COALESCE(started_at, NOW()),
            snapshot_cutoff = $2::timestamptz,
            progress = 0,
            failure_reason = NULL,
            updated_at = NOW()
      WHERE id = $1 AND status IN ('queued', 'failed')
      RETURNING ${SELECT_COLUMNS}`,
    [id, snapshotCutoff]
  );
  return rows[0] || null;
}

export async function updateProgress(db, id, { progress, recordCount }) {
  await db.query(
    `UPDATE ioc_search_exports
        SET progress = LEAST(GREATEST($2, 0), 100),
            record_count = COALESCE($3, record_count),
            updated_at = NOW()
      WHERE id = $1`,
    [id, Math.trunc(progress), recordCount == null ? null : Math.trunc(recordCount)]
  );
}

export async function markReady(db, id, { recordCount, fileSize, storagePath, expiresAt }) {
  await db.query(
    `UPDATE ioc_search_exports
        SET status = 'ready', progress = 100, record_count = $2, file_size = $3,
            storage_path = $4, expires_at = $5::timestamptz, completed_at = NOW(), updated_at = NOW()
      WHERE id = $1`,
    [id, recordCount, fileSize, storagePath, expiresAt]
  );
}

export async function markFailed(db, id, reason) {
  await db.query(
    `UPDATE ioc_search_exports
        SET status = 'failed', failure_reason = $2, updated_at = NOW()
      WHERE id = $1`,
    [id, String(reason || 'Export failed').slice(0, 2000)]
  );
}

export async function markCancelled(db, id) {
  await db.query(
    `UPDATE ioc_search_exports
        SET status = 'cancelled', cancelled_at = NOW(), updated_at = NOW()
      WHERE id = $1`,
    [id]
  );
}

// Request cancellation. Queued jobs cancel immediately; processing jobs set the flag so
// the worker stops between batches.
export async function requestCancel(db, id) {
  const { rows } = await db.query(
    `UPDATE ioc_search_exports
        SET cancel_requested = TRUE,
            status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE status END,
            cancelled_at = CASE WHEN status = 'queued' THEN NOW() ELSE cancelled_at END,
            updated_at = NOW()
      WHERE id = $1 AND status IN ('queued', 'processing')
      RETURNING ${SELECT_COLUMNS}`,
    [id]
  );
  return rows[0] || null;
}

export async function isCancelRequested(db, id) {
  const { rows } = await db.query(`SELECT cancel_requested FROM ioc_search_exports WHERE id = $1`, [id]);
  return Boolean(rows[0]?.cancel_requested);
}

// Find ready exports whose retention window has elapsed.
export async function findExpiredReady(db, limit = 100) {
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM ioc_search_exports
      WHERE status = 'ready' AND expires_at IS NOT NULL AND expires_at <= NOW()
      ORDER BY expires_at ASC
      LIMIT $1`,
    [limit]
  );
  return rows;
}

export async function markExpired(db, id) {
  const { rows } = await db.query(
    `UPDATE ioc_search_exports
        SET status = 'expired', storage_path = NULL, updated_at = NOW()
      WHERE id = $1 AND status IN ('ready', 'expired')
      RETURNING ${SELECT_COLUMNS}`,
    [id]
  );
  return rows[0] || null;
}

/**
 * Find terminal metadata rows older than the retention window for hard deletion.
 * Idempotent: only expired/failed/cancelled rows are candidates; ready/active are never deleted here.
 */
export async function findStaleMetadata(db, { olderThanDays = 7, limit = 200 } = {}) {
  const days = Math.min(Math.max(Math.trunc(Number(olderThanDays) || 7), 1), 90);
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM ioc_search_exports
      WHERE status IN ('expired', 'failed', 'cancelled')
        AND COALESCE(completed_at, cancelled_at, updated_at, created_at)
            <= NOW() - ($1::int * INTERVAL '1 day')
      ORDER BY created_at ASC
      LIMIT $2`,
    [days, Math.min(Math.max(limit, 1), 500)]
  );
  return rows;
}

/**
 * Hard-delete a terminal metadata row. Returns the deleted row, or null if already gone /
 * still non-terminal (so the cleanup job stays idempotent and race-safe).
 */
export async function deleteMetadataRow(db, id) {
  const { rows } = await db.query(
    `DELETE FROM ioc_search_exports
      WHERE id = $1 AND status IN ('expired', 'failed', 'cancelled')
      RETURNING ${SELECT_COLUMNS}`,
    [id]
  );
  return rows[0] || null;
}
