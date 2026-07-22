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

export async function listExports(db, { email, includeAll = false, limit = 50, offset = 0 }) {
  const params = [];
  let where = '';
  if (!includeAll) {
    params.push(email);
    where = `WHERE requested_by_email = $${params.length}`;
  }
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

export async function countActiveForUser(db, email) {
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS n FROM ioc_search_exports
     WHERE requested_by_email = $1 AND status IN ('queued', 'processing')`,
    [email]
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

export async function prepareRetry(db, id, maxRetries) {
  const { rows } = await db.query(
    `UPDATE ioc_search_exports
        SET status = 'queued', progress = 0, failure_reason = NULL, cancel_requested = FALSE,
            started_at = NULL, completed_at = NULL, storage_path = NULL, file_size = NULL,
            snapshot_cutoff = NULL, retry_count = retry_count + 1, updated_at = NOW()
      WHERE id = $1 AND status = 'failed' AND retry_count < $2
      RETURNING ${SELECT_COLUMNS}`,
    [id, maxRetries]
  );
  return rows[0] || null;
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
  await db.query(
    `UPDATE ioc_search_exports
        SET status = 'expired', storage_path = NULL, updated_at = NOW()
      WHERE id = $1`,
    [id]
  );
}
