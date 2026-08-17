const SELECT_COLUMNS = `
  id, action, original_query, normalized_query, normalized_ast, payload, status,
  match_count, succeeded, skipped, failed, progress, error_sample,
  requested_by_id, requested_by_email, requested_by_public_id, requested_by_role,
  requested_at, started_at, completed_at, snapshot_cutoff, expires_at,
  failure_reason, cancel_requested, cancelled_at, job_id, created_at, updated_at`;

export async function createBulkQueryJob(db, {
  action,
  originalQuery,
  normalizedQuery,
  normalizedAst,
  payload,
  requestedById,
  requestedByEmail,
  requestedByPublicId,
  requestedByRole
}) {
  const { rows } = await db.query(
    `INSERT INTO ioc_bulk_query_jobs
       (action, original_query, normalized_query, normalized_ast, payload,
        requested_by_id, requested_by_email, requested_by_public_id, requested_by_role)
     VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8, $9)
     RETURNING ${SELECT_COLUMNS}`,
    [
      action,
      originalQuery,
      normalizedQuery,
      JSON.stringify(normalizedAst),
      JSON.stringify(payload || {}),
      requestedById,
      requestedByEmail,
      requestedByPublicId || null,
      requestedByRole || null
    ]
  );
  return rows[0];
}

export async function getBulkQueryJobById(db, id) {
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM ioc_bulk_query_jobs WHERE id = $1`,
    [id]
  );
  return rows[0] || null;
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

export async function listBulkQueryJobs(db, {
  userId,
  includeAll = false,
  limit = 50,
  offset = 0,
  statuses = null
} = {}) {
  const { where, params } = buildListWhere({ userId, includeAll, statuses });
  params.push(Math.min(Math.max(limit, 1), 200));
  const limitIdx = params.length;
  params.push(Math.max(offset, 0));
  const offsetIdx = params.length;
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM ioc_bulk_query_jobs
     ${where}
     ORDER BY created_at DESC
     LIMIT $${limitIdx} OFFSET $${offsetIdx}`,
    params
  );
  return rows;
}

export async function countBulkQueryJobs(db, { userId, includeAll = false, statuses = null } = {}) {
  const { where, params } = buildListWhere({ userId, includeAll, statuses });
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS n FROM ioc_bulk_query_jobs ${where}`,
    params
  );
  return Number(rows[0]?.n || 0);
}

export async function countActiveForUser(db, userId) {
  const id = Number(userId);
  if (!Number.isFinite(id) || id <= 0) return 0;
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS n FROM ioc_bulk_query_jobs
     WHERE requested_by_id = $1 AND status IN ('queued', 'processing')`,
    [id]
  );
  return Number(rows[0]?.n || 0);
}

export async function setJobId(db, id, jobId) {
  await db.query(
    `UPDATE ioc_bulk_query_jobs SET job_id = $2, updated_at = NOW() WHERE id = $1`,
    [id, jobId]
  );
}

export async function claimForProcessing(db, id) {
  const { rows } = await db.query(
    `UPDATE ioc_bulk_query_jobs
     SET status = 'processing', started_at = COALESCE(started_at, NOW()), updated_at = NOW()
     WHERE id = $1 AND status = 'queued' AND cancel_requested = FALSE
     RETURNING ${SELECT_COLUMNS}`,
    [id]
  );
  return rows[0] || null;
}

export async function markProgress(db, id, { matchCount, succeeded, skipped, failed, progress }) {
  await db.query(
    `UPDATE ioc_bulk_query_jobs
     SET match_count = COALESCE($2, match_count),
         succeeded = $3, skipped = $4, failed = $5,
         progress = $6, updated_at = NOW()
     WHERE id = $1`,
    [id, matchCount ?? null, succeeded, skipped, failed, progress]
  );
}

export async function markCompleted(db, id, {
  matchCount,
  succeeded,
  skipped,
  failed,
  errorSample,
  retentionHours
}) {
  const hours = Math.max(1, Number(retentionHours) || 24);
  const { rows } = await db.query(
    `UPDATE ioc_bulk_query_jobs
     SET status = 'completed',
         match_count = $2,
         succeeded = $3, skipped = $4, failed = $5,
         error_sample = $6::jsonb,
         progress = 100,
         completed_at = NOW(),
         expires_at = NOW() + ($7::int * INTERVAL '1 hour'),
         updated_at = NOW()
     WHERE id = $1
     RETURNING ${SELECT_COLUMNS}`,
    [id, matchCount, succeeded, skipped, failed, JSON.stringify(errorSample || []), hours]
  );
  return rows[0] || null;
}

export async function markFailed(db, id, reason) {
  const { rows } = await db.query(
    `UPDATE ioc_bulk_query_jobs
     SET status = 'failed', failure_reason = $2, completed_at = NOW(), updated_at = NOW()
     WHERE id = $1
     RETURNING ${SELECT_COLUMNS}`,
    [id, String(reason || 'Bulk action failed').slice(0, 500)]
  );
  return rows[0] || null;
}

export async function isCancelRequested(db, id) {
  const { rows } = await db.query(
    `SELECT cancel_requested FROM ioc_bulk_query_jobs WHERE id = $1`,
    [id]
  );
  return Boolean(rows[0]?.cancel_requested);
}

export async function replaceTargets(db, jobId, ids) {
  await db.query(`DELETE FROM ioc_bulk_query_job_targets WHERE job_id = $1`, [jobId]);
  if (!ids.length) return 0;
  const { rowCount } = await db.query(
    `INSERT INTO ioc_bulk_query_job_targets (job_id, ioc_item_id)
     SELECT $1::uuid, x FROM UNNEST($2::bigint[]) AS x
     ON CONFLICT DO NOTHING`,
    [jobId, ids]
  );
  return rowCount || ids.length;
}

export async function listTargetPage(db, jobId, { afterId = 0, limit = 100 } = {}) {
  const { rows } = await db.query(
    `SELECT ioc_item_id FROM ioc_bulk_query_job_targets
     WHERE job_id = $1 AND ioc_item_id > $2
     ORDER BY ioc_item_id
     LIMIT $3`,
    [jobId, afterId, limit]
  );
  return rows.map((r) => Number(r.ioc_item_id));
}

export async function deleteTargets(db, jobId) {
  await db.query(`DELETE FROM ioc_bulk_query_job_targets WHERE job_id = $1`, [jobId]);
}

export async function findStaleMetadata(db, { olderThanDays = 7, limit = 50 } = {}) {
  const { rows } = await db.query(
    `SELECT id FROM ioc_bulk_query_jobs
     WHERE status IN ('completed', 'failed', 'cancelled', 'expired')
       AND updated_at < NOW() - ($1::int * INTERVAL '1 day')
     ORDER BY updated_at ASC
     LIMIT $2`,
    [olderThanDays, limit]
  );
  return rows;
}

export async function deleteMetadataRow(db, id) {
  await db.query(`DELETE FROM ioc_bulk_query_jobs WHERE id = $1`, [id]);
}
