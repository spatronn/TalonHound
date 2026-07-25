// Data-access for system_backups.

const SELECT_COLUMNS = `
  id, backup_id, trigger_type, status, started_at, completed_at, duration_ms,
  archive_path, archive_filename, archive_size_bytes, checksum_sha256, encrypted,
  database_size_bytes, files_size_bytes, error_code, error_message,
  verified_at, verify_status, verify_error, manifest, job_id,
  created_by_id, created_by_email, created_at, updated_at`;

export async function createBackupRow(db, {
  backupId,
  triggerType = 'manual',
  createdById = null,
  createdByEmail = null,
  encrypted = false
}) {
  const { rows } = await db.query(
    `INSERT INTO system_backups
       (backup_id, trigger_type, status, encrypted, created_by_id, created_by_email)
     VALUES ($1, $2, 'queued', $3, $4, $5)
     RETURNING ${SELECT_COLUMNS}`,
    [backupId, triggerType, encrypted, createdById, createdByEmail]
  );
  return rows[0];
}

export async function getBackupById(db, id) {
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM system_backups WHERE id = $1`,
    [id]
  );
  return rows[0] || null;
}

export async function getBackupByBackupId(db, backupId) {
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM system_backups WHERE backup_id = $1`,
    [backupId]
  );
  return rows[0] || null;
}

export async function listBackups(db, { limit = 50, offset = 0, statuses = null } = {}) {
  const params = [];
  const clauses = [`status <> 'deleted'`];
  if (Array.isArray(statuses) && statuses.length) {
    params.push(statuses);
    clauses.push(`status = ANY($${params.length}::text[])`);
  }
  params.push(Math.min(Math.max(limit, 1), 200));
  const lim = params.length;
  params.push(Math.max(offset, 0));
  const off = params.length;
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM system_backups
     WHERE ${clauses.join(' AND ')}
     ORDER BY created_at DESC
     LIMIT $${lim} OFFSET $${off}`,
    params
  );
  return rows;
}

export async function countBackups(db, { statuses = null, excludeDeleted = true } = {}) {
  const params = [];
  const clauses = [];
  if (excludeDeleted) clauses.push(`status <> 'deleted'`);
  if (Array.isArray(statuses) && statuses.length) {
    params.push(statuses);
    clauses.push(`status = ANY($${params.length}::text[])`);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  const { rows } = await db.query(`SELECT COUNT(*)::int AS n FROM system_backups ${where}`, params);
  return rows[0]?.n || 0;
}

export async function countActiveBackups(db) {
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS n FROM system_backups
     WHERE status IN ('queued', 'running', 'verifying')`
  );
  return rows[0]?.n || 0;
}

export async function setJobId(db, id, jobId) {
  await db.query(
    `UPDATE system_backups SET job_id = $2, updated_at = NOW() WHERE id = $1`,
    [id, jobId]
  );
}

export async function claimBackup(db, id) {
  const { rows } = await db.query(
    `UPDATE system_backups
        SET status = 'running',
            started_at = COALESCE(started_at, NOW()),
            error_code = NULL,
            error_message = NULL,
            updated_at = NOW()
      WHERE id = $1 AND status IN ('queued', 'failed', 'interrupted')
      RETURNING ${SELECT_COLUMNS}`,
    [id]
  );
  return rows[0] || null;
}

export async function markVerifying(db, id) {
  const { rows } = await db.query(
    `UPDATE system_backups
        SET status = 'verifying', updated_at = NOW()
      WHERE id = $1 AND status = 'running'
      RETURNING ${SELECT_COLUMNS}`,
    [id]
  );
  return rows[0] || null;
}

export async function markCompleted(db, id, {
  archivePath,
  archiveFilename,
  archiveSizeBytes,
  checksumSha256,
  databaseSizeBytes,
  filesSizeBytes = 0,
  encrypted = false,
  manifest,
  durationMs
}) {
  const { rows } = await db.query(
    `UPDATE system_backups
        SET status = 'completed',
            completed_at = NOW(),
            duration_ms = $2,
            archive_path = $3,
            archive_filename = $4,
            archive_size_bytes = $5,
            checksum_sha256 = $6,
            database_size_bytes = $7,
            files_size_bytes = $8,
            encrypted = $9,
            manifest = $10::jsonb,
            verified_at = NOW(),
            verify_status = 'passed',
            verify_error = NULL,
            updated_at = NOW()
      WHERE id = $1
      RETURNING ${SELECT_COLUMNS}`,
    [
      id,
      durationMs,
      archivePath,
      archiveFilename,
      archiveSizeBytes,
      checksumSha256,
      databaseSizeBytes,
      filesSizeBytes,
      encrypted,
      JSON.stringify(manifest)
    ]
  );
  return rows[0];
}

export async function markFailed(db, id, { errorCode, errorMessage }) {
  const { rows } = await db.query(
    `UPDATE system_backups
        SET status = 'failed',
            completed_at = NOW(),
            error_code = $2,
            error_message = $3,
            updated_at = NOW()
      WHERE id = $1
      RETURNING ${SELECT_COLUMNS}`,
    [id, errorCode || 'BACKUP_FAILED', String(errorMessage || 'Backup failed').slice(0, 2000)]
  );
  return rows[0];
}

export async function markDeleted(db, id) {
  const { rows } = await db.query(
    `UPDATE system_backups
        SET status = 'deleted', updated_at = NOW(), archive_path = NULL
      WHERE id = $1 AND status IN ('completed', 'failed', 'interrupted')
      RETURNING ${SELECT_COLUMNS}`,
    [id]
  );
  return rows[0] || null;
}

export async function markVerifyResult(db, id, { ok, error = null, checksum = null }) {
  const { rows } = await db.query(
    `UPDATE system_backups
        SET verified_at = NOW(),
            verify_status = $2,
            verify_error = $3,
            checksum_sha256 = COALESCE($4, checksum_sha256),
            updated_at = NOW()
      WHERE id = $1
      RETURNING ${SELECT_COLUMNS}`,
    [id, ok ? 'passed' : 'failed', ok ? null : String(error || 'verify failed').slice(0, 2000), checksum]
  );
  return rows[0];
}

export async function interruptStale(db, staleMinutes = 180) {
  const { rows } = await db.query(
    `UPDATE system_backups
        SET status = 'interrupted',
            error_code = 'INTERRUPTED',
            error_message = 'Backup interrupted by process restart or stale lock',
            updated_at = NOW()
      WHERE status IN ('queued', 'running', 'verifying')
        AND updated_at < NOW() - ($1::text || ' minutes')::interval
      RETURNING ${SELECT_COLUMNS}`,
    [String(staleMinutes)]
  );
  return rows;
}

export async function interruptAllActive(db) {
  const { rows } = await db.query(
    `UPDATE system_backups
        SET status = 'interrupted',
            error_code = 'INTERRUPTED',
            error_message = 'Backup interrupted by worker restart',
            updated_at = NOW()
      WHERE status IN ('queued', 'running', 'verifying')
      RETURNING ${SELECT_COLUMNS}`
  );
  return rows;
}

export async function getLastSuccessful(db) {
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM system_backups
     WHERE status = 'completed'
     ORDER BY completed_at DESC NULLS LAST
     LIMIT 1`
  );
  return rows[0] || null;
}

export async function sumCompletedArchiveBytes(db) {
  const { rows } = await db.query(
    `SELECT COALESCE(SUM(archive_size_bytes), 0)::bigint AS n
     FROM system_backups WHERE status = 'completed'`
  );
  return Number(rows[0]?.n || 0);
}

export async function listCompletedForRetention(db) {
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM system_backups WHERE status = 'completed'`
  );
  return rows;
}

export async function getProtectedBackupIds(db) {
  const { rows } = await db.query(
    `SELECT DISTINCT backup_id FROM system_restores
     WHERE status IN ('pending_confirmation', 'ready', 'running')
     UNION
     SELECT DISTINCT safety_backup_id FROM system_restores
     WHERE safety_backup_id IS NOT NULL
       AND status IN ('pending_confirmation', 'ready', 'running')`
  );
  return new Set(rows.map((r) => r.backup_id || r.safety_backup_id).filter(Boolean));
}
