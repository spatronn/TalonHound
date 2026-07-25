// Data-access for system_restores (prepare / confirm; execute is CLI).

const SELECT_COLUMNS = `
  id, backup_row_id, backup_id, status, confirmation_phrase, safety_backup_id,
  safety_backup_row_id, cli_command, prepared_by_id, prepared_by_email,
  confirmed_by_id, confirmed_by_email, error_code, error_message,
  prepared_at, confirmed_at, started_at, completed_at, created_at, updated_at`;

export function buildRestoreCliCommand(backupId) {
  return `./scripts/restore-stack.sh --backup-id ${backupId} --confirm`;
}

export async function createRestorePrepare(db, {
  backupRowId,
  backupId,
  confirmationPhrase,
  preparedById = null,
  preparedByEmail = null,
  safetyBackupId = null,
  safetyBackupRowId = null
}) {
  const cli = buildRestoreCliCommand(backupId);
  const { rows } = await db.query(
    `INSERT INTO system_restores
       (backup_row_id, backup_id, status, confirmation_phrase, safety_backup_id,
        safety_backup_row_id, cli_command, prepared_by_id, prepared_by_email)
     VALUES ($1, $2, 'pending_confirmation', $3, $4, $5, $6, $7, $8)
     RETURNING ${SELECT_COLUMNS}`,
    [
      backupRowId,
      backupId,
      confirmationPhrase,
      safetyBackupId,
      safetyBackupRowId,
      cli,
      preparedById,
      preparedByEmail
    ]
  );
  return rows[0];
}

export async function getRestoreById(db, id) {
  const { rows } = await db.query(
    `SELECT ${SELECT_COLUMNS} FROM system_restores WHERE id = $1`,
    [id]
  );
  return rows[0] || null;
}

export async function confirmRestore(db, id, {
  confirmation,
  expectedBackupId,
  confirmedById = null,
  confirmedByEmail = null
}) {
  const phrase = String(confirmation || '').trim();
  const ok = phrase === 'RESTORE' || phrase === expectedBackupId;
  if (!ok) {
    const err = new Error('Restore confirmation did not match');
    err.code = 'CONFIRMATION';
    err.status = 400;
    throw err;
  }
  const { rows } = await db.query(
    `UPDATE system_restores
        SET status = 'ready',
            confirmed_at = NOW(),
            confirmed_by_id = $2,
            confirmed_by_email = $3,
            updated_at = NOW()
      WHERE id = $1 AND status = 'pending_confirmation'
      RETURNING ${SELECT_COLUMNS}`,
    [id, confirmedById, confirmedByEmail]
  );
  if (!rows[0]) {
    const err = new Error('Restore is not awaiting confirmation');
    err.status = 409;
    throw err;
  }
  return rows[0];
}

export async function attachSafetyBackup(db, id, { safetyBackupId, safetyBackupRowId }) {
  const { rows } = await db.query(
    `UPDATE system_restores
        SET safety_backup_id = $2,
            safety_backup_row_id = $3,
            updated_at = NOW()
      WHERE id = $1
      RETURNING ${SELECT_COLUMNS}`,
    [id, safetyBackupId, safetyBackupRowId]
  );
  return rows[0];
}

export async function markRestoreFailed(db, id, { errorCode, errorMessage }) {
  const { rows } = await db.query(
    `UPDATE system_restores
        SET status = 'failed',
            error_code = $2,
            error_message = $3,
            completed_at = NOW(),
            updated_at = NOW()
      WHERE id = $1
      RETURNING ${SELECT_COLUMNS}`,
    [id, errorCode || 'RESTORE_FAILED', String(errorMessage || '').slice(0, 2000)]
  );
  return rows[0];
}

/** Validate confirmation without DB (unit-testable). */
export function isValidRestoreConfirmation(confirmation, backupId) {
  const phrase = String(confirmation || '').trim();
  return phrase === 'RESTORE' || phrase === String(backupId || '').trim();
}
