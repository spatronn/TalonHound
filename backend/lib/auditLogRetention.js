/**
 * Audit Log Retention / Lifecycle.
 *
 * Central retention window for the audit_logs table, persisted on the canonical
 * singleton system_settings row (see migrations/162_audit_log_retention.sql).
 *
 *   audit_log_retention_days = <positive int>  -> delete rows older than N days
 *   audit_log_retention_days = NULL            -> "Keep forever" (no deletion)
 *
 * The cutoff is always computed server-side with NOW() (an absolute instant),
 * so the database owns the boundary and no frontend-local-time math can affect
 * which rows are deleted. Deletion is performed in small, bounded, index-driven
 * batches (never one huge DELETE), guarded by a Postgres advisory lock so only
 * one instance deletes at a time.
 */

const SETTINGS_ID = 1;

/** Default retention for existing/new installs. */
export const AUDIT_LOG_RETENTION_DEFAULT_DAYS = 365;

/** Preset choices surfaced in the UI (plus Custom + Keep forever). */
export const AUDIT_LOG_RETENTION_PRESET_DAYS = Object.freeze([90, 180, 365, 730]);

/**
 * Sanity upper bound for a custom value (~100 years). Not a product policy limit —
 * it only guards against absurd / overflow input while leaving any realistic
 * retention window valid. NULL ("Keep forever") is the way to disable deletion.
 */
export const AUDIT_LOG_RETENTION_MAX_DAYS = 36500;

/** Advisory lock key: only one audit-retention cleanup deletes at a time. */
export const AUDIT_LOG_RETENTION_LOCK_KEY = 72900162;

/** Default cleanup batch size (rows per bounded DELETE). */
export const AUDIT_LOG_RETENTION_DEFAULT_BATCH_SIZE = 5000;

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Validate a submitted retention value independently of any UI.
 *
 * Accepts, in order of precedence:
 *   { keep_forever: true }            -> Keep forever
 *   { mode: 'keep_forever' }          -> Keep forever
 *   { retention_days: null }          -> Keep forever
 *   { retention_days: <int> } | { days: <int> }
 *
 * Rejects zero, negatives, decimals, and non-numeric input.
 *
 * @param {unknown} body
 * @returns {{ ok: true, keepForever: boolean, days: number|null } | { ok: false, error: string }}
 */
export function parseAuditLogRetentionInput(body) {
  const b = body && typeof body === 'object' ? body : {};
  const keepForeverFlag = b.keep_forever === true || b.mode === 'keep_forever';

  const hasDaysKey = Object.prototype.hasOwnProperty.call(b, 'retention_days')
    || Object.prototype.hasOwnProperty.call(b, 'days');
  const rawDays = b.retention_days !== undefined ? b.retention_days : b.days;

  if (keepForeverFlag || rawDays === null) {
    return { ok: true, keepForever: true, days: null };
  }

  if (!hasDaysKey || rawDays === undefined || rawDays === '') {
    return { ok: false, error: 'retention_days is required (a positive integer number of days, or use keep_forever)' };
  }

  let days;
  if (typeof rawDays === 'number') {
    if (!Number.isFinite(rawDays) || !Number.isInteger(rawDays)) {
      return { ok: false, error: 'retention_days must be a whole number of days (no decimals)' };
    }
    days = rawDays;
  } else if (typeof rawDays === 'string') {
    const trimmed = rawDays.trim();
    if (!/^\d+$/.test(trimmed)) {
      return { ok: false, error: 'retention_days must be a positive integer number of days' };
    }
    days = Number(trimmed);
  } else {
    return { ok: false, error: 'retention_days must be a positive integer number of days' };
  }

  if (!Number.isFinite(days) || days <= 0) {
    return { ok: false, error: 'retention_days must be greater than zero' };
  }
  if (days > AUDIT_LOG_RETENTION_MAX_DAYS) {
    return { ok: false, error: `retention_days must not exceed ${AUDIT_LOG_RETENTION_MAX_DAYS} days` };
  }

  return { ok: true, keepForever: false, days };
}

function normalizeRetentionDays(value) {
  if (value == null) return null;
  const n = Number(value);
  return Number.isFinite(n) && n >= 1 ? Math.floor(n) : null;
}

/**
 * Read the current retention configuration from the singleton settings row.
 * Falls back to the default when the row/column is absent.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 */
export async function getAuditLogRetentionConfig(db) {
  const { rows } = await db.query(
    `SELECT audit_log_retention_days,
            audit_log_retention_updated_at,
            audit_log_retention_updated_by,
            audit_log_retention_last_run_at
       FROM system_settings
      WHERE id = $1`,
    [SETTINGS_ID]
  );
  if (!rows.length) {
    return {
      retentionDays: AUDIT_LOG_RETENTION_DEFAULT_DAYS,
      keepForever: false,
      updatedAt: null,
      updatedBy: null,
      lastRunAt: null
    };
  }
  const row = rows[0];
  const retentionDays = normalizeRetentionDays(row.audit_log_retention_days);
  return {
    retentionDays,
    keepForever: retentionDays == null,
    updatedAt: row.audit_log_retention_updated_at || null,
    updatedBy: row.audit_log_retention_updated_by || null,
    lastRunAt: row.audit_log_retention_last_run_at || null
  };
}

/**
 * Persist a new retention value. `days === null` means Keep forever.
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {{ days: number|null, updatedBy?: string|null }} opts
 */
export async function setAuditLogRetention(db, { days, updatedBy = null }) {
  const value = days == null ? null : normalizeRetentionDays(days);
  await db.query(
    `INSERT INTO system_settings (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`,
    [SETTINGS_ID]
  );
  await db.query(
    `UPDATE system_settings
        SET audit_log_retention_days = $2,
            audit_log_retention_updated_at = NOW(),
            audit_log_retention_updated_by = $3,
            updated_at = NOW()
      WHERE id = $1`,
    [SETTINGS_ID, value, updatedBy ? String(updatedBy).slice(0, 255) : null]
  );
  return getAuditLogRetentionConfig(db);
}

async function markCleanupRun(db) {
  await db.query(
    `UPDATE system_settings SET audit_log_retention_last_run_at = NOW() WHERE id = $1`,
    [SETTINGS_ID]
  );
}

/**
 * Delete a single bounded batch of audit rows older than the cutoff.
 *
 * The cutoff is computed in SQL (NOW() - N days). `FOR UPDATE SKIP LOCKED`
 * over the created_at index keeps each statement a small, self-contained
 * transaction that never waits on rows another cleaner already holds. Reuses
 * audit_logs_created_at_desc_idx — no dedicated index is required.
 *
 * @param {import('pg').Pool|import('pg').PoolClient} db
 * @param {{ days: number, batchSize: number }} opts
 * @returns {Promise<number>} rows deleted in this batch
 */
export async function deleteAuditLogsOlderThanBatch(db, { days, batchSize }) {
  const res = await db.query(
    `WITH doomed AS (
       SELECT id
         FROM audit_logs
        WHERE created_at < NOW() - make_interval(days => $1::int)
        ORDER BY created_at ASC
        LIMIT $2
        FOR UPDATE SKIP LOCKED
     )
     DELETE FROM audit_logs a
      USING doomed d
      WHERE a.id = d.id`,
    [days, batchSize]
  );
  return Number(res.rowCount || 0);
}

/**
 * Run one audit-log retention cleanup pass.
 *
 * - Acquires an advisory lock (skips if another instance holds it).
 * - Reads the configured retention; "Keep forever" performs no deletion.
 * - Daily gate: skips when the previous run is younger than `minIntervalMs`
 *   (unless `force`), so restarts/poll ticks cannot cause repeated heavy runs.
 * - Deletes in bounded batches until no eligible rows remain.
 * - Records last-run time and emits low-volume operational logs.
 *
 * A failure aborts the pass without corrupting the setting; the next scheduled
 * run continues naturally.
 *
 * @param {import('pg').Pool} pool
 * @param {{
 *   batchSize?: number,
 *   minIntervalMs?: number,
 *   force?: boolean,
 *   maxBatches?: number,
 *   logger?: { log?: Function, info?: Function, warn?: Function, error?: Function }
 * }} [opts]
 */
export async function runAuditLogRetentionCleanup(pool, opts = {}) {
  const batchSize = Math.max(Number(opts.batchSize) || AUDIT_LOG_RETENTION_DEFAULT_BATCH_SIZE, 1);
  const minIntervalMs = opts.minIntervalMs == null ? DAY_MS : Math.max(Number(opts.minIntervalMs), 0);
  const force = Boolean(opts.force);
  const maxBatches = Number.isFinite(opts.maxBatches) ? Number(opts.maxBatches) : 10000;
  const logger = opts.logger || console;
  const logInfo = (msg) => (logger.info ? logger.info(msg) : logger.log?.(msg));

  const lockClient = await pool.connect();
  let locked = false;
  try {
    const lk = await lockClient.query('SELECT pg_try_advisory_lock($1) AS ok', [AUDIT_LOG_RETENTION_LOCK_KEY]);
    locked = Boolean(lk.rows[0]?.ok);
    if (!locked) {
      return { skipped: true, reason: 'locked' };
    }

    const cfg = await getAuditLogRetentionConfig(lockClient);

    if (cfg.keepForever) {
      // Keep forever: no deletion, and keep log noise low.
      return { skipped: true, reason: 'keep_forever', retentionDays: null };
    }

    if (!force && cfg.lastRunAt) {
      const elapsed = Date.now() - new Date(cfg.lastRunAt).getTime();
      if (Number.isFinite(elapsed) && elapsed < minIntervalMs) {
        return { skipped: true, reason: 'not_due', retentionDays: cfg.retentionDays, lastRunAt: cfg.lastRunAt };
      }
    }

    const days = cfg.retentionDays;
    let cutoff = null;
    try {
      const cutoffRes = await lockClient.query('SELECT (NOW() - make_interval(days => $1::int)) AS cutoff', [days]);
      cutoff = cutoffRes.rows[0]?.cutoff || null;
    } catch {
      cutoff = null;
    }
    const cutoffIso = cutoff instanceof Date ? cutoff.toISOString() : (cutoff || 'unknown');
    logInfo(`[audit-retention] cleanup started retention_days=${days} cutoff=${cutoffIso} batch_size=${batchSize}`);

    let totalDeleted = 0;
    let batches = 0;
    for (;;) {
      if (batches >= maxBatches) {
        logger.warn?.(`[audit-retention] batch cap reached (${maxBatches}); remaining rows will be handled on the next run`);
        break;
      }
      const deleted = await deleteAuditLogsOlderThanBatch(pool, { days, batchSize });
      totalDeleted += deleted;
      batches += 1;
      if (deleted < batchSize) break; // no eligible rows remain
    }

    await markCleanupRun(lockClient);

    if (totalDeleted > 0) {
      logInfo(`[audit-retention] cleanup completed retention_days=${days} deleted_rows=${totalDeleted} batches=${batches}`);
    } else {
      logInfo(`[audit-retention] cleanup completed retention_days=${days} deleted_rows=0`);
    }

    return { skipped: false, retentionDays: days, cutoff: cutoffIso, deleted: totalDeleted, batches };
  } catch (err) {
    logger.error?.(`[audit-retention] cleanup error: ${err?.message || err}`);
    return { skipped: false, error: err?.message || String(err) };
  } finally {
    if (locked) {
      await lockClient.query('SELECT pg_advisory_unlock($1)', [AUDIT_LOG_RETENTION_LOCK_KEY]).catch(() => {});
    }
    lockClient.release();
  }
}
