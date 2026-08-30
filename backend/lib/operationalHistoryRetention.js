/**
 * Operational history retention for unbounded-growth tables.
 *
 * Env (defaults):
 *   INTEGRATION_RUN_RETENTION_DAYS        = 90  — finished integration_runs
 *   INTEGRATION_QUEUE_JOB_RETENTION_DAYS  = same as run retention (or 90) — terminal queue jobs
 *   IOC_IP_GEO_CACHE_TTL_DAYS             = 30  — ioc_ip_geo_cache by updated_at
 *
 * Intentionally NOT purged:
 *   - ioc_enrichments: unique current-state rows (provider, ioc_value, ioc_type);
 *     deleting would drop live enrichment cache, not historical logs.
 *   - enrichment_usage_daily: small per-day aggregates; retain unless volume
 *     becomes a problem (revisit then).
 *
 * Cleanup uses bounded DELETE batches (auditLogRetention pattern) and an
 * advisory lock so only one instance runs at a time. Existing indexes on
 * integration_runs(created_at) and integration_queue_jobs(status) are reused;
 * ioc_ip_geo_cache.updated_at uses idx from migration 003 when present.
 */

function readPositiveDays(name, fallback) {
  const n = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(n) || n < 1) return fallback;
  return Math.floor(n);
}

export const INTEGRATION_RUN_RETENTION_DEFAULT_DAYS = 90;
export const INTEGRATION_QUEUE_JOB_RETENTION_DEFAULT_DAYS = 90;
export const IOC_IP_GEO_CACHE_TTL_DEFAULT_DAYS = 30;

export const OPERATIONAL_HISTORY_RETENTION_LOCK_KEY = 72900163;
export const OPERATIONAL_HISTORY_RETENTION_DEFAULT_BATCH_SIZE = 5000;

const DAY_MS = 24 * 60 * 60 * 1000;

export function resolveOperationalRetentionDays() {
  const runDays = readPositiveDays(
    'INTEGRATION_RUN_RETENTION_DAYS',
    INTEGRATION_RUN_RETENTION_DEFAULT_DAYS
  );
  const queueEnv = process.env.INTEGRATION_QUEUE_JOB_RETENTION_DAYS;
  const queueDays = queueEnv != null && String(queueEnv).trim() !== ''
    ? readPositiveDays('INTEGRATION_QUEUE_JOB_RETENTION_DAYS', INTEGRATION_QUEUE_JOB_RETENTION_DEFAULT_DAYS)
    : runDays;
  const geoDays = readPositiveDays(
    'IOC_IP_GEO_CACHE_TTL_DAYS',
    IOC_IP_GEO_CACHE_TTL_DEFAULT_DAYS
  );
  return { runDays, queueDays, geoDays };
}

/**
 * Delete one batch of finished integration_runs older than the retention window.
 * Uses created_at (indexed) with status <> 'running' so in-flight rows survive.
 *
 * @returns {Promise<number>} rows deleted
 */
export async function deleteFinishedIntegrationRunsBatch(db, { days, batchSize }) {
  const res = await db.query(
    `WITH doomed AS (
       SELECT id
         FROM integration_runs
        WHERE status <> 'running'
          AND created_at < NOW() - make_interval(days => $1::int)
        ORDER BY created_at ASC
        LIMIT $2
        FOR UPDATE SKIP LOCKED
     )
     DELETE FROM integration_runs r
      USING doomed d
      WHERE r.id = d.id`,
    [days, batchSize]
  );
  return Number(res.rowCount || 0);
}

/**
 * Delete one batch of terminal integration_queue_jobs older than the window.
 *
 * @returns {Promise<number>} rows deleted
 */
export async function deleteTerminalQueueJobsBatch(db, { days, batchSize }) {
  const res = await db.query(
    `WITH doomed AS (
       SELECT job_id
         FROM integration_queue_jobs
        WHERE status IN ('success', 'failed', 'skipped')
          AND COALESCE(finished_at, queued_at) < NOW() - make_interval(days => $1::int)
        ORDER BY COALESCE(finished_at, queued_at) ASC
        LIMIT $2
        FOR UPDATE SKIP LOCKED
     )
     DELETE FROM integration_queue_jobs j
      USING doomed d
      WHERE j.job_id = d.job_id`,
    [days, batchSize]
  );
  return Number(res.rowCount || 0);
}

/**
 * Delete one batch of stale ioc_ip_geo_cache rows (updated_at older than TTL).
 * Table has updated_at (no created_at); see 001_core.sql.
 *
 * @returns {Promise<number>} rows deleted
 */
export async function deleteStaleIpGeoCacheBatch(db, { days, batchSize }) {
  const res = await db.query(
    `WITH doomed AS (
       SELECT ip
         FROM ioc_ip_geo_cache
        WHERE updated_at < NOW() - make_interval(days => $1::int)
        ORDER BY updated_at ASC
        LIMIT $2
        FOR UPDATE SKIP LOCKED
     )
     DELETE FROM ioc_ip_geo_cache c
      USING doomed d
      WHERE c.ip = d.ip`,
    [days, batchSize]
  );
  return Number(res.rowCount || 0);
}

async function drainBatches(deleteBatch, { days, batchSize, maxBatches }) {
  let totalDeleted = 0;
  let batches = 0;
  for (;;) {
    if (batches >= maxBatches) break;
    const deleted = await deleteBatch({ days, batchSize });
    totalDeleted += deleted;
    batches += 1;
    if (deleted < batchSize) break;
  }
  return { deleted: totalDeleted, batches };
}

/**
 * One operational-history retention pass (throttled by minIntervalMs via caller
 * and an in-module last-run gate when opts.lastRunAtMs is provided / returned).
 *
 * @param {import('pg').Pool} pool
 */
export async function runOperationalHistoryRetentionCleanup(pool, opts = {}) {
  const batchSize = Math.max(
    Number(opts.batchSize) || OPERATIONAL_HISTORY_RETENTION_DEFAULT_BATCH_SIZE,
    1
  );
  const minIntervalMs = opts.minIntervalMs == null ? DAY_MS : Math.max(Number(opts.minIntervalMs), 0);
  const force = Boolean(opts.force);
  const maxBatches = Number.isFinite(opts.maxBatches) ? Number(opts.maxBatches) : 10000;
  const logger = opts.logger || console;
  const logInfo = (msg) => (logger.info ? logger.info(msg) : logger.log?.(msg));

  // Module-level last-run tracking when caller does not persist a DB watermark.
  if (!force && opts.lastRunAtMs != null && minIntervalMs > 0) {
    const elapsed = Date.now() - Number(opts.lastRunAtMs);
    if (Number.isFinite(elapsed) && elapsed < minIntervalMs) {
      return { skipped: true, reason: 'not_due', lastRunAtMs: opts.lastRunAtMs };
    }
  }

  const lockClient = await pool.connect();
  let locked = false;
  try {
    const lk = await lockClient.query(
      'SELECT pg_try_advisory_lock($1) AS ok',
      [OPERATIONAL_HISTORY_RETENTION_LOCK_KEY]
    );
    locked = Boolean(lk.rows[0]?.ok);
    if (!locked) {
      return { skipped: true, reason: 'locked' };
    }

    const { runDays, queueDays, geoDays } = resolveOperationalRetentionDays();
    logInfo(
      `[ops-retention] cleanup started run_days=${runDays} queue_days=${queueDays} geo_days=${geoDays} batch_size=${batchSize}`
    );

    // ioc_enrichments: unique current-state (provider, ioc_value, ioc_type) — do not purge.
    // enrichment_usage_daily: small aggregates — retain.

    const runs = await drainBatches(
      ({ days, batchSize: bs }) => deleteFinishedIntegrationRunsBatch(pool, { days, batchSize: bs }),
      { days: runDays, batchSize, maxBatches }
    );
    const jobs = await drainBatches(
      ({ days, batchSize: bs }) => deleteTerminalQueueJobsBatch(pool, { days, batchSize: bs }),
      { days: queueDays, batchSize, maxBatches }
    );
    const geo = await drainBatches(
      ({ days, batchSize: bs }) => deleteStaleIpGeoCacheBatch(pool, { days, batchSize: bs }),
      { days: geoDays, batchSize, maxBatches }
    );

    const deleted =
      runs.deleted + jobs.deleted + geo.deleted;
    const batches = runs.batches + jobs.batches + geo.batches;
    logInfo(
      `[ops-retention] cleanup completed deleted_runs=${runs.deleted} deleted_jobs=${jobs.deleted} deleted_geo=${geo.deleted} batches=${batches}`
    );

    return {
      skipped: false,
      runDays,
      queueDays,
      geoDays,
      deleted,
      runs,
      jobs,
      geo,
      lastRunAtMs: Date.now()
    };
  } catch (err) {
    logger.error?.(`[ops-retention] cleanup error: ${err?.message || err}`);
    return { skipped: false, error: err?.message || String(err) };
  } finally {
    if (locked) {
      await lockClient.query(
        'SELECT pg_advisory_unlock($1)',
        [OPERATIONAL_HISTORY_RETENTION_LOCK_KEY]
      ).catch(() => {});
    }
    lockClient.release();
  }
}
