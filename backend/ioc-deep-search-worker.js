import './lib/ensure-db-password.js';
import './lib/ensure-redis-password.js';
import pg from 'pg';
import IORedis from 'ioredis';
import { Worker } from 'bullmq';
import { getRedisUrl } from './lib/redis-url.js';
import { createAuditLogService } from './lib/auditLogService.js';
import { createServiceLogger } from './lib/appLogger.js';
import { AUDIT_ACTION, AUDIT_SEVERITY } from './lib/auditConstants.js';
import {
  parseSearchQuery,
  buildWhereClause,
  buildDeepSearchSpoolInsertSql
} from './lib/iocSearchDsl/index.js';
import { isFileArtifactsReadEnabled } from './lib/fileArtifacts/flags.js';
import { getDeepSearchConfig, DEEP_SEARCH_QUEUE_NAME } from './lib/iocDeepSearch/deepSearchConfig.js';
import { queryFingerprint } from './lib/iocDeepSearch/deepSearchStatus.js';
import {
  getDeepSearchById,
  claimForProcessing,
  markCompleted,
  markFailed,
  markCancelled,
  isCancelRequested,
  findExpiredCompleted,
  markExpired,
  deleteResultsBatch,
  findStaleMetadata,
  deleteMetadataRow
} from './lib/iocDeepSearch/deepSearchStore.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

const audit = createAuditLogService(pool);
const log = createServiceLogger('ioc-deep-search');
const cfg = getDeepSearchConfig();
const redis = new IORedis(getRedisUrl(), { maxRetriesPerRequest: null });
const workerConcurrency = Math.min(Math.max(Number(process.env.IOC_DEEP_SEARCH_WORKER_CONCURRENCY || 2), 1), 10);

// Postgres statement-cancel SQLSTATE (statement_timeout / pg_cancel_backend).
const QUERY_CANCELED = '57014';

async function auditDeep(action, row, { severity = AUDIT_SEVERITY.INFO, status = 'success', extra = {} } = {}) {
  const event = {
    action,
    entityType: 'ioc_deep_search',
    entityId: row.id,
    entityDisplay: String(row.normalized_query || '').slice(0, 200),
    severity,
    actorEmail: row.requested_by_email,
    actorUsername: row.requested_by_email,
    metadata: {
      deep_search_id: row.id,
      normalized_query: row.normalized_query,
      match_count: row.match_count == null ? null : Number(row.match_count),
      ...extra
    }
  };
  if (status === 'failed') return audit.auditFailure(event);
  return audit.auditSuccess(event);
}

async function runDeepSearch(deepSearchId) {
  const initial = await getDeepSearchById(pool, deepSearchId);
  if (!initial) {
    log.warn('deep search row not found', { event: 'deep_search.missing', deep_search_id: deepSearchId });
    return;
  }
  if (initial.status !== 'queued') return; // Already claimed, cancelled or done.

  const snapshotCutoff = new Date().toISOString();
  const row = await claimForProcessing(pool, deepSearchId, snapshotCutoff);
  if (!row) return; // Lost the claim race.

  const fp = queryFingerprint(row.normalized_query);
  log.info('deep search started', {
    event: 'deep_search.started',
    deep_search_id: row.id,
    origin: row.origin,
    reason: row.classification_reason || null,
    query_fingerprint: fp
  });
  await auditDeep(AUDIT_ACTION.IOC_DEEP_SEARCH_STARTED, row, { extra: { snapshot_cutoff: snapshotCutoff } });

  if (await isCancelRequested(pool, deepSearchId)) {
    await markCancelled(pool, deepSearchId);
    await auditDeep(AUDIT_ACTION.IOC_DEEP_SEARCH_CANCELLED, row, { extra: { cancelled_before_start: true } });
    return;
  }

  // Re-parse the stored normalized query from scratch — the worker never trusts a
  // client-supplied AST/SQL and re-derives the predicate under the same validators.
  let ast;
  try {
    ({ ast } = parseSearchQuery(row.normalized_query));
  } catch (err) {
    await markFailed(pool, deepSearchId, `Query re-validation failed: ${err.message}`);
    await auditDeep(AUDIT_ACTION.IOC_DEEP_SEARCH_FAILED, row, { status: 'failed', severity: AUDIT_SEVERITY.WARNING, extra: { reason: err.message } });
    log.error('deep search failed (revalidation)', { event: 'deep_search.failed', deep_search_id: row.id, query_fingerprint: fp });
    return;
  }

  const faRead = isFileArtifactsReadEnabled();
  const built = buildWhereClause(ast, { fileArtifactsReadEnabled: faRead });
  const dslParams = built.params;
  const cutoffIdx = dslParams.length + 1;
  const deepSearchIdIdx = dslParams.length + 2;
  // Snapshot-bound predicate: exclude rows imported after the claim instant so the
  // materialized set is deterministic. No row cap — the whole matching set is materialized;
  // the only bound is the background statement_timeout set below.
  const whereSql = `(${built.sql}) AND i.created_at <= $${cutoffIdx}::timestamptz`;
  const insertSql = buildDeepSearchSpoolInsertSql({ fileArtifactsReadEnabled: faRead, whereSql, deepSearchIdIdx });
  const params = [...dslParams, snapshotCutoff, deepSearchId];

  const startedAt = Date.now();
  const client = await pool.connect();

  // Running-query cancellation: capture this backend's PID, then a lightweight watcher polls
  // the cancel flag and issues pg_cancel_backend(pid) from a SEPARATE connection so the
  // in-flight INSERT ... SELECT is actually stopped at the database (SQLSTATE 57014), not
  // merely marked cancelled after it finishes. Same-role cancellation, no process signals.
  let backendPid = null;
  let cancelSignalled = false;
  let watcher = null;
  let watching = false;
  async function stopWatcher() {
    if (watcher) { clearInterval(watcher); watcher = null; }
  }
  function startWatcher() {
    watcher = setInterval(async () => {
      if (watching || cancelSignalled || backendPid == null) return;
      watching = true;
      try {
        if (await isCancelRequested(pool, deepSearchId)) {
          cancelSignalled = true;
          await pool.query('SELECT pg_cancel_backend($1)', [backendPid]);
          await stopWatcher();
        }
      } catch { /* best-effort; a missed tick retries next interval */ } finally {
        watching = false;
      }
    }, cfg.cancelPollMs);
  }

  try {
    const pidRes = await client.query('SELECT pg_backend_pid() AS pid');
    backendPid = pidRes.rows[0]?.pid ?? null;

    await client.query('BEGIN');
    await client.query(`SET LOCAL statement_timeout = ${Math.trunc(cfg.queryTimeoutMs)}`);
    // Parallel hash/gather needs extra DSM segments; the db container ships 64MiB /dev/shm
    // which OOMs on large FA aggregates. Serialize this transaction (mirrors the interactive
    // search path) rather than raising container shm.
    await client.query('SET LOCAL max_parallel_workers_per_gather = 0');
    // Idempotent materialization: clear any spool rows from a prior aborted attempt so a
    // re-delivered job can never accumulate duplicates.
    await client.query('DELETE FROM ioc_deep_search_results WHERE deep_search_id = $1', [deepSearchId]);

    startWatcher();
    const ins = await client.query(insertSql, params);
    await stopWatcher();
    const matchCount = ins.rowCount || 0;

    // Cancel that arrived while the statement ran (signalled, or flag set just as it finished):
    // discard the uncommitted insert and settle as cancelled.
    if (cancelSignalled || (await isCancelRequested(pool, deepSearchId))) {
      await client.query('ROLLBACK');
      await markCancelled(pool, deepSearchId);
      await auditDeep(AUDIT_ACTION.IOC_DEEP_SEARCH_CANCELLED, { ...row }, { extra: { cancelled_mid_run: true } });
      log.info('deep search cancelled', { event: 'deep_search.cancelled', deep_search_id: row.id, query_fingerprint: fp });
      return;
    }

    await client.query('COMMIT');

    const durationMs = Date.now() - startedAt;
    const expiresAt = new Date(Date.now() + cfg.retentionHours * 3600 * 1000).toISOString();
    // Conditional completion: loses any race against a concurrent cancel (returns false when
    // the row is no longer 'running' or a cancel was requested after COMMIT).
    const completed = await markCompleted(pool, deepSearchId, { matchCount, durationMs, expiresAt });
    if (!completed) {
      // A cancel won the race after COMMIT — the spool rows are already committed, so remove
      // them in bounded batches and settle as cancelled. Never present them as completed.
      for (;;) {
        const n = await deleteResultsBatch(pool, deepSearchId, cfg.cleanupBatchSize);
        if (n < cfg.cleanupBatchSize) break;
      }
      await markCancelled(pool, deepSearchId);
      await auditDeep(AUDIT_ACTION.IOC_DEEP_SEARCH_CANCELLED, { ...row }, { extra: { cancelled_post_commit: true } });
      log.info('deep search cancelled', { event: 'deep_search.cancelled', deep_search_id: row.id, query_fingerprint: fp });
      return;
    }

    await auditDeep(AUDIT_ACTION.IOC_DEEP_SEARCH_COMPLETED, { ...row, match_count: matchCount }, {
      extra: { match_count: matchCount, duration_ms: durationMs, expires_at: expiresAt }
    });
    log.info('deep search completed', {
      event: 'deep_search.completed',
      deep_search_id: row.id,
      match_count: matchCount,
      duration_ms: durationMs,
      query_fingerprint: fp
    });
  } catch (err) {
    await stopWatcher();
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    const canceled = err && err.code === QUERY_CANCELED;
    // A 57014 can mean either our own cancel signal OR the statement_timeout expiring. Only the
    // former settles as cancelled; the latter fails honestly. Unrelated DB errors always fail.
    if (canceled && (cancelSignalled || (await isCancelRequested(pool, deepSearchId).catch(() => false)))) {
      await markCancelled(pool, deepSearchId);
      await auditDeep(AUDIT_ACTION.IOC_DEEP_SEARCH_CANCELLED, { ...row }, { extra: { cancelled_via_signal: true } });
      log.info('deep search cancelled', { event: 'deep_search.cancelled', deep_search_id: row.id, query_fingerprint: fp });
      return;
    }
    const reason = canceled
      ? `Deep search exceeded the background time limit of ${Math.round(cfg.queryTimeoutMs / 1000)}s. Refine the query.`
      : err.message;
    await markFailed(pool, deepSearchId, reason);
    await auditDeep(AUDIT_ACTION.IOC_DEEP_SEARCH_FAILED, { ...row }, {
      status: 'failed', severity: AUDIT_SEVERITY.WARNING, extra: { reason, timed_out: Boolean(canceled) }
    });
    log.error('deep search failed', {
      event: 'deep_search.failed',
      deep_search_id: row.id,
      timed_out: Boolean(canceled),
      query_fingerprint: fp
    });
  } finally {
    await stopWatcher();
    client.release();
  }
}

async function tablesExist() {
  try {
    const { rows } = await pool.query(
      "SELECT to_regclass('public.ioc_deep_searches') AS a, to_regclass('public.ioc_deep_search_results') AS b"
    );
    return Boolean(rows[0]?.a) && Boolean(rows[0]?.b);
  } catch {
    return false;
  }
}

async function waitForTables() {
  const maxAttempts = Math.max(Number(process.env.IOC_DEEP_SEARCH_TABLE_WAIT_ATTEMPTS || 60), 1);
  const delayMs = Math.min(Math.max(Number(process.env.IOC_DEEP_SEARCH_TABLE_WAIT_INTERVAL_MS || 5000), 1000), 30000);
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    if (await tablesExist()) return true;
    if (attempt === 1 || attempt % 6 === 0) {
      log.warn('deep search tables not found yet; waiting for migration 144', { event: 'deep_search.await_migration', attempt, max_attempts: maxAttempts });
    }
    await new Promise((r) => setTimeout(r, delayMs));
  }
  log.warn('proceeding without confirmed deep search tables; jobs will fail until migration 144 is applied', { event: 'deep_search.await_migration_timeout' });
  return false;
}

let worker = null;
let cleanupTimer = null;
const CLEANUP_INTERVAL_MS = Math.max(Number(process.env.IOC_DEEP_SEARCH_CLEANUP_INTERVAL_MS || 300000), 60000);
let cleanupRunning = false;

// Retention sweep:
// 1) Expire completed result sets past expires_at: batched-delete spool rows, flip to 'expired'.
// 2) Hard-delete terminal metadata rows older than metadataRetentionDays.
async function cleanupExpired() {
  if (cleanupRunning) return;
  cleanupRunning = true;
  try {
    if (!(await tablesExist())) return;

    const expired = await findExpiredCompleted(pool, 100);
    let expiredCount = 0;
    let deletedRows = 0;
    for (const row of expired) {
      // Batched delete avoids a long lock on a multi-million-row result set.
      for (;;) {
        const n = await deleteResultsBatch(pool, row.id, cfg.cleanupBatchSize);
        deletedRows += n;
        if (n < cfg.cleanupBatchSize) break;
      }
      const marked = await markExpired(pool, row.id);
      if (marked) {
        expiredCount += 1;
        await auditDeep(AUDIT_ACTION.IOC_DEEP_SEARCH_EXPIRED, marked, { extra: { expired_at: new Date().toISOString() } });
      }
    }

    const stale = await findStaleMetadata(pool, { olderThanDays: cfg.metadataRetentionDays, limit: 200 });
    let purged = 0;
    for (const row of stale) {
      // Defensive: ensure no orphan spool rows remain before deleting the parent metadata.
      for (;;) {
        const n = await deleteResultsBatch(pool, row.id, cfg.cleanupBatchSize);
        deletedRows += n;
        if (n < cfg.cleanupBatchSize) break;
      }
      const gone = await deleteMetadataRow(pool, row.id);
      if (gone) purged += 1;
    }

    if (expiredCount || purged || deletedRows) {
      log.info('deep search cleanup', {
        event: 'deep_search.cleanup',
        expired: expiredCount,
        purged_metadata: purged,
        deleted_result_rows: deletedRows
      });
    }
  } catch (err) {
    log.warn('deep search cleanup failed', { event: 'deep_search.cleanup_failed', error: err.message });
  } finally {
    cleanupRunning = false;
  }
}

async function start() {
  await waitForTables();
  const { waitUntilSetupComplete } = await import('./lib/systemTime.js');
  const tz = await waitUntilSetupComplete(pool, { logPrefix: '[ioc-deep-search]' });
  process.env.TZ = tz;
  process.env.SYSTEM_TIMEZONE = tz;

  worker = new Worker(
    DEEP_SEARCH_QUEUE_NAME,
    async (job) => {
      const deepSearchId = job.data?.deepSearchId;
      if (!deepSearchId) return;
      if (!(await tablesExist())) {
        throw new Error('ioc_deep_searches tables are not present yet (migration 144 not applied)');
      }
      await runDeepSearch(deepSearchId);
    },
    { connection: redis, concurrency: workerConcurrency }
  );

  worker.on('failed', (job, err) => {
    log.error('deep search job failed', { event: 'deep_search.job_failed', job_id: job?.id, error: err?.message || String(err) });
  });

  cleanupTimer = setInterval(cleanupExpired, CLEANUP_INTERVAL_MS);
  cleanupExpired().catch(() => {});

  log.info('deep search worker started', { event: 'deep_search.worker_started', queue: DEEP_SEARCH_QUEUE_NAME, concurrency: workerConcurrency, tz });
}

async function shutdown() {
  if (cleanupTimer) clearInterval(cleanupTimer);
  try { if (worker) await worker.close(); } catch { /* ignore */ }
  try { await redis.quit(); } catch { /* ignore */ }
  try { await pool.end(); } catch { /* ignore */ }
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

start().catch((err) => {
  log.error('deep search worker fatal startup error', { event: 'deep_search.worker_fatal', error: err?.message || String(err) });
  process.exit(1);
});
