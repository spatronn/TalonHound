import './lib/ensure-db-password.js';
import './lib/ensure-redis-password.js';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import pg from 'pg';
import IORedis from 'ioredis';
import { Worker } from 'bullmq';
import { getRedisUrl } from './lib/redis-url.js';
import { createAuditLogService } from './lib/auditLogService.js';
import { AUDIT_ACTION, AUDIT_SEVERITY } from './lib/auditConstants.js';
import { parseSearchQuery, buildWhereClause, getPreviewLimit } from './lib/iocSearchDsl/index.js';
import { getExportConfig, EXPORT_QUEUE_NAME, resolveExportFilePath } from './lib/iocSearchExport/exportConfig.js';
import { streamExportToSink } from './lib/iocSearchExport/exportStream.js';
import {
  getExportById,
  claimForProcessing,
  updateProgress,
  markReady,
  markFailed,
  markCancelled,
  isCancelRequested,
  findExpiredReady,
  markExpired,
  findStaleMetadata,
  deleteMetadataRow
} from './lib/iocSearchExport/exportStore.js';

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

const audit = createAuditLogService(pool);
const cfg = getExportConfig();
const previewLimit = getPreviewLimit();
const redis = new IORedis(getRedisUrl(), { maxRetriesPerRequest: null });
const workerConcurrency = Math.min(Math.max(Number(process.env.IOC_EXPORT_WORKER_CONCURRENCY || 2), 1), 10);

fs.mkdirSync(cfg.storageDir, { recursive: true });

function endStream(stream) {
  return new Promise((resolve, reject) => {
    stream.end((err) => (err ? reject(err) : resolve()));
  });
}

async function auditExport(action, row, { severity = AUDIT_SEVERITY.INFO, status = 'success', extra = {} } = {}) {
  const event = {
    action,
    entityType: 'ioc_search_export',
    entityId: row.id,
    entityDisplay: String(row.normalized_query || '').slice(0, 200),
    severity,
    actorEmail: row.requested_by_email,
    actorUsername: row.requested_by_email,
    metadata: {
      export_id: row.id,
      normalized_query: row.normalized_query,
      record_count: row.record_count == null ? null : Number(row.record_count),
      ...extra
    }
  };
  if (status === 'failed') return audit.auditFailure(event);
  return audit.auditSuccess(event);
}

// Coarse, monotonic progress. Preview scope has a real target; "all" scope has an
// unknown total, so we ramp asymptotically toward — but never reach — 100 until done.
function computeProgress(scope, recordCount) {
  if (scope === 'preview') {
    return Math.min(99, Math.floor((recordCount / Math.max(previewLimit, 1)) * 100));
  }
  const denom = recordCount + cfg.batchSize * 2;
  return Math.min(99, Math.floor((recordCount / Math.max(denom, 1)) * 100));
}

async function cleanupFile(filePath) {
  if (!filePath) return;
  try {
    await fs.promises.unlink(filePath);
  } catch (err) {
    if (err && err.code !== 'ENOENT') console.warn('[ioc-search-export] unlink failed:', err.message);
  }
}

async function runExport(exportId) {
  const initial = await getExportById(pool, exportId);
  if (!initial) {
    console.warn('[ioc-search-export] export row not found:', exportId);
    return;
  }
  if (!['queued', 'failed'].includes(initial.status)) {
    // Already claimed, cancelled or done — nothing to do.
    return;
  }

  const snapshotCutoff = new Date().toISOString();
  const row = await claimForProcessing(pool, exportId, snapshotCutoff);
  if (!row) return; // Lost the claim race.

  await auditExport(AUDIT_ACTION.IOC_SEARCH_EXPORT_STARTED, row, { extra: { snapshot_cutoff: snapshotCutoff } });

  // Re-parse the stored normalized query from scratch. The worker never trusts a
  // client-supplied AST/SQL — it re-derives the predicate under the same validators.
  let ast;
  try {
    ({ ast } = parseSearchQuery(row.normalized_query));
  } catch (err) {
    await markFailed(pool, exportId, `Query re-validation failed: ${err.message}`);
    await auditExport(AUDIT_ACTION.IOC_SEARCH_EXPORT_FAILED, row, { status: 'failed', severity: AUDIT_SEVERITY.WARNING, extra: { reason: err.message } });
    return;
  }

  const { sql: whereSql, params: dslParams } = buildWhereClause(ast);
  // selected_columns is NOT NULL and sanitized at creation time; always non-empty.
  const cols = Array.isArray(row.selected_columns) && row.selected_columns.length
    ? row.selected_columns
    : undefined;

  const isGz = row.format === 'csv_gz';
  const fileName = `${row.id}.csv${isGz ? '.gz' : ''}`;
  const filePath = resolveExportFilePath(cfg.storageDir, fileName);

  const fileStream = fs.createWriteStream(filePath);
  const sink = isGz ? zlib.createGzip() : fileStream;
  if (isGz) sink.pipe(fileStream);
  const finished = new Promise((resolve, reject) => {
    fileStream.on('finish', resolve);
    fileStream.on('error', reject);
    if (isGz) sink.on('error', reject);
  });

  try {
    const result = await streamExportToSink({
      db: pool,
      whereSql,
      dslParams,
      cutoff: snapshotCutoff,
      columns: cols,
      scope: row.scope,
      batchSize: cfg.batchSize,
      hardLimit: cfg.hardLimit,
      previewLimit,
      sink,
      progressEvery: cfg.progressUpdateEvery,
      isCancelled: () => isCancelRequested(pool, exportId),
      onProgress: (recordCount) => updateProgress(pool, exportId, { progress: computeProgress(row.scope, recordCount), recordCount })
    });

    if (result.status === 'cancelled') {
      await endStream(sink);
      await finished.catch(() => {});
      await cleanupFile(filePath);
      await markCancelled(pool, exportId);
      await auditExport(AUDIT_ACTION.IOC_SEARCH_EXPORT_CANCELLED, { ...row, record_count: result.recordCount }, { extra: { cancelled_mid_stream: true } });
      return;
    }

    if (result.status === 'hard_limit') {
      // (hardLimit+1)th row was observed: delete the partial file and fail.
      await endStream(sink);
      await finished.catch(() => {});
      await cleanupFile(filePath);
      const reason = `Result set exceeds the hard limit of ${cfg.hardLimit.toLocaleString('en-US')} records. Refine the query.`;
      await markFailed(pool, exportId, reason);
      await auditExport(AUDIT_ACTION.IOC_SEARCH_EXPORT_FAILED, { ...row, record_count: result.recordCount }, { status: 'failed', severity: AUDIT_SEVERITY.WARNING, extra: { reason } });
      return;
    }

    await endStream(sink);
    await finished;

    const recordCount = result.recordCount;
    const stat = await fs.promises.stat(filePath);
    const expiresAt = new Date(Date.now() + cfg.retentionHours * 3600 * 1000).toISOString();
    await markReady(pool, exportId, {
      recordCount,
      fileSize: stat.size,
      storagePath: fileName,
      expiresAt
    });
    await auditExport(AUDIT_ACTION.IOC_SEARCH_EXPORT_COMPLETED, { ...row, record_count: recordCount }, {
      extra: { record_count: recordCount, file_size: stat.size, expires_at: expiresAt }
    });
    console.log(`[ioc-search-export] export ${exportId} ready records=${recordCount} bytes=${stat.size}`);
  } catch (err) {
    try { await endStream(sink); } catch { /* ignore */ }
    await cleanupFile(filePath);
    await markFailed(pool, exportId, err.message);
    await auditExport(AUDIT_ACTION.IOC_SEARCH_EXPORT_FAILED, { ...row }, {
      status: 'failed', severity: AUDIT_SEVERITY.WARNING, extra: { reason: err.message }
    });
    console.error(`[ioc-search-export] export ${exportId} failed:`, err.message);
  }
}

async function exportTableExists() {
  try {
    const { rows } = await pool.query("SELECT to_regclass('public.ioc_search_exports') AS reg");
    return Boolean(rows[0]?.reg);
  } catch {
    return false;
  }
}

// Deployment safety: migrations run as a separate step (npm run migrate), so the worker
// container can start before migration 124 creates ioc_search_exports. Wait for the
// table with bounded backoff — jobs enqueued during the gap stay queued and are picked
// up once the table appears — then start consuming regardless (no infinite wait). If the
// table is still absent, per-job processing fails gracefully with a clear message.
async function waitForExportTable() {
  const maxAttempts = Math.max(Number(process.env.IOC_EXPORT_TABLE_WAIT_ATTEMPTS || 60), 1);
  const delayMs = Math.min(Math.max(Number(process.env.IOC_EXPORT_TABLE_WAIT_INTERVAL_MS || 5000), 1000), 30000);
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    if (await exportTableExists()) return true;
    if (attempt === 1 || attempt % 6 === 0) {
      console.warn(`[ioc-search-export] ioc_search_exports not found yet (attempt ${attempt}/${maxAttempts}); waiting for migration 124…`);
    }
    await new Promise((r) => setTimeout(r, delayMs));
  }
  console.warn('[ioc-search-export] proceeding without confirmed ioc_search_exports table; jobs will fail until migration 124 is applied.');
  return false;
}

let worker = null;
let cleanupTimer = null;

// Retention sweep:
// 1) Delete ready artifacts past expires_at and flip status to 'expired'.
// 2) Hard-delete terminal metadata rows older than metadataRetentionDays (default 7).
const CLEANUP_INTERVAL_MS = Math.max(Number(process.env.IOC_EXPORT_CLEANUP_INTERVAL_MS || 300000), 60000);
let cleanupRunning = false;
async function cleanupExpired() {
  if (cleanupRunning) return;
  cleanupRunning = true;
  try {
    if (!(await exportTableExists())) return; // quietly skip until migration applied

    const expired = await findExpiredReady(pool, 100);
    for (const row of expired) {
      if (row.storage_path) {
        const p = path.resolve(cfg.storageDir, path.basename(String(row.storage_path)));
        await cleanupFile(p);
      }
      const marked = await markExpired(pool, row.id);
      if (marked) {
        await auditExport(AUDIT_ACTION.IOC_SEARCH_EXPORT_EXPIRED, marked, {
          extra: { expired_at: new Date().toISOString() }
        });
      }
    }
    if (expired.length) console.log(`[ioc-search-export] expired ${expired.length} export(s)`);

    // Metadata cleanup is independent of file cleanup and must tolerate missing files.
    const stale = await findStaleMetadata(pool, {
      olderThanDays: cfg.metadataRetentionDays,
      limit: 200
    });
    let deleted = 0;
    for (const row of stale) {
      // Best-effort unlink if a path somehow remains on a terminal row.
      if (row.storage_path) {
        const p = path.resolve(cfg.storageDir, path.basename(String(row.storage_path)));
        await cleanupFile(p);
      }
      const gone = await deleteMetadataRow(pool, row.id);
      if (gone) deleted += 1;
    }
    if (deleted) console.log(`[ioc-search-export] purged ${deleted} stale metadata row(s)`);
  } catch (err) {
    console.warn('[ioc-search-export] cleanup failed:', err.message);
  } finally {
    cleanupRunning = false;
  }
}

async function start() {
  await waitForExportTable();
  const { waitUntilSetupComplete } = await import('./lib/systemTime.js');
  const tz = await waitUntilSetupComplete(pool, { logPrefix: '[ioc-search-export]' });
  process.env.TZ = tz;
  process.env.SYSTEM_TIMEZONE = tz;

  worker = new Worker(
    EXPORT_QUEUE_NAME,
    async (job) => {
      const exportId = job.data?.exportId;
      if (!exportId) return;
      // Guard against processing before the schema exists so failures are clear rather
      // than a cryptic "relation does not exist".
      if (!(await exportTableExists())) {
        throw new Error('ioc_search_exports table is not present yet (migration 124 not applied)');
      }
      await runExport(exportId);
    },
    { connection: redis, concurrency: workerConcurrency }
  );

  worker.on('failed', (job, err) => {
    console.error('[ioc-search-export] job failed', job?.id, err?.message || err);
  });

  cleanupTimer = setInterval(cleanupExpired, CLEANUP_INTERVAL_MS);
  cleanupExpired().catch(() => {});

  console.log(`[ioc-search-export] worker started queue=${EXPORT_QUEUE_NAME} concurrency=${workerConcurrency} storage=${cfg.storageDir} tz=${tz}`);
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
  console.error('[ioc-search-export] fatal startup error', err);
  process.exit(1);
});
