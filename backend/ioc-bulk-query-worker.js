import './lib/ensure-db-password.js';
import './lib/ensure-redis-password.js';
import pg from 'pg';
import IORedis from 'ioredis';
import { Worker } from 'bullmq';
import { getRedisUrl } from './lib/redis-url.js';
import { createAuditLogService } from './lib/auditLogService.js';
import { createServiceLogger } from './lib/appLogger.js';
import { getBulkQueryConfig, BULK_QUERY_QUEUE_NAME } from './lib/iocBulkQueryJob/config.js';
import {
  getBulkQueryJobById,
  claimForProcessing,
  markProgress,
  markCompleted,
  markFailed,
  isCancelRequested,
  replaceTargets,
  listTargetPage,
  deleteTargets,
  findStaleMetadata,
  deleteMetadataRow
} from './lib/iocBulkQueryJob/store.js';
import {
  compileQueryWideTarget,
  streamMatchingIocIds,
  extraAuditMetadata,
  mergeOutcomes,
  errorSampleFromResults
} from './lib/iocBulkQueryTriage.js';
import {
  bulkAddTag,
  bulkAddClassification,
  bulkSuppress,
  bulkExpire
} from './lib/iocBulkTriage.js';
import { AUDIT_ACTION, AUDIT_ENTITY, AUDIT_SEVERITY } from './lib/auditConstants.js';

const { Pool } = pg;
const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

const audit = createAuditLogService(pool);
const log = createServiceLogger('ioc-bulk-query');
const cfg = getBulkQueryConfig();
const redis = new IORedis(getRedisUrl(), { maxRetriesPerRequest: null });
const workerConcurrency = Math.min(Math.max(Number(process.env.IOC_BULK_QUERY_WORKER_CONCURRENCY || 2), 1), 10);

function actorFromRow(row) {
  return {
    id: row.requested_by_id,
    email: row.requested_by_email,
    username: row.requested_by_email,
    publicId: row.requested_by_public_id,
    role: row.requested_by_role
  };
}

async function applyChunk(action, ids, payload, user, extraMetadata) {
  if (action === 'tag') {
    return bulkAddTag(pool, { iocIds: ids, tagId: payload.tag_id, user, audit, extraMetadata });
  }
  if (action === 'classification') {
    return bulkAddClassification(pool, {
      iocIds: ids,
      slug: payload.classification_slug,
      user,
      audit,
      extraMetadata
    });
  }
  if (action === 'suppress') {
    return bulkSuppress(pool, {
      iocIds: ids,
      reason: payload.reason,
      expiresAt: payload.expires_at,
      user,
      audit,
      extraMetadata
    });
  }
  return bulkExpire(pool, { iocIds: ids, reason: payload.reason, user, audit, extraMetadata });
}

async function processJob(jobId) {
  const claimed = await claimForProcessing(pool, jobId);
  if (!claimed) {
    const existing = await getBulkQueryJobById(pool, jobId);
    if (!existing) throw new Error('Bulk job not found');
    if (existing.cancel_requested) return;
    if (existing.status !== 'queued') return;
    throw new Error('Failed to claim bulk job');
  }

  const compiled = compileQueryWideTarget(claimed.normalized_query || claimed.original_query);
  if (!compiled.ok) {
    await markFailed(pool, jobId, compiled.message);
    return;
  }

  const payload = claimed.payload && typeof claimed.payload === 'object' ? claimed.payload : {};
  const extraMetadata = extraAuditMetadata(compiled, claimed.action);
  const user = actorFromRow(claimed);
  const ids = [];
  const streamed = await streamMatchingIocIds(pool, compiled, {
    chunkSize: cfg.chunkSize,
    hardLimit: cfg.hardLimit,
    onChunk: async (chunk) => {
      ids.push(...chunk);
    }
  });
  if (!streamed.ok) {
    await markFailed(pool, jobId, streamed.message);
    return;
  }

  await replaceTargets(pool, jobId, ids);
  await markProgress(pool, jobId, {
    matchCount: ids.length,
    succeeded: 0,
    skipped: 0,
    failed: 0,
    progress: ids.length ? 1 : 100
  });

  let totals = { requested: 0, succeeded: 0, skipped: 0, failed: 0, results: [] };
  let afterId = 0;
  for (;;) {
    if (await isCancelRequested(pool, jobId)) {
      await markFailed(pool, jobId, 'Cancelled');
      await deleteTargets(pool, jobId);
      return;
    }
    const page = await listTargetPage(pool, jobId, { afterId, limit: cfg.chunkSize });
    if (!page.length) break;
    afterId = page[page.length - 1];
    const outcome = await applyChunk(claimed.action, page, payload, user, extraMetadata);
    if (!outcome.ok) {
      await markFailed(pool, jobId, outcome.message || 'Bulk action failed');
      await deleteTargets(pool, jobId);
      return;
    }
    totals = mergeOutcomes(totals, outcome);
    const progress = ids.length
      ? Math.min(99, Math.floor((totals.requested / ids.length) * 100))
      : 100;
    await markProgress(pool, jobId, {
      matchCount: ids.length,
      succeeded: totals.succeeded,
      skipped: totals.skipped,
      failed: totals.failed,
      progress
    });
  }

  const completed = await markCompleted(pool, jobId, {
    matchCount: ids.length,
    succeeded: totals.succeeded,
    skipped: totals.skipped,
    failed: totals.failed,
    errorSample: errorSampleFromResults(totals.results),
    retentionHours: cfg.retentionHours
  });
  await deleteTargets(pool, jobId);
  await audit.auditSuccess?.({
    action: totals.failed > 0 ? AUDIT_ACTION.IOC_BULK_QUERY_FAILED : AUDIT_ACTION.IOC_BULK_QUERY_COMPLETED,
    entityType: AUDIT_ENTITY.IOC_BULK_QUERY,
    entityId: jobId,
    entityDisplay: compiled.normalizedQuery,
    severity: totals.failed > 0 ? AUDIT_SEVERITY.WARNING : AUDIT_SEVERITY.INFO,
    metadata: {
      selection_mode: 'all_matching',
      bulk_action: claimed.action,
      query: compiled.normalizedQuery,
      match_count: ids.length,
      succeeded: totals.succeeded,
      skipped: totals.skipped,
      failed: totals.failed,
      mode: 'async',
      ...(payload.reason ? { reason: payload.reason } : {})
    }
  }).catch(() => {});
  return completed;
}

const worker = new Worker(
  BULK_QUERY_QUEUE_NAME,
  async (job) => {
    const jobId = job.data?.jobId || job.id;
    await processJob(jobId);
  },
  { connection: redis, concurrency: workerConcurrency }
);

worker.on('failed', (job, err) => {
  log.error({ jobId: job?.data?.jobId || job?.id, err: err?.message }, 'query-wide bulk job failed');
  const id = job?.data?.jobId;
  if (id) markFailed(pool, id, err?.message || 'Worker failed').catch(() => {});
});

async function cleanupLoop() {
  try {
    const stale = await findStaleMetadata(pool, {
      olderThanDays: cfg.metadataRetentionDays,
      limit: 50
    });
    for (const row of stale) {
      await deleteMetadataRow(pool, row.id);
    }
  } catch (err) {
    log.warn({ err: err?.message }, 'bulk-query metadata cleanup failed');
  }
}

setInterval(() => { cleanupLoop().catch(() => {}); }, 60 * 60 * 1000);
cleanupLoop().catch(() => {});

log.info({ queue: BULK_QUERY_QUEUE_NAME, concurrency: workerConcurrency }, 'ioc-bulk-query worker started');
