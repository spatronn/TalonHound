/**
 * Threat Library AI analysis concurrency: one global slot budget for the
 * shared URL/PDF analysis pipeline (BullMQ `analyze` / `retry` jobs).
 *
 * Jobs persist as `threat_library_jobs.status = 'queued'` with a null
 * `bullmq_job_id` until a slot is claimed. Claiming is serialized with a
 * Postgres transaction advisory lock so two schedulers cannot both observe
 * occupied=0 and start work when the limit is 1.
 */

import { createServiceLogger } from '../appLogger.js';
import { getThreatLibraryJobOptions } from './queueConfig.js';
import { getAiSettings, updateJob, updateReportStatus } from './store.js';
import { PIPELINE_JOB_MODES, THREAT_LIBRARY_JOB_MODES } from './jobModes.js';

const log = createServiceLogger('threat-library-scheduler');

export const MAX_CONCURRENT_REPORT_ANALYSES_MIN = 1;
export const MAX_CONCURRENT_REPORT_ANALYSES_MAX = 4;
/** Preserves the historical worker concurrency default (env default was 2). */
export const MAX_CONCURRENT_REPORT_ANALYSES_DEFAULT = 2;
export const ANALYSIS_SLOT_LOCK_KEY = 'threat-library.analysis_slots';

// Every URL/PDF pipeline mode (jobModes.js) shares the slot budget, crash
// recovery and unclaimed-cancel handling — including the AI-free refresh.
const ANALYSIS_JOB_TYPES = PIPELINE_JOB_MODES;
const OCCUPIED_JOB_STATUSES = Object.freeze(['queued', 'running']);
const LIVE_BULLMQ_STATES = new Set(['active', 'waiting', 'delayed', 'paused', 'waiting-children']);

export class AnalysisConcurrencySettingError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AnalysisConcurrencySettingError';
    this.code = 'invalid_max_concurrent_report_analyses';
    this.status = 400;
  }
}

/**
 * Parse and validate the persisted setting. Integers only; min 1, max 4.
 * @param {unknown} value
 * @returns {number}
 */
export function parseMaxConcurrentReportAnalyses(value) {
  if (value === null || value === undefined || value === '') {
    throw new AnalysisConcurrencySettingError(
      `max_concurrent_report_analyses must be an integer between ${MAX_CONCURRENT_REPORT_ANALYSES_MIN} and ${MAX_CONCURRENT_REPORT_ANALYSES_MAX}`
    );
  }
  if (typeof value === 'boolean') {
    throw new AnalysisConcurrencySettingError(
      `max_concurrent_report_analyses must be an integer between ${MAX_CONCURRENT_REPORT_ANALYSES_MIN} and ${MAX_CONCURRENT_REPORT_ANALYSES_MAX}`
    );
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!/^-?\d+$/.test(trimmed)) {
      throw new AnalysisConcurrencySettingError(
        `max_concurrent_report_analyses must be an integer between ${MAX_CONCURRENT_REPORT_ANALYSES_MIN} and ${MAX_CONCURRENT_REPORT_ANALYSES_MAX}`
      );
    }
    value = Number(trimmed);
  }
  if (typeof value !== 'number' || !Number.isFinite(value) || !Number.isInteger(value)) {
    throw new AnalysisConcurrencySettingError(
      `max_concurrent_report_analyses must be an integer between ${MAX_CONCURRENT_REPORT_ANALYSES_MIN} and ${MAX_CONCURRENT_REPORT_ANALYSES_MAX}`
    );
  }
  if (value < MAX_CONCURRENT_REPORT_ANALYSES_MIN || value > MAX_CONCURRENT_REPORT_ANALYSES_MAX) {
    throw new AnalysisConcurrencySettingError(
      `max_concurrent_report_analyses must be an integer between ${MAX_CONCURRENT_REPORT_ANALYSES_MIN} and ${MAX_CONCURRENT_REPORT_ANALYSES_MAX}`
    );
  }
  return value;
}

/**
 * Read the configured limit, falling back to the historical default of 2.
 * @param {unknown} value
 */
export function resolveMaxConcurrentReportAnalyses(value) {
  if (value == null || value === '') return MAX_CONCURRENT_REPORT_ANALYSES_DEFAULT;
  try {
    return parseMaxConcurrentReportAnalyses(value);
  } catch {
    return MAX_CONCURRENT_REPORT_ANALYSES_DEFAULT;
  }
}

/**
 * Worker process ceiling: must be able to run the setting maximum without restart.
 * Env remains a hard cap (1–4); default is the setting maximum (4).
 */
export function resolveThreatLibraryWorkerConcurrency(envValue = process.env.THREAT_LIBRARY_WORKER_CONCURRENCY) {
  const raw = envValue == null || envValue === '' ? MAX_CONCURRENT_REPORT_ANALYSES_MAX : Number(envValue);
  if (!Number.isFinite(raw)) return MAX_CONCURRENT_REPORT_ANALYSES_MAX;
  return Math.min(Math.max(Math.trunc(raw), MAX_CONCURRENT_REPORT_ANALYSES_MIN), MAX_CONCURRENT_REPORT_ANALYSES_MAX);
}

export function dispatchExtraFromJob(job) {
  const progress = job?.progress && typeof job.progress === 'object' ? job.progress : {};
  const dispatch = progress.dispatch && typeof progress.dispatch === 'object' ? progress.dispatch : {};
  const jobType = dispatch.jobType || job?.job_type || 'analyze';
  const extra = {
    sourceUrl: dispatch.sourceUrl || job?.source_url || undefined,
    resumeAnalysis:
      dispatch.resumeAnalysis === true ||
      jobType === THREAT_LIBRARY_JOB_MODES.RETRY ||
      jobType === THREAT_LIBRARY_JOB_MODES.RERUN_AI,
    newAnalysisRun: dispatch.newAnalysisRun === true || jobType === THREAT_LIBRARY_JOB_MODES.RERUN_AI,
    jobType
  };
  // Maintenance jobs return the report to the status it had when requested.
  if (dispatch.restoreStatus && typeof dispatch.restoreStatus === 'object') {
    extra.restoreStatus = dispatch.restoreStatus;
  }
  return extra;
}

/**
 * @param {import('pg').Pool|import('pg').PoolClient} pool
 * @param {{
 *   enqueue: (job: object) => Promise<{ id: string|number }>,
 *   limitOverride?: number
 * }} opts
 */
export async function dispatchQueuedThreatLibraryAnalyses(pool, opts = {}) {
  const enqueue = opts.enqueue;
  if (typeof enqueue !== 'function') {
    throw new Error('dispatchQueuedThreatLibraryAnalyses requires an enqueue function');
  }

  const client = typeof pool.connect === 'function' ? await pool.connect() : pool;
  const release = client !== pool;
  let claimed = [];
  let occupied = 0;
  let limit = MAX_CONCURRENT_REPORT_ANALYSES_DEFAULT;

  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [ANALYSIS_SLOT_LOCK_KEY]);

    if (opts.limitOverride != null) {
      limit = parseMaxConcurrentReportAnalyses(opts.limitOverride);
    } else {
      const settings = await getAiSettings(client);
      limit = resolveMaxConcurrentReportAnalyses(settings?.max_concurrent_report_analyses);
    }

    const occupiedRes = await client.query(
      `SELECT COUNT(*)::int AS occupied
       FROM threat_library_jobs
       WHERE status = ANY($1::text[])
         AND bullmq_job_id IS NOT NULL
         AND job_type = ANY($2::text[])`,
      [OCCUPIED_JOB_STATUSES, ANALYSIS_JOB_TYPES]
    );
    occupied = occupiedRes.rows[0]?.occupied || 0;
    const available = Math.max(0, limit - occupied);
    if (available === 0) {
      await client.query('COMMIT');
      return { claimed, occupied, limit, available: 0 };
    }

    const { rows: candidates } = await client.query(
      `SELECT j.id, j.report_id, j.job_type, j.status, j.progress, j.created_at,
              r.source_url, r.public_id AS report_public_id, r.source_type
       FROM threat_library_jobs j
       JOIN threat_reports r ON r.id = j.report_id
       WHERE j.status = 'queued'
         AND j.bullmq_job_id IS NULL
         AND j.job_type = ANY($1::text[])
         AND r.deleted_at IS NULL
       ORDER BY j.created_at ASC, j.id ASC
       LIMIT $2
       FOR UPDATE OF j SKIP LOCKED`,
      [ANALYSIS_JOB_TYPES, available]
    );

    for (const job of candidates) {
      const extra = dispatchExtraFromJob(job);
      const bull = await enqueue({ ...job, ...extra });
      if (!bull?.id && bull?.id !== 0) {
        throw new Error('enqueue did not return a BullMQ job id');
      }
      const bullId = String(bull.id);
      const updated = await client.query(
        `UPDATE threat_library_jobs
         SET bullmq_job_id = $2
         WHERE id = $1 AND status = 'queued' AND bullmq_job_id IS NULL
         RETURNING id`,
        [job.id, bullId]
      );
      if (!updated.rowCount) {
        log.warn('analysis claim lost after enqueue', { jobId: job.id, reportId: job.report_id });
        continue;
      }
      claimed.push({
        jobId: job.id,
        reportId: job.report_id,
        reportPublicId: job.report_public_id || null,
        sourceType: job.source_type || null,
        bullmqJobId: bullId,
        jobType: extra.jobType
      });
      log.info('report claimed', {
        jobId: job.id,
        reportId: job.report_id,
        sourceType: job.source_type || null,
        jobType: extra.jobType,
        occupied: occupied + claimed.length,
        limit
      });
    }

    await client.query('COMMIT');
    if (claimed.length) {
      log.info('analysis slots assigned', {
        claimed: claimed.length,
        occupied: occupied + claimed.length,
        limit
      });
    }
    return {
      claimed,
      occupied: occupied + claimed.length,
      limit,
      available: Math.max(0, limit - (occupied + claimed.length))
    };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    throw err;
  } finally {
    if (release) client.release();
  }
}

/**
 * Enqueue a claimed job onto the shared Threat Library BullMQ queue.
 * @param {import('bullmq').Queue} queue
 * @param {object} job
 */
export async function enqueueClaimedThreatLibraryJob(queue, job) {
  if (!queue) {
    const err = new Error('Threat Library queue unavailable');
    err.code = 'queue_unavailable';
    throw err;
  }
  const extra = dispatchExtraFromJob(job);
  return queue.add(
    extra.jobType || 'analyze',
    {
      reportId: job.report_id,
      jobId: job.id,
      sourceUrl: extra.sourceUrl,
      resumeAnalysis: extra.resumeAnalysis === true,
      jobType: extra.jobType,
      newAnalysisRun: extra.newAnalysisRun === true,
      ...(extra.restoreStatus ? { restoreStatus: extra.restoreStatus } : {})
    },
    getThreatLibraryJobOptions()
  );
}

/**
 * Persist a queued analysis job (no BullMQ add). The HTTP import returns
 * immediately; dispatch claims a slot when one exists.
 * @param {import('pg').Pool} pool
 * @param {import('bullmq').Queue} queue
 * @param {{
 *   reportId: number,
 *   jobType?: string,
 *   requestedBy?: string|null,
 *   dispatch?: object,
 *   createJob: Function
 * }} input
 */
export async function queueThreatLibraryAnalysis(pool, queue, input) {
  const createJob = input.createJob;
  const jobRow = await createJob(pool, {
    reportId: input.reportId,
    jobType: input.jobType || 'analyze',
    requestedBy: input.requestedBy || null
  });
  if (input.dispatch && typeof input.dispatch === 'object') {
    await updateJob(pool, jobRow.id, {
      status: 'queued',
      stage: 'queued',
      progress: { ...(input.progress || {}), dispatch: input.dispatch }
    });
  }
  log.info('report queued', {
    jobId: jobRow.id,
    reportId: input.reportId,
    jobType: input.jobType || 'analyze'
  });
  const result = await dispatchQueuedThreatLibraryAnalyses(pool, {
    enqueue: (job) => enqueueClaimedThreatLibraryJob(queue, job)
  });
  return { jobRow, dispatch: result };
}

/**
 * Re-queue interrupted claimed/running jobs whose BullMQ state is gone so a
 * crash cannot permanently consume a concurrency slot. Live BullMQ states
 * are left alone (another worker may still own them).
 *
 * @param {import('pg').Pool} pool
 * @param {{ getJobState?: (bullmqJobId: string) => Promise<string|null> }} opts
 */
export async function recoverInterruptedAnalysisJobs(pool, opts = {}) {
  const { rows } = await pool.query(
    `SELECT j.id, j.report_id, j.status, j.bullmq_job_id, j.job_type
     FROM threat_library_jobs j
     WHERE j.status = ANY($1::text[])
       AND j.bullmq_job_id IS NOT NULL
       AND j.job_type = ANY($2::text[])`,
    [OCCUPIED_JOB_STATUSES, ANALYSIS_JOB_TYPES]
  );
  const recovered = [];
  for (const row of rows) {
    let state = null;
    if (typeof opts.getJobState === 'function') {
      try {
        state = await opts.getJobState(String(row.bullmq_job_id));
      } catch {
        state = null;
      }
    }
    if (state && LIVE_BULLMQ_STATES.has(state)) continue;

    if (row.status === 'running') {
      await pool.query(
        `UPDATE threat_library_jobs
         SET status = 'queued',
             bullmq_job_id = NULL,
             stage = 'queued',
             error_message = 'recovered after interrupted analysis'
         WHERE id = $1 AND status = 'running'`,
        [row.id]
      );
      await updateReportStatus(pool, row.report_id, {
        analysis_status: 'pending',
        import_status: 'processing'
      });
      recovered.push({ jobId: row.id, reportId: row.report_id, reason: 'interrupted_running' });
      log.info('stale analysis recovered', { jobId: row.id, reportId: row.report_id, reason: 'interrupted_running', bullmqState: state || 'missing' });
    } else if (row.status === 'queued') {
      await pool.query(
        `UPDATE threat_library_jobs
         SET bullmq_job_id = NULL
         WHERE id = $1 AND status = 'queued'`,
        [row.id]
      );
      recovered.push({ jobId: row.id, reportId: row.report_id, reason: 'stale_claim' });
      log.info('stale analysis recovered', { jobId: row.id, reportId: row.report_id, reason: 'stale_claim', bullmqState: state || 'missing' });
    }
  }
  return recovered;
}

/**
 * Cancel queued jobs that have not been claimed yet (they do not occupy a
 * slot). Claimed/running jobs keep the existing cancel-at-checkpoint path.
 * @param {import('pg').Pool} pool
 * @param {number} reportId
 */
export async function cancelUnclaimedAnalysisJobs(pool, reportId) {
  const { rows } = await pool.query(
    `UPDATE threat_library_jobs
     SET status = 'cancelled',
         stage = 'cancelled',
         finished_at = NOW()
     WHERE report_id = $1
       AND status = 'queued'
       AND bullmq_job_id IS NULL
       AND job_type = ANY($2::text[])
     RETURNING id, job_type, progress`,
    [reportId, ANALYSIS_JOB_TYPES]
  );
  if (rows.length) {
    log.info('unclaimed analysis cancelled', { reportId, jobIds: rows.map((r) => r.id) });
  }
  return rows;
}

/**
 * Status a cancelled-before-claim maintenance job (refresh_extraction /
 * rerun_ai) must hand back: the report was moved to `pending` only to queue
 * it, its committed state never changed. Null for analyze / retry jobs.
 * @param {object[]} cancelledJobs rows returned by cancelUnclaimedAnalysisJobs
 */
export function restoreStatusForCancelledJobs(cancelledJobs) {
  for (const job of cancelledJobs || []) {
    const restore = job?.progress?.dispatch?.restoreStatus;
    if (restore && typeof restore === 'object' && restore.analysis_status) return restore;
  }
  return null;
}
