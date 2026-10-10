/**
 * Threat Library worker boundary: validate the job mode, then route it.
 *
 *   refresh_extraction → extractionRefresh.runExtractionRefresh (AI-free)
 *   analyze / retry / rerun_ai → pipeline.runAnalysisPipeline (AI)
 *   inspect_ioc_source / extract_ioc_source → Additional IOC Sources jobs
 *
 * An unknown mode is rejected before any stage runs (UnknownJobModeError).
 */

import { parseJobMode, THREAT_LIBRARY_JOB_MODES, isIocSourceJobMode } from './jobModes.js';
import { runExtractionRefresh } from './extractionRefresh.js';
import { runAnalysisPipeline } from './pipeline.js';
import { inspectIocSource } from './iocSources/inspect.js';
import { extractIocSource } from './iocSources/extract.js';
import { getIocSourceByPublicId } from './iocSources/store.js';
import { updateJob } from './store.js';

/**
 * @param {import('pg').Pool} pool
 * @param {{ reportId: number, jobId: number, jobType: string, sourceUrl?: string, resumeAnalysis?: boolean, newAnalysisRun?: boolean, restoreStatus?: object, jobPayload?: object }} ctx
 * @param {{ analyzeThreatDocument?: Function, fetchImpl?: Function }} [deps] provider seam (tests)
 */
export async function runThreatLibraryJob(pool, ctx, deps = {}) {
  const mode = parseJobMode(ctx?.jobType);

  if (mode === THREAT_LIBRARY_JOB_MODES.REFRESH_EXTRACTION) {
    return runExtractionRefresh(pool, { reportId: ctx.reportId, jobId: ctx.jobId, restoreStatus: ctx.restoreStatus });
  }

  if (isIocSourceJobMode(mode)) {
    return runIocSourceJob(pool, { ...ctx, jobType: mode }, deps);
  }

  return runAnalysisPipeline(pool, { ...ctx, jobType: mode }, deps);
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} ctx
 * @param {{ fetchImpl?: Function }} [deps]
 */
async function runIocSourceJob(pool, ctx, deps = {}) {
  const payload = ctx.jobPayload && typeof ctx.jobPayload === 'object' ? ctx.jobPayload : {};
  const sourcePublicId = payload.source_public_id || payload.sourcePublicId;
  if (!sourcePublicId) {
    const err = new Error('IOC source job missing source_public_id');
    err.code = 'missing_source_id';
    throw err;
  }

  const source = await getIocSourceByPublicId(pool, sourcePublicId);
  if (!source || Number(source.report_id) !== Number(ctx.reportId)) {
    const err = new Error('IOC source not found for report');
    err.code = 'source_not_found';
    throw err;
  }

  await updateJob(pool, ctx.jobId, {
    status: 'running',
    stage: ctx.jobType,
    progress: { source_public_id: sourcePublicId }
  });

  const result = ctx.jobType === THREAT_LIBRARY_JOB_MODES.EXTRACT_IOC_SOURCE
    ? await extractIocSource(pool, source, deps)
    : await inspectIocSource(pool, source, deps);

  await updateJob(pool, ctx.jobId, {
    status: result.ok ? 'completed' : 'failed',
    stage: ctx.jobType,
    progress: {
      source_public_id: sourcePublicId,
      ok: result.ok,
      code: result.code || null,
      preview: result.preview || null
    },
    error_message: result.ok ? null : (result.code || 'ioc_source_job_failed')
  });

  return result;
}
