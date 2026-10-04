/**
 * Threat Library worker boundary: validate the job mode, then route it.
 *
 *   refresh_extraction → extractionRefresh.runExtractionRefresh (AI-free)
 *   analyze / retry / rerun_ai → pipeline.runAnalysisPipeline (AI)
 *
 * An unknown mode is rejected before any stage runs (UnknownJobModeError).
 */

import { parseJobMode, THREAT_LIBRARY_JOB_MODES } from './jobModes.js';
import { runExtractionRefresh } from './extractionRefresh.js';
import { runAnalysisPipeline } from './pipeline.js';

/**
 * @param {import('pg').Pool} pool
 * @param {{ reportId: number, jobId: number, jobType: string, sourceUrl?: string, resumeAnalysis?: boolean, newAnalysisRun?: boolean, restoreStatus?: object }} ctx
 * @param {{ analyzeThreatDocument?: Function }} [deps] provider seam (tests)
 */
export async function runThreatLibraryJob(pool, ctx, deps = {}) {
  const mode = parseJobMode(ctx?.jobType);
  if (mode === THREAT_LIBRARY_JOB_MODES.REFRESH_EXTRACTION) {
    return runExtractionRefresh(pool, { reportId: ctx.reportId, jobId: ctx.jobId, restoreStatus: ctx.restoreStatus });
  }
  return runAnalysisPipeline(pool, { ...ctx, jobType: mode }, deps);
}
