/**
 * Retry analysis: decide active stage before enqueue so UI can leave failed immediately.
 */

const TERMINAL_ANALYSIS = new Set(['ready', 'skipped', 'review_required', 'failed']);

export function isActiveAnalysisStatus(status) {
  const s = String(status || '').toLowerCase();
  if (!s) return false;
  return !TERMINAL_ANALYSIS.has(s);
}

/**
 * Prefer AI-stage resume when document + candidates already exist (Retry Analysis contract).
 * @param {{ hasDocument?: boolean, candidateCount?: number }} opts
 */
export function resolveRetryStartStatus(opts = {}) {
  const hasDocument = opts.hasDocument === true;
  const candidateCount = Number(opts.candidateCount) || 0;
  if (hasDocument && candidateCount > 0) return 'analyzing';
  if (hasDocument) return 'extracting';
  return 'pending';
}

/**
 * Progress payload for an accepted retry — keeps earlier stages visually complete.
 */
export function buildRetryProgress(analysisStatus) {
  const stage = String(analysisStatus || 'pending');
  const base = { stage, resumed: true, analysis_chunks_completed: 0 };
  if (stage === 'analyzing') {
    return {
      ...base,
      reused_document: true,
      reused_candidates: true,
      analysis_chunks_total: null
    };
  }
  if (stage === 'extracting') {
    return { ...base, reused_document: true };
  }
  return base;
}
