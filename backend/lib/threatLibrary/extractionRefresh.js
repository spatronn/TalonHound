/**
 * Deterministic extraction refresh ("Refresh extraction").
 *
 * Re-runs the deterministic part of the Threat Library pipeline on a completed
 * report — candidate extraction under the CURRENT contract, canonicalization,
 * occurrence / assertion / publisher-membership policy, IOC matching and the
 * candidate counts — and reconciles the result into the stored candidate set.
 *
 * It never invokes a model. This module and its whole static import graph stay
 * free of `./ai/*` (extractionRefresh.test.js enforces it), and it never
 * regenerates AI-owned report data: entities, relationships, report tags,
 * summary, confidence, report type, TLP, ai_result, analysis chunks / run id.
 * The one exception is subtractive and deterministic: the vulnerability
 * grounding gate the pipeline applies to every model result
 * (vulnerabilityGrounding.js) is re-applied to the STORED summary and entity
 * links, so a CVE the source never mentions, or a CVE-product pairing the
 * source never states, is removed. Nothing is added or rewritten otherwise.
 *
 * State ownership on a surviving canonical identity (candidate_type,
 * normalized_value):
 *   extraction  recomputed — occurrences, assertion, evidence, typing, policy
 *   AI          replayed — a stored model decision (evidence.decision_source
 *               = 'ai' / ai_role_suggestion) is fed back through the same
 *               mergeAiCandidateUpdates step the full pipeline uses, so the
 *               current evidence policy still gates it; nothing new is asked
 *   matching    recomputed against the local IOC catalog
 *   analyst     kept — review_status, the Context only decision, the Context
 *               Only → IOC promotion override, promotion outcome, row ids
 * A new identity is created as extraction produces it (ai_needed stays set
 * when the policy needs the model — no classification is fabricated); a
 * removed identity is deleted; state never moves between identities.
 */

import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import {
  applyPublicationDate,
  compactExtractionDiagnostics,
  extractReportCandidates,
  hasUsableDocument,
  isDocumentContractCurrent,
  matchCandidateSet,
  mergeAiCandidateUpdates,
  rebuildDocumentFromRetainedSource,
  summarizeResolvedCandidates
} from './extractionStages.js';
import {
  getReportById,
  loadReportCandidateRows,
  loadReportEntityLinks,
  reconcileReportCandidates,
  removeReportEntityLinks,
  restoreReportStatus,
  updateJob,
  updateReportStatus
} from './store.js';
import { groundStoredVulnerabilities, VULNERABILITY_GROUNDING_VERSION } from './vulnerabilityGrounding.js';
import { THREAT_LIBRARY_JOB_MODES } from './jobModes.js';
import {
  preserveAnalystCandidates,
  requiresReviewAfterExtractionRefresh
} from './candidateAnalystState.js';
import { createServiceLogger } from '../appLogger.js';

const log = createServiceLogger('threat-library');

const MODE = THREAT_LIBRARY_JOB_MODES.REFRESH_EXTRACTION;
const RESTORABLE = new Set(['review_required', 'ready']);

function evidenceOf(row) {
  return row?.evidence && typeof row.evidence === 'object' ? row.evidence : {};
}

/**
 * The terminal status a refresh returns the report to. Only a committed review
 * set or a finalized report is restorable; anything else falls back to
 * review_required (a refresh never finalizes a report implicitly).
 * @param {{ analysis_status?: string }|null|undefined} requested
 */
export function resolveRefreshRestoreStatus(requested) {
  const status = String(requested?.analysis_status || '').toLowerCase();
  const analysisStatus = RESTORABLE.has(status) ? status : 'review_required';
  return { analysis_status: analysisStatus, import_status: analysisStatus };
}

/**
 * Status a completed refresh actually leaves the report in.
 * review_required stays review_required. A finalized report stays finalized
 * only when the reconcile diff has no review-relevant change; otherwise it
 * returns to review_required. A refresh never finalizes a report.
 * @param {{ analysis_status?: string }|null|undefined} requested prior status
 * @param {{ added?: object[], removed?: object[], updated?: object[] }|null|undefined} diff
 */
export function resolveRefreshOutcomeStatus(requested, diff) {
  const restore = resolveRefreshRestoreStatus(requested);
  const reviewRelevant = requiresReviewAfterExtractionRefresh(diff);
  if (restore.analysis_status === 'ready' && reviewRelevant) {
    return {
      analysis_status: 'review_required',
      import_status: 'review_required',
      review_relevant: true,
      reopened_for_review: true,
      prior_status: 'ready'
    };
  }
  return {
    analysis_status: restore.analysis_status,
    import_status: restore.import_status,
    review_relevant: reviewRelevant,
    reopened_for_review: false,
    prior_status: restore.analysis_status
  };
}

/**
 * Stored model decisions as candidate updates for mergeAiCandidateUpdates.
 * Only rows whose persisted evidence proves the model decided them are
 * replayed; the replay is keyed by canonical identity, so it can only land on
 * the same (type, value) the model classified.
 * @param {object[]} rows persisted threat_report_candidates rows
 * @param {{ documentRebuilt?: boolean }} [opts] block pointers are kept only
 *   when the block ids still refer to the same document
 */
export function aiReplayUpdatesFromRows(rows, opts = {}) {
  const updates = [];
  for (const row of rows || []) {
    const ev = evidenceOf(row);
    // An analyst promotion overwrote assessment / role; the model's own
    // decision (if any) is the one recorded in promoted_from.
    const promotedFrom = ev.decision_source === 'analyst' && ev.promoted_from && typeof ev.promoted_from === 'object'
      ? ev.promoted_from
      : null;
    const decisionSource = promotedFrom ? promotedFrom.decision_source : ev.decision_source;
    const roleSuggestion = ev.ai_role_suggestion || null;
    if (decisionSource !== 'ai' && !roleSuggestion) continue;
    const confidence = row.confidence == null ? null : Number(row.confidence);
    if (decisionSource === 'ai') {
      const update = {
        candidate_type: row.candidate_type,
        normalized_value: row.normalized_value,
        assessment: (promotedFrom ? promotedFrom.assessment : row.assessment) || undefined,
        role: (promotedFrom ? promotedFrom.role : row.role) || undefined,
        confidence
      };
      if (row.evidence_text) update.evidence_text = row.evidence_text;
      if (!opts.documentRebuilt) {
        if (row.section) update.section = row.section;
        if (row.block_id) update.evidence_block_ids = [row.block_id];
      }
      updates.push(update);
    } else {
      // Explicit / provider rows: the model only suggested a role.
      updates.push({
        candidate_type: row.candidate_type,
        normalized_value: row.normalized_value,
        role: roleSuggestion,
        confidence
      });
    }
  }
  return updates;
}

export { applyAnalystState } from './candidateAnalystState.js';

/**
 * Pure-ish core (reads only: IOC matching): the refreshed candidate set for a
 * report document and its persisted rows. No writes.
 * @param {import('pg').Pool} pool
 * @param {{ report: object, document: object, previousRows: object[], documentRebuilt?: boolean }} input
 */
export async function computeExtractionRefresh(pool, { report, document, previousRows, documentRebuilt = false }) {
  const extracted = extractReportCandidates(report, document);
  const replay = aiReplayUpdatesFromRows(previousRows, { documentRebuilt });
  const merged = mergeAiCandidateUpdates(extracted.candidates, { candidate_updates: replay }, { document: extracted.document });
  const matched = await matchCandidateSet(pool, merged);
  const candidates = preserveAnalystCandidates(matched.candidates, previousRows);
  return {
    document: extracted.document,
    diagnostics: extracted.diagnostics,
    candidates,
    summary: summarizeResolvedCandidates(candidates),
    replayedAiDecisions: replay.length
  };
}

/**
 * Re-apply the vulnerability grounding gate to the stored model output of a
 * report (summary + entity links). Subtractive only; returns the grounded
 * summary when it changed (else null) and diagnostics.
 * @param {import('pg').Pool} pool
 * @param {{ id: number, summary?: string|null }} report
 * @param {object} document canonical document the refresh extracted from
 */
export async function applyStoredVulnerabilityGrounding(pool, report, document) {
  const entities = await loadReportEntityLinks(pool, report.id);
  const grounded = groundStoredVulnerabilities({ summary: report.summary ?? null, entities }, document);
  const removal = await removeReportEntityLinks(pool, report.id, grounded.entity_ids_removed);
  return {
    summary: grounded.summary_changed ? grounded.summary : null,
    diagnostics: {
      version: VULNERABILITY_GROUNDING_VERSION,
      summary_changed: grounded.summary_changed,
      summary_removed_cves: grounded.removed_cves,
      summary_unpaired: grounded.unpaired,
      entity_links_removed: removal.links_removed,
      relationships_removed: removal.relationships_removed
    }
  };
}

/**
 * Worker entry for `refresh_extraction` jobs.
 * @param {import('pg').Pool} pool
 * @param {{ reportId: number, jobId: number, restoreStatus?: object }} ctx
 */
export async function runExtractionRefresh(pool, ctx) {
  const report = await getReportById(pool, ctx.reportId);
  if (!report) throw Object.assign(new Error('Report not found'), { code: 'not_found' });

  const startedAt = Date.now();
  const restore = resolveRefreshRestoreStatus(ctx.restoreStatus);
  // The dispatch payload rides on every job progress write so a job re-queued
  // after a worker crash still knows its mode and the status to restore.
  const dispatch = { jobType: MODE, restoreStatus: restore };
  const priorProgress = report.analysis_progress && typeof report.analysis_progress === 'object'
    ? { ...report.analysis_progress }
    : {};
  delete priorProgress.mode;
  delete priorProgress.dispatch;
  delete priorProgress.requested_at;

  const setStage = async (stage) => {
    await updateJob(pool, ctx.jobId, { status: 'running', stage, progress: { stage, mode: MODE, dispatch } });
    await updateReportStatus(pool, report.id, {
      analysis_status: stage,
      import_status: 'processing',
      analysis_progress: { ...priorProgress, stage, mode: MODE }
    });
  };

  try {
    await setStage('extracting');

    let document = report.canonical_document;
    let sourceHtml = null;
    let documentRebuilt = false;
    if (!hasUsableDocument(document)) {
      throw Object.assign(new Error('The report has no stored canonical document to refresh from.'), { code: 'refresh_document_missing' });
    }
    if (!isDocumentContractCurrent(report, document)) {
      let rebuilt = null;
      try {
        rebuilt = await rebuildDocumentFromRetainedSource(pool, report);
      } catch (err) {
        log.warn('retained source unusable for extraction refresh', { reportId: report.id, error: err.message });
      }
      if (!rebuilt) {
        throw Object.assign(
          new Error('The stored document predates the current extractor and no retained source is available; Refresh extraction never re-fetches the source.'),
          { code: 'refresh_source_unavailable' }
        );
      }
      document = rebuilt.document;
      sourceHtml = rebuilt.sourceHtml;
      documentRebuilt = true;
    }

    await applyPublicationDate(pool, report, { document, sourceHtml });
    const previousRows = await loadReportCandidateRows(pool, report.id);

    await setStage('matching');
    const refreshed = await computeExtractionRefresh(pool, { report, document, previousRows, documentRebuilt });
    const persisted = await reconcileReportCandidates(pool, report.id, refreshed.candidates);
    const outcome = resolveRefreshOutcomeStatus(restore, persisted);
    const grounding = await applyStoredVulnerabilityGrounding(pool, report, refreshed.document);

    const result = {
      document_rebuilt: documentRebuilt,
      candidates_total: refreshed.candidates.length,
      added: persisted.added.length,
      updated: persisted.updated.length,
      unchanged: persisted.unchanged,
      removed: persisted.removed.length,
      replayed_ai_decisions: refreshed.replayedAiDecisions,
      vulnerability_grounding: grounding.diagnostics,
      ai_invoked: false,
      review_relevant: outcome.review_relevant,
      reopened_for_review: outcome.reopened_for_review,
      prior_status: outcome.prior_status,
      restored_status: outcome.analysis_status
    };
    const lastRefresh = {
      job_id: ctx.jobId,
      completed_at: new Date().toISOString(),
      extraction_contract: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
      ...result,
      added_identities: persisted.added.slice(0, 40),
      removed_identities: persisted.removed.slice(0, 40)
    };

    await updateReportStatus(pool, report.id, {
      canonical_document: refreshed.document,
      candidate_summary: refreshed.summary,
      ...(grounding.summary != null ? { summary: grounding.summary } : {}),
      analysis_status: outcome.analysis_status,
      import_status: outcome.import_status,
      analysis_progress: {
        ...priorProgress,
        stage: outcome.analysis_status,
        completed: true,
        candidate_extraction_version: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
        document_extractor: refreshed.document.meta?.extractor || null,
        extraction_diagnostics: compactExtractionDiagnostics(refreshed.diagnostics),
        last_refresh: lastRefresh
      },
      clear_cancel: true
    });
    await updateJob(pool, ctx.jobId, {
      status: 'completed',
      stage: outcome.analysis_status,
      progress: { stage: outcome.analysis_status, mode: MODE, dispatch, summary: refreshed.summary, refresh: result }
    });

    log.info('extraction refresh completed', {
      reportId: report.id,
      jobId: ctx.jobId,
      mode: MODE,
      extraction_contract: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
      candidates_refreshed: true,
      ...result,
      elapsed_ms: Date.now() - startedAt
    });
    if (outcome.reopened_for_review) {
      log.info('finalized report reopened for review after extraction refresh', {
        reportId: report.id,
        jobId: ctx.jobId,
        prior_status: outcome.prior_status,
        restored_status: outcome.analysis_status,
        added: result.added,
        removed: result.removed,
        updated: result.updated
      });
    }
    return {
      ok: true,
      summary: {
        ...refreshed.summary,
        mode: MODE,
        extraction_contract: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
        ...result
      }
    };
  } catch (err) {
    const code = err?.code && /^[a-z0-9_]{2,64}$/i.test(String(err.code)) ? String(err.code) : 'refresh_failed';
    // The committed review set is unchanged unless the reconcile transaction
    // committed; either way the report returns to its prior terminal status —
    // a deterministic refresh failure never strands a report in "failed"
    // (which would force an AI Retry).
    await restoreReportStatus(pool, report.id, restore, {
      ...priorProgress,
      stage: restore.analysis_status,
      last_refresh: {
        job_id: ctx.jobId,
        failed_at: new Date().toISOString(),
        extraction_contract: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
        error_code: code,
        ai_invoked: false
      }
    });
    await updateJob(pool, ctx.jobId, {
      status: 'failed',
      stage: 'extracting',
      error_message: err?.message || 'Refresh extraction failed',
      progress: { stage: 'extracting', mode: MODE, dispatch, failure_code: code }
    });
    log.warn('extraction refresh failed', {
      reportId: report.id,
      jobId: ctx.jobId,
      mode: MODE,
      extraction_contract: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
      code,
      ai_invoked: false,
      restored_status: restore.analysis_status
    });
    return { ok: false, code, error: err?.message || 'Refresh extraction failed' };
  }
}
