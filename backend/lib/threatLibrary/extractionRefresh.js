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
 * The exceptions are subtractive and deterministic: the grounding gates the
 * pipeline applies to every model result are re-applied to the STORED summary
 * and entity links: vulnerabilityGrounding.js (a CVE the source never
 * mentions, or a CVE-product pairing the source never states, is removed) and
 * publisherEntityGrounding.js (the publisher's own name promoted to a
 * campaign / threat actor the source never states is unlinked, and the
 * summary clause asserting it is removed). Nothing is added or rewritten
 * otherwise.
 *
 * The report title is document-derived, not AI-owned: a URL report re-selects
 * it from its retained source HTML under the current title rules
 * (extract/titleSelection.js); without retained HTML it is kept.
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
  reselectReportTitle,
  summarizeResolvedCandidates
} from './extractionStages.js';
import {
  getReportById,
  loadReportCandidateRows,
  loadReportEntityLinks,
  reconcileReportCandidates,
  removeReportEntityLinks,
  restoreReportStatus,
  loadSourceLinkedCandidateIds,
  updateJob,
  updateReportStatus
} from './store.js';
import { groundStoredVulnerabilities, VULNERABILITY_GROUNDING_VERSION } from './vulnerabilityGrounding.js';
import { groundStoredPublisherEntities, PUBLISHER_ENTITY_GROUNDING_VERSION } from './publisherEntityGrounding.js';
import { THREAT_LIBRARY_JOB_MODES } from './jobModes.js';
import {
  preserveAnalystCandidates,
  requiresReviewAfterExtractionRefresh
} from './candidateAnalystState.js';
import { createServiceLogger } from '../appLogger.js';
import { compactExtractionQuality, storedExtractionQuality, withPostMergeQuality, withReplayMembershipDivergence } from './extractionQuality.js';
import { preserveStoredIocLinks } from './iocMatch.js';
import {
  REFRESH_GUARD_DECISIONS,
  buildRefreshMembershipDiff,
  compactRefreshMembershipDiff,
  evaluateRefreshMembershipGuard,
  normalizeRefreshMembershipPolicy
} from './refreshMembershipGuard.js';

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
  // Deterministic publisher reading (extraction + AI replay + catalog match),
  // with the stored global-IOC links of identities the lookup skipped kept.
  const linked = await preserveStoredIocLinks(pool, matched.candidates, previousRows);
  const candidates = preserveAnalystCandidates(linked.candidates, previousRows);
  // Where replayed analyst state moves membership away from the deterministic
  // reading, quality says so (an explicit override is a note; anything else warns).
  const quality = withPostMergeQuality(withReplayMembershipDivergence(extracted.diagnostics?.quality || null, {
    deterministic: linked.candidates,
    final: candidates,
    previousRows
  }), candidates);
  return {
    document: extracted.document,
    diagnostics: quality ? { ...extracted.diagnostics, quality } : extracted.diagnostics,
    candidates,
    summary: summarizeResolvedCandidates(candidates),
    replayedAiDecisions: replay.length,
    iocLinksPreserved: linked.preserved
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
 * Re-apply the publisher-entity gate to the stored model output of a report.
 * Subtractive only: unlinks unsupported entities from THIS report (with this
 * report's relationships that use them; the shared entity row stays) and
 * returns the grounded summary when it changed (else null).
 * @param {import('pg').Pool} pool
 * @param {{ id: number, summary?: string|null, source_url?: string|null, source_name?: string|null }} report
 * @param {object} document canonical document the refresh extracted from
 */
export async function applyStoredPublisherEntityGrounding(pool, report, document) {
  const entities = await loadReportEntityLinks(pool, report.id);
  const grounded = groundStoredPublisherEntities({ summary: report.summary ?? null, entities }, { report, document });
  const removal = await removeReportEntityLinks(pool, report.id, grounded.entity_ids_removed);
  return {
    summary: grounded.summary_changed ? grounded.summary : null,
    diagnostics: {
      version: PUBLISHER_ENTITY_GROUNDING_VERSION,
      entities_removed: grounded.entities_removed,
      summary_changed: grounded.summary_changed,
      summary_unresolved: grounded.summary_unresolved,
      entity_links_removed: removal.links_removed,
      relationships_removed: removal.relationships_removed
    }
  };
}

/**
 * Canonical document a refresh extracts from: the stored one when its
 * extractor contract is current, else a rebuild from the retained source
 * (never a re-fetch). Reads only.
 * @param {import('pg').Pool} pool
 * @param {object} report
 * @returns {Promise<{ document: object, sourceHtml: string|null, documentRebuilt: boolean }>}
 */
export async function prepareRefreshDocument(pool, report) {
  const document = report.canonical_document;
  if (!hasUsableDocument(document)) {
    throw Object.assign(new Error('The report has no stored canonical document to refresh from.'), { code: 'refresh_document_missing' });
  }
  if (isDocumentContractCurrent(report, document)) return { document, sourceHtml: null, documentRebuilt: false };
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
  return { document: rebuilt.document, sourceHtml: rebuilt.sourceHtml, documentRebuilt: true };
}

/**
 * Membership diff + guard decision for a computed refresh (no writes).
 * @param {object} report stored report row (its quality record is the "before")
 * @param {object[]} previousRows persisted candidate rows
 * @param {Awaited<ReturnType<typeof computeExtractionRefresh>>} refreshed
 * @param {unknown} membershipPolicy
 * @param {{ linkedCandidateIds?: Set<string>|null }} [opts] rows with IOC Source
 *   provenance (kept, not deleted, when they leave the original document)
 */
export function guardExtractionRefresh(report, previousRows, refreshed, membershipPolicy, opts = {}) {
  const diff = buildRefreshMembershipDiff({
    previousRows,
    nextCandidates: refreshed.candidates,
    previousQuality: storedExtractionQuality(report),
    nextQuality: refreshed.diagnostics?.quality || null,
    linkedCandidateIds: opts.linkedCandidateIds || null
  });
  return { diff, guard: evaluateRefreshMembershipGuard(diff, membershipPolicy, { acceptorRole: opts.acceptorRole ?? null }) };
}

/** requested_by of an acceptance queued by the server-side maintenance CLI. */
export const MAINTENANCE_CLI_ACTOR = 'system:threat-library-maintenance';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Role of the principal that accepted a refresh, resolved from the database
 * when the job runs (never from the request body or the queued payload): the
 * CURRENT role of an active user, so a demoted or disabled admin cannot
 * authorize an admin-only acceptance queued earlier. The maintenance CLI
 * (server shell access) is `system`. Anything unresolvable is null (not admin).
 * @param {import('pg').Pool} pool
 * @param {{ mode?: string, requested_by?: string|null }} policy
 * @returns {Promise<string|null>}
 */
export async function resolveAcceptorRole(pool, policy) {
  if (policy?.mode !== 'accept') return null;
  const who = String(policy.requested_by || '');
  if (who === MAINTENANCE_CLI_ACTOR) return 'system';
  if (!UUID_RE.test(who)) return null;
  try {
    const { rows } = await pool.query(`SELECT role, status FROM users WHERE public_id = $1::uuid`, [who]);
    const row = rows?.[0];
    return row && String(row.status || '') === 'active' ? String(row.role || '') || null : null;
  } catch (err) {
    log.warn('refresh acceptance: acceptor role lookup failed (treated as non-admin)', { error: err.message });
    return null;
  }
}

export const REFRESH_CONCURRENT_CHANGE_CODE = 'refresh_candidates_changed_concurrently';

/** Row state the refresh computed from and the guard protects (analyst, promotion, membership). */
const SNAPSHOT_FIELDS = Object.freeze([
  'candidate_type',
  'normalized_value',
  'review_status',
  'assessment',
  'role',
  'is_ioc',
  'source_assertion',
  'match_state',
  'matched_ioc_id',
  'promotion_outcome',
  'has_original_document_occurrence'
]);

function snapshotKey(row) {
  const t = row?.updated_at ? new Date(row.updated_at).getTime() : null;
  return JSON.stringify([...SNAPSHOT_FIELDS.map((f) => row?.[f] ?? null), Number.isFinite(t) ? t : null]);
}

/**
 * Ids of rows that differ between the snapshot a refresh was computed and
 * guarded from and the rows locked for the write (added, removed or changed
 * by a concurrent review, Create IOCs, promotion or IOC Source reconcile).
 * @param {object[]} snapshotRows
 * @param {object[]} lockedRows
 * @returns {string[]}
 */
export function candidateSnapshotDrift(snapshotRows, lockedRows) {
  const before = new Map((snapshotRows || []).map((r) => [String(r.id), snapshotKey(r)]));
  const after = new Map((lockedRows || []).map((r) => [String(r.id), snapshotKey(r)]));
  const drift = [];
  for (const [id, key] of before) if (after.get(id) !== key) drift.push(id);
  for (const id of after.keys()) if (!before.has(id)) drift.push(id);
  return drift.sort();
}

/**
 * Linked-source provenance of the stored rows a refresh would drop (one query).
 * @param {import('pg').Pool} pool
 * @param {object[]} previousRows
 * @param {object[]} nextCandidates
 */
export async function linkedRowsLeavingDocument(pool, previousRows, nextCandidates) {
  const nextKeys = new Set((nextCandidates || []).map((c) => `${c.candidate_type}\0${c.normalized_value}`));
  const leaving = (previousRows || []).filter(
    (r) => r.has_original_document_occurrence !== false && !nextKeys.has(`${r.candidate_type}\0${r.normalized_value}`)
  );
  return loadSourceLinkedCandidateIds(pool, leaving.map((r) => r.id));
}

/**
 * Read-only preview of a Refresh extraction: what the refresh would change in
 * report Indicator membership and quality, and whether the guard would block
 * it under the given policy. Never writes (no candidates, status, title,
 * publication date or entity changes).
 * @param {import('pg').Pool} pool
 * @param {object} report
 * @param {{ membershipPolicy?: unknown }} [opts]
 */
export async function previewExtractionRefresh(pool, report, opts = {}) {
  const { document, documentRebuilt } = await prepareRefreshDocument(pool, report);
  const previousRows = await loadReportCandidateRows(pool, report.id);
  const refreshed = await computeExtractionRefresh(pool, { report, document, previousRows, documentRebuilt });
  const linkedCandidateIds = await linkedRowsLeavingDocument(pool, previousRows, refreshed.candidates);
  const { diff, guard } = guardExtractionRefresh(report, previousRows, refreshed, opts.membershipPolicy, { linkedCandidateIds });
  return {
    preview: true,
    extraction_contract: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
    document_rebuilt: documentRebuilt,
    candidates: { before: previousRows.length, after: refreshed.candidates.length },
    guard,
    membership_diff: compactRefreshMembershipDiff(diff, 100),
    quality: compactExtractionQuality(refreshed.diagnostics?.quality || null),
    ai_invoked: false
  };
}

/**
 * Worker entry for `refresh_extraction` jobs.
 * @param {import('pg').Pool} pool
 * @param {{ reportId: number, jobId: number, restoreStatus?: object, membershipPolicy?: object }} ctx
 */
export async function runExtractionRefresh(pool, ctx) {
  const report = await getReportById(pool, ctx.reportId);
  if (!report) throw Object.assign(new Error('Report not found'), { code: 'not_found' });

  const startedAt = Date.now();
  const restore = resolveRefreshRestoreStatus(ctx.restoreStatus);
  const membershipPolicy = normalizeRefreshMembershipPolicy(ctx.membershipPolicy);
  // The dispatch payload rides on every job progress write so a job re-queued
  // after a worker crash still knows its mode, the status to restore and the
  // membership policy it was requested with.
  const dispatch = {
    jobType: MODE,
    restoreStatus: restore,
    ...(membershipPolicy.mode !== 'protect' ? { membershipPolicy } : {})
  };
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

    const prepared = await prepareRefreshDocument(pool, report);
    let document = prepared.document;
    const { sourceHtml, documentRebuilt } = prepared;

    const titleUpdate = await reselectReportTitle(pool, report, { document, sourceHtml });
    document = titleUpdate.document;
    const previousRows = await loadReportCandidateRows(pool, report.id);

    await setStage('matching');
    const refreshed = await computeExtractionRefresh(pool, { report, document, previousRows, documentRebuilt });

    // Membership guard: compare before / after Indicators BEFORE anything is
    // written. A material unexpected loss is not applied unless the request
    // explicitly accepted it (policy `accept` with a reason).
    const linkedCandidateIds = await linkedRowsLeavingDocument(pool, previousRows, refreshed.candidates);
    // Authorization of an explicit acceptance is decided here (and again under
    // the row locks), from the requester's current role in the database.
    const acceptorRole = await resolveAcceptorRole(pool, membershipPolicy);
    const { diff: membershipDiff, guard } = guardExtractionRefresh(report, previousRows, refreshed, membershipPolicy, { linkedCandidateIds, acceptorRole });
    const compactDiff = compactRefreshMembershipDiff(membershipDiff);
    if (guard.decision === REFRESH_GUARD_DECISIONS.BLOCK) {
      return await blockExtractionRefresh(pool, { report, ctx, restore, priorProgress, dispatch, guard, compactDiff, startedAt });
    }

    // Time-of-use revalidation: the guard above read the review set outside
    // the write transaction. Inside it, with every candidate row of the report
    // locked, the rows must still be exactly the snapshot the refresh was
    // computed from (a concurrent review / Create IOCs / IOC Source reconcile
    // aborts with nothing written), and the guard is re-evaluated against the
    // locked state and link provenance (the accepted preview fingerprint is
    // checked again there).
    let lockedGuard = { diff: membershipDiff, guard };
    const persisted = await reconcileReportCandidates(pool, report.id, refreshed.candidates, {
      beforeWrite: async (lockedRows, client) => {
        const drift = candidateSnapshotDrift(previousRows, lockedRows);
        if (drift.length) {
          throw Object.assign(
            new Error('Candidates changed while Refresh extraction was running (review, Create IOCs or an IOC Source); nothing was saved. Run Refresh extraction again.'),
            { code: REFRESH_CONCURRENT_CHANGE_CODE, drift_count: drift.length }
          );
        }
        const lockedLinked = await linkedRowsLeavingDocument(client, lockedRows, refreshed.candidates);
        lockedGuard = guardExtractionRefresh(report, lockedRows, refreshed, membershipPolicy, { linkedCandidateIds: lockedLinked, acceptorRole });
        if (lockedGuard.guard.decision === REFRESH_GUARD_DECISIONS.BLOCK) {
          throw Object.assign(new Error(lockedGuard.guard.message), { code: REFRESH_BLOCKED_CODE, lockedGuard });
        }
      }
    });
    const compactLockedDiff = compactRefreshMembershipDiff(lockedGuard.diff);

    // Publication date is written only for an applied refresh (this run's
    // extraction read the stored date; a blocked or aborted refresh writes nothing).
    await applyPublicationDate(pool, report, { document, sourceHtml });
    const outcome = resolveRefreshOutcomeStatus(restore, persisted);
    const grounding = await applyStoredVulnerabilityGrounding(pool, report, refreshed.document);
    const publisherGrounding = await applyStoredPublisherEntityGrounding(
      pool,
      { ...report, summary: grounding.summary ?? report.summary },
      refreshed.document
    );
    const groundedSummary = publisherGrounding.summary ?? grounding.summary;

    const result = {
      document_rebuilt: documentRebuilt,
      candidates_total: refreshed.candidates.length,
      added: persisted.added.length,
      updated: persisted.updated.length,
      unchanged: persisted.unchanged,
      removed: persisted.removed.length,
      replayed_ai_decisions: refreshed.replayedAiDecisions,
      vulnerability_grounding: grounding.diagnostics,
      publisher_entity_grounding: publisherGrounding.diagnostics,
      title_changed: titleUpdate.changed,
      ...(titleUpdate.changed ? { previous_title: titleUpdate.previous_title, title_source: titleUpdate.source } : {}),
      ai_invoked: false,
      review_relevant: outcome.review_relevant,
      reopened_for_review: outcome.reopened_for_review,
      prior_status: outcome.prior_status,
      restored_status: outcome.analysis_status,
      membership_guard: membershipGuardSummary(lockedGuard.guard, compactLockedDiff)
    };
    const lastRefresh = {
      job_id: ctx.jobId,
      completed_at: new Date().toISOString(),
      extraction_contract: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
      ...result,
      added_identities: persisted.added.slice(0, 40),
      removed_identities: persisted.removed.slice(0, 40),
      membership_diff: compactLockedDiff
    };

    await updateReportStatus(pool, report.id, {
      canonical_document: refreshed.document,
      candidate_summary: refreshed.summary,
      ...(titleUpdate.changed ? { title: titleUpdate.title } : {}),
      ...(groundedSummary != null ? { summary: groundedSummary } : {}),
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
    // The guard re-evaluated against the locked rows blocked: the write
    // transaction rolled back, so this is an ordinary blocked refresh.
    if (err?.code === REFRESH_BLOCKED_CODE && err.lockedGuard) {
      return await blockExtractionRefresh(pool, {
        report,
        ctx,
        restore,
        priorProgress,
        dispatch,
        guard: err.lockedGuard.guard,
        compactDiff: compactRefreshMembershipDiff(err.lockedGuard.diff),
        startedAt
      });
    }
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

/** Compact guard outcome for job results, last_refresh and audit metadata. */
export function membershipGuardSummary(guard, compactDiff) {
  return {
    version: guard.version,
    decision: guard.decision,
    policy: guard.policy,
    material: guard.material,
    material_fingerprint: guard.material_fingerprint || null,
    reasons: guard.reasons.map((r) => ({ code: r.code, count: r.count, material: r.material })),
    authorization: guard.authorization || null,
    ...(guard.accepted
      ? {
          accepted_reason: guard.accepted.reason,
          accepted_by: guard.accepted.requested_by || null,
          accepted_by_role: guard.accepted.acceptor_role || null,
          accepted_preview_fingerprint: guard.accepted.preview_fingerprint || null
        }
      : {}),
    indicators_before: compactDiff?.indicators?.before ?? null,
    indicators_after: compactDiff?.indicators?.after ?? null,
    added_indicators: compactDiff?.counts?.added_indicators ?? 0,
    removed_indicators: compactDiff?.counts?.removed_indicators ?? 0,
    ioc_link_changes: compactDiff?.counts?.ioc_link_changes ?? 0,
    // Affected identities (bounded) so the audit trail names what an
    // acceptance covered, not only how many rows.
    affected: {
      removed_indicators: (compactDiff?.removed_indicators || []).slice(0, AUDIT_IDENTITY_LIMIT).map((r) => r.identity),
      reviewed_candidates_deleted: (compactDiff?.reviewed_candidates_deleted || []).slice(0, AUDIT_IDENTITY_LIMIT).map((r) => r.identity),
      ioc_link_changes: (compactDiff?.ioc_link_changes || []).slice(0, AUDIT_IDENTITY_LIMIT).map((r) => ({
        identity: r.identity,
        from_ioc_id: r.from_ioc_id,
        to_ioc_id: r.to_ioc_id ?? null
      }))
    }
  };
}

const AUDIT_IDENTITY_LIMIT = 40;

export const REFRESH_BLOCKED_CODE = 'refresh_membership_loss_blocked';

/**
 * A blocked refresh writes nothing to the review set: the report returns to
 * its prior status with the diff recorded on last_refresh, and the job fails
 * with a dedicated code (the worker's audit event records the guard outcome).
 */
async function blockExtractionRefresh(pool, { report, ctx, restore, priorProgress, dispatch, guard, compactDiff, startedAt }) {
  const summary = membershipGuardSummary(guard, compactDiff);
  await restoreReportStatus(pool, report.id, restore, {
    ...priorProgress,
    stage: restore.analysis_status,
    last_refresh: {
      job_id: ctx.jobId,
      blocked_at: new Date().toISOString(),
      blocked: true,
      extraction_contract: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
      error_code: REFRESH_BLOCKED_CODE,
      membership_guard: summary,
      membership_diff: compactDiff,
      ai_invoked: false
    }
  });
  await updateJob(pool, ctx.jobId, {
    status: 'failed',
    stage: 'membership_guard',
    error_message: guard.message,
    progress: {
      stage: 'membership_guard',
      mode: MODE,
      dispatch,
      failure_code: REFRESH_BLOCKED_CODE,
      membership_guard: summary,
      membership_diff: compactDiff
    }
  });
  log.warn('extraction refresh blocked by membership guard', {
    reportId: report.id,
    jobId: ctx.jobId,
    mode: MODE,
    extraction_contract: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
    reasons: summary.reasons,
    removed_indicators: summary.removed_indicators,
    restored_status: restore.analysis_status,
    elapsed_ms: Date.now() - startedAt
  });
  return {
    ok: false,
    code: REFRESH_BLOCKED_CODE,
    error: guard.message,
    summary: {
      mode: MODE,
      extraction_contract: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION,
      ai_invoked: false,
      membership_guard: summary
    }
  };
}
