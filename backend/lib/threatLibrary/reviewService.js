/**
 * Analyst review + explicit IOC creation from Threat Library candidates.
 *
 * Approve / Context only / Ignore / Approve high-confidence malicious
 * change review state only. They never create IOC records.
 *
 * Create IOCs materializes only approved, supported, new observables.
 * Finalize closes the report lifecycle and never creates IOCs.
 */

import crypto from 'node:crypto';
import { createManualIoc } from '../manualIocCreate.js';
import { getThreatLibraryIocSourceId, getReportById, updateReportStatus } from './store.js';
import {
  buildCreateIocsAuditEvent,
  buildFinalizeAuditEvent,
  buildReviewAuditEvent,
  iocCreatedOriginMetadata,
  safeErrorCategory
} from './audit.js';
import { CONFIDENCE_POLICY } from './constants.js';
import { isEligibleForHighConfidenceMalicious } from './evidencePolicy.js';
import { isFinalizeAllowed, isReviewMutationAllowed, reviewNotReadyError } from './reportPhase.js';
import {
  canExecutePromotion,
  classifyCreateEligibility,
  isNoneEligibleBlock,
  isPendingActionableCandidate,
  previewCreateIocPromotion,
  PROMOTION_OUTCOMES,
  summarizePromotionResults
} from './promotion.js';

async function findIocByTypeAndValue(pool, observableType, observable) {
  const type = String(observableType || '').toLowerCase();
  const value = String(observable || '');
  if (!type || !value) return null;
  const { rows } = await pool.query(
    `SELECT id, public_id, observable_type
     FROM ioc_items
     WHERE observable_type = $1 AND observable = $2
     ORDER BY created_at ASC, id ASC
     LIMIT 1`,
    [type, value]
  );
  return rows[0] || null;
}

async function persistPromotionRow(pool, reportId, candidateId, patch) {
  await pool.query(
    `UPDATE threat_report_candidates
     SET promotion_outcome = $3,
         promotion_detail = $4,
         promoted_at = NOW(),
         matched_ioc_id = COALESCE($5, matched_ioc_id),
         matched_ioc_observable_type = COALESCE($6, matched_ioc_observable_type),
         match_state = CASE WHEN $5 IS NOT NULL THEN 'existing' ELSE match_state END,
         updated_at = NOW()
     WHERE report_id = $1 AND id = $2`,
    [
      reportId,
      candidateId,
      patch.outcome,
      patch.detail || null,
      patch.ioc_id ?? null,
      patch.observable_type || null
    ]
  );
}

async function linkCandidateRelationships(pool, reportId, candidateId, iocId) {
  await pool.query(
    `UPDATE threat_relationships SET object_ioc_id = $2
     WHERE report_id = $3 AND object_candidate_id = $1 AND object_ioc_id IS NULL`,
    [candidateId, iocId, reportId]
  );
  await pool.query(
    `UPDATE threat_relationships SET subject_ioc_id = $2
     WHERE report_id = $3 AND subject_candidate_id = $1 AND subject_ioc_id IS NULL`,
    [candidateId, iocId, reportId]
  );
}

/**
 * Write one audit row for a user-initiated review operation. Audit failures
 * are observable (auditLogService logs them) but never fail the operation.
 */
async function emitAudit(opts, event) {
  if (!event || typeof opts?.audit?.auditLog !== 'function') return;
  try {
    await opts.audit.auditLog({ req: opts.req, actor: opts.user, ...event });
  } catch {
    /* auditLogService already reports insert failures */
  }
}

/**
 * @param {import('pg').Pool} pool
 * @param {number} reportId
 * @param {{
 *   candidateIds?: number[],
 *   action: 'approve'|'context_only'|'ignore'|'create_iocs'|'approve_high_confidence_malicious',
 *   confirm?: boolean,
 *   user?: object,
 *   audit?: object,
 *   createIoc?: Function,
 *   findExistingIoc?: Function
 * }} opts
 */
export async function applyCandidateReviewActions(pool, reportId, opts) {
  const action = opts.action;
  const report = await getReportById(pool, reportId);
  if (!report) return { ok: false, status: 404, error: 'Report not found' };
  // The candidate set is rewritten by the pipeline until review_required; a
  // decision applied to a moving set would be lost or land on the wrong row.
  if (!isReviewMutationAllowed(report)) return reviewNotReadyError(report);

  let ids = Array.isArray(opts.candidateIds) ? opts.candidateIds.map(Number).filter((n) => n > 0) : [];

  if (action === 'approve_high_confidence_malicious') {
    const { rows } = await pool.query(
      `SELECT * FROM threat_report_candidates
       WHERE report_id = $1
         AND assessment = 'malicious'
         AND confidence IS NOT NULL AND confidence >= $2
         AND review_status = 'pending'`,
      [reportId, CONFIDENCE_POLICY.AUTO_APPROVE_SUGGEST]
    );
    ids = rows
      .filter((r) => {
        const ev = r.evidence && typeof r.evidence === 'object' ? r.evidence : {};
        if (ev.is_parser_derived_metadata === true || r.is_ioc === false) return false;
        const occurrences = Array.isArray(ev.occurrences) && ev.occurrences.length
          ? ev.occurrences
          : r.section
            ? [{ zone: r.section, section_kind: r.section }]
            : [];
        return isEligibleForHighConfidenceMalicious({
          ...r,
          is_ioc: true,
          zone: r.section,
          policy_decision: ev.policy_decision || undefined,
          occurrences
        });
      })
      .map((r) => Number(r.id));
  }

  if (!ids.length && action !== 'finalize') {
    return { ok: false, status: 400, error: 'No candidates selected' };
  }

  if (action === 'create_iocs') {
    return createIocsFromCandidates(pool, report, ids, opts);
  }

  if (!['approve', 'approve_high_confidence_malicious', 'context_only', 'ignore'].includes(action)) {
    return { ok: false, status: 400, error: 'Unknown action' };
  }

  // Pre-update snapshot of the selection: the grouped audit event reports
  // changed vs already-in-state counts and the type distribution from it.
  const { rows: selectedBefore } = await pool.query(
    `SELECT id, candidate_type, review_status FROM threat_report_candidates
     WHERE report_id = $1 AND id = ANY($2::bigint[])`,
    [reportId, ids]
  );

  if (action === 'approve' || action === 'approve_high_confidence_malicious') {
    // Non-IOC artifacts (mutex names, relative paths, code identifiers) are
    // context rows: they can never be approved into the IOC set.
    await pool.query(
      `UPDATE threat_report_candidates SET review_status = 'approved', updated_at = NOW()
       WHERE report_id = $1 AND id = ANY($2::bigint[]) AND is_ioc = true`,
      [reportId, ids]
    );
  } else if (action === 'context_only') {
    await pool.query(
      `UPDATE threat_report_candidates
       SET review_status = 'context_only', assessment = 'context_only', match_state = 'context_only', updated_at = NOW()
       WHERE report_id = $1 AND id = ANY($2::bigint[])`,
      [reportId, ids]
    );
  } else if (action === 'ignore') {
    await pool.query(
      `UPDATE threat_report_candidates SET review_status = 'ignored', updated_at = NOW()
       WHERE report_id = $1 AND id = ANY($2::bigint[])`,
      [reportId, ids]
    );
  }

  await emitAudit(opts, buildReviewAuditEvent({
    report,
    action,
    requestedIds: ids,
    candidates: selectedBefore,
    user: opts.user
  }));

  return { ok: true, updated: ids.length };
}

async function createIocsFromCandidates(pool, report, ids, opts) {
  const { rows: candidates } = await pool.query(
    `SELECT * FROM threat_report_candidates
     WHERE report_id = $1 AND id = ANY($2::bigint[])`,
    [report.id, ids]
  );
  const ordered = ids.map((id) => candidates.find((c) => Number(c.id) === Number(id))).filter(Boolean);
  const preview = previewCreateIocPromotion(ordered);

  if (isNoneEligibleBlock(preview.summary)) {
    return {
      ok: false,
      status: 409,
      code: 'create_iocs_none_eligible',
      error: 'Only approved indicators can be created as IOCs. Review and approve the selected indicators before creating IOC records.',
      summary: preview.summary,
      results: preview.results
    };
  }

  if (opts.confirm !== true) {
    return {
      ok: true,
      preview: true,
      summary: preview.summary,
      results: preview.results
    };
  }

  if (!canExecutePromotion(preview.summary)) {
    return {
      ok: false,
      status: 409,
      code: 'create_iocs_none_eligible',
      error: 'Only approved indicators can be created as IOCs. Review and approve the selected indicators before creating IOC records.',
      summary: preview.summary,
      results: preview.results
    };
  }

  const sourceId = await getThreatLibraryIocSourceId(pool);
  if (!sourceId) return { ok: false, status: 500, error: 'Threat Library IOC source missing' };

  const createIoc = opts.createIoc || createManualIoc;
  const findExisting = opts.findExistingIoc || findIocByTypeAndValue;
  // Correlates the parent bulk audit event with every ioc.created row it produced.
  const operationId = opts.operationId || crypto.randomUUID();
  const created = [];
  const errors = [];
  const results = [];
  const ctx = { createIoc, findExisting, sourceId, operationId, opts, created, errors, results };

  for (const candidate of ordered) {
    const classified = classifyCreateEligibility(candidate);
    if (classified.outcome === PROMOTION_OUTCOMES.WILL_CREATE) {
      try {
        await promoteCandidate(pool, report, candidate, ctx);
      } catch (err) {
        // A thrown error must not abort the batch or hide already-committed rows:
        // record this candidate as failed with a safe category and continue.
        const message = `create failed (${safeErrorCategory(err)})`;
        try {
          await persistPromotionRow(pool, report.id, candidate.id, {
            outcome: PROMOTION_OUTCOMES.FAILED,
            detail: message
          });
        } catch {
          /* row state stays as-is; the audit summary still counts the failure */
        }
        errors.push({ candidate_id: candidate.id, message });
        results.push({ candidate_id: candidate.id, outcome: PROMOTION_OUTCOMES.FAILED, detail: message });
      }
      continue;
    }

    await persistPromotionRow(pool, report.id, candidate.id, {
      outcome: classified.outcome,
      detail: classified.detail || null,
      ioc_id: classified.ioc_id ?? null,
      observable_type: classified.ioc_id
        ? (candidate.matched_ioc_observable_type || candidate.candidate_type)
        : null
    });
    results.push({
      candidate_id: candidate.id,
      outcome: classified.outcome,
      ioc_id: classified.ioc_id ?? null,
      detail: classified.detail || null
    });
  }

  const summary = summarizePromotionResults(results);
  summary.selected = ordered.length;
  summary.eligible = preview.summary.eligible;

  // Every row above is persisted (autocommit) before this event is written, so
  // the audit describes committed state, not intent.
  await emitAudit(opts, buildCreateIocsAuditEvent({
    report,
    summary,
    results,
    candidates: ordered,
    operationId,
    user: opts.user
  }));

  return { ok: true, preview: false, summary, results, created, errors, operation_id: operationId };
}

/** Create-or-link one eligible candidate; records its outcome in `ctx.results`. */
async function promoteCandidate(pool, report, candidate, ctx) {
  const { createIoc, findExisting, sourceId, operationId, opts, created, errors, results } = ctx;
  const existingDetail = 'An IOC record already exists for this indicator.';

  async function linkExisting(existing) {
    await persistPromotionRow(pool, report.id, candidate.id, {
      outcome: PROMOTION_OUTCOMES.ALREADY_EXISTING,
      detail: existingDetail,
      ioc_id: Number(existing.id),
      observable_type: existing.observable_type || candidate.candidate_type
    });
    await linkCandidateRelationships(pool, report.id, candidate.id, Number(existing.id));
    results.push({
      candidate_id: candidate.id,
      outcome: PROMOTION_OUTCOMES.ALREADY_EXISTING,
      ioc_id: Number(existing.id),
      detail: existingDetail
    });
  }

  let existing = await findExisting(pool, candidate.candidate_type, candidate.normalized_value);
  if (existing) {
    await linkExisting(existing);
    return;
  }

  const result = await createIoc(
    pool,
    {
      observable: candidate.normalized_value,
      source_id: sourceId,
      confidence: candidate.confidence != null && candidate.confidence >= 0.85 ? 'high' : 'medium',
      note: `Threat Library report ${report.public_id}: ${candidate.role || 'unknown'} (${candidate.assessment})`,
      source_url: report.source_url || null
    },
    {
      user: opts.user,
      audit: opts.audit,
      // `req` lets createManualIoc emit its own ioc.created row (actor, IP,
      // request id); the origin metadata ties that row back to this report.
      req: opts.req,
      auditMetadata: iocCreatedOriginMetadata({ report, candidate, operationId, user: opts.user })
    }
  );

  if (result.status >= 200 && result.status < 300 && result.body?.id) {
    await persistPromotionRow(pool, report.id, candidate.id, {
      outcome: PROMOTION_OUTCOMES.CREATED,
      detail: null,
      ioc_id: result.body.id,
      observable_type: result.body.observable_type || candidate.candidate_type
    });
    await linkCandidateRelationships(pool, report.id, candidate.id, result.body.id);
    created.push({ candidate_id: candidate.id, ioc_id: result.body.id, public_id: result.body.public_id });
    results.push({
      candidate_id: candidate.id,
      outcome: PROMOTION_OUTCOMES.CREATED,
      ioc_id: result.body.id
    });
    return;
  }

  if (result.body?.skipped && result.body?.reason === 'duplicate_tuple') {
    existing = await findExisting(pool, candidate.candidate_type, candidate.normalized_value);
    if (existing) {
      await linkExisting(existing);
      return;
    }
  }

  const message = result.body?.message || `create failed (${result.status})`;
  await persistPromotionRow(pool, report.id, candidate.id, {
    outcome: PROMOTION_OUTCOMES.FAILED,
    detail: message
  });
  errors.push({ candidate_id: candidate.id, message });
  results.push({
    candidate_id: candidate.id,
    outcome: PROMOTION_OUTCOMES.FAILED,
    detail: message
  });
}

/**
 * Finalize report after review (marks ready/imported without creating IOCs implicitly).
 * Blocked while any actionable indicator is still pending analyst review.
 */
export async function finalizeReport(pool, reportId, opts = {}) {
  const report = await getReportById(pool, reportId);
  if (!report) return { ok: false, status: 404, error: 'Report not found' };
  if (!isFinalizeAllowed(report)) return reviewNotReadyError(report);

  const { rows: candidates } = await pool.query(
    `SELECT * FROM threat_report_candidates WHERE report_id = $1`,
    [reportId]
  );
  const pendingCount = candidates.filter((c) => isPendingActionableCandidate(c)).length;
  if (pendingCount > 0) {
    return {
      ok: false,
      status: 409,
      code: 'pending_review_remaining',
      pending_count: pendingCount,
      error: `${pendingCount} indicator${pendingCount === 1 ? '' : 's'} still need review.`
    };
  }

  await updateReportStatus(pool, reportId, {
    import_status: 'ready',
    analysis_status: 'ready',
    finalize: true
  });
  await emitAudit(opts, buildFinalizeAuditEvent({ report, candidates, user: opts.user }));
  return { ok: true };
}
