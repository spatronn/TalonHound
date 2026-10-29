/**
 * MCP Threat Library post-import lifecycle tools.
 *
 * Thin adapters over the same application services the UI uses:
 *   - applyCandidateReviewActions / finalizeReport (reviewService.js)
 *   - approveLinkedIocSource / dismissLinkedIocSource (iocSources/analystActions.js)
 *   - loadReportSnapshot + membership buckets (same as get_threat_report)
 *
 * Never invents parallel approval, Create IOCs or finalization rules.
 */

import { mcpActorAuditFields } from '../mcpIocService.js';
import { applyCandidateReviewActions, finalizeReport } from './reviewService.js';
import { finalizeBlockers, linkedSourceBlocker, loadReportSources } from './finalizeGuard.js';
import {
  classifyCreateEligibility,
  publicPromoteEligibility,
  asPromotedRow,
  isPendingActionableCandidate,
  PROMOTION_OUTCOMES,
  previewCreateIocPromotion
} from './promotion.js';
import {
  countCandidateBuckets,
  isContextOnlyCandidate,
  isUnionReportIndicatorMember,
  linkedSourceProvenanceColumnSql
} from './indicatorMembership.js';
import {
  getReportByPublicId,
  loadReportLinkedSourceCandidateIds,
  loadReportSnapshot
} from './store.js';
import { loadLinkedIocSourceSummary, withLinkedSourceQuality } from './iocSources/linkedSourceStatus.js';
import {
  listIocSourcesForReport,
  listSourceFiles,
  publicIocSource,
  summarizeIocSources
} from './iocSources/store.js';
import { approveLinkedIocSource, dismissLinkedIocSource } from './iocSources/analystActions.js';
import {
  isFinalizeAllowed,
  isReviewMutationAllowed,
  REPORT_PHASES,
  resolveReportPhase
} from './reportPhase.js';
import { extractionQualitySummary, storedExtractionQuality } from './extractionQuality.js';
import { TLP_DISPLAY } from './constants.js';
import { serializePublicationDate } from './publicationDate.js';
import {
  isThreatReportId,
  serializeThreatReportIndicator,
  THREAT_REPORT_READABLE_IMPORT_STATUSES,
  withLinkedSourceProvenance,
  clampIndicatorPage
} from './mcpThreatReport.js';
import { serializeImportJobState, serializeImportReportState } from '../mcpThreatLibraryImportService.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LINKED_PROVENANCE_SQL = linkedSourceProvenanceColumnSql('');

const REVIEW_ACTIONS = Object.freeze([
  'approve',
  'context_only',
  'ignore',
  'approve_high_confidence_malicious',
  'promote_to_ioc'
]);

const REVIEW_STATUS_FILTERS = Object.freeze([
  'all',
  'pending',
  'approved',
  'context_only',
  'ignored',
  'created_ioc'
]);

function iso(v) {
  if (!v) return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

function reportRevision(report, candidates) {
  // Stale-mutation guard for MCP clients. updated_at + roster size is enough to
  // reject an apply that races a concurrent UI/MCP reviewer without inventing
  // a new DB column.
  return `${iso(report.updated_at) || '0'}|${Array.isArray(candidates) ? candidates.length : 0}`;
}

function invalidReportId() {
  return { status: 400, error: { code: 'INVALID_REPORT_ID', message: 'report_id must be a Threat Library report uuid' } };
}

function notFound() {
  return { status: 404, error: { code: 'NOT_FOUND', message: 'Threat report not found' } };
}

function notReadable(report) {
  return {
    status: 409,
    error: {
      code: 'REPORT_NOT_READY',
      message: `Threat report is not readable yet (import_status=${report.import_status})`
    }
  };
}

function staleRevision(expected, actual) {
  return {
    status: 409,
    error: {
      code: 'STALE_REPORT',
      message: 'Report state changed since the client last read it. Re-read with threat_library_get_review and retry.',
      expected_revision: expected,
      report_revision: actual
    }
  };
}

async function loadLatestJob(pool, reportId) {
  const { rows } = await pool.query(
    `SELECT public_id, job_type, status, stage, bullmq_job_id, error_message, created_at, finished_at
     FROM threat_library_jobs WHERE report_id = $1 ORDER BY id DESC LIMIT 1`,
    [reportId]
  );
  return rows[0] || null;
}

async function resolveReport(pool, reportIdArg) {
  const id = String(reportIdArg || '').trim();
  if (!isThreatReportId(id)) return { error: invalidReportId() };
  const report = await getReportByPublicId(pool, id);
  if (!report) return { error: notFound() };
  return { report };
}

async function loadReviewSnapshot(pool, report) {
  const snapshot = await loadReportSnapshot(pool, report.id);
  const linked = await loadReportLinkedSourceCandidateIds(pool, report.id);
  snapshot.candidates = withLinkedSourceProvenance(snapshot.candidates, linked);
  try {
    snapshot.linkedSources = await loadLinkedIocSourceSummary(pool, report.id);
  } catch {
    snapshot.linkedSources = null;
  }
  try {
    snapshot.iocSourceSummary = await summarizeIocSources(pool, report.id);
  } catch {
    snapshot.iocSourceSummary = { total: 0, discovered_pending: 0, attached: 0, extracted: 0, failed: 0 };
  }
  snapshot.iocSources = await listIocSourcesForReport(pool, report.id);
  return snapshot;
}

function reviewDecisionOf(c) {
  const raw = String(c?.review_status || 'pending').toLowerCase();
  return raw === 'created_ioc' ? 'approved' : raw;
}

function countReviewDecisions(candidates) {
  const out = {
    pending: 0,
    approved: 0,
    context_only: 0,
    ignored: 0,
    pending_actionable: 0,
    approved_indicators: 0,
    creatable: 0,
    already_existing_ioc: 0,
    matched_ioc: 0
  };
  for (const c of candidates) {
    const decision = reviewDecisionOf(c);
    if (decision === 'pending') out.pending += 1;
    else if (decision === 'approved') out.approved += 1;
    else if (decision === 'context_only' || isContextOnlyCandidate(c)) out.context_only += 1;
    else if (decision === 'ignored') out.ignored += 1;

    if (isPendingActionableCandidate(c)) out.pending_actionable += 1;
    if (isUnionReportIndicatorMember(c) && (decision === 'approved')) out.approved_indicators += 1;
    if (c.matched_ioc_id) out.matched_ioc += 1;

    const elig = classifyCreateEligibility(c);
    if (elig.outcome === PROMOTION_OUTCOMES.WILL_CREATE) out.creatable += 1;
    if (elig.outcome === PROMOTION_OUTCOMES.ALREADY_EXISTING) out.already_existing_ioc += 1;
  }
  return out;
}

function serializeReviewCandidate(c) {
  const base = serializeThreatReportIndicator(c);
  const elig = classifyCreateEligibility(c);
  const ev = c.evidence && typeof c.evidence === 'object' ? c.evidence : {};
  const union = isUnionReportIndicatorMember(c);
  const linked = c.has_linked_source_occurrence === true;
  return {
    ...base,
    // Numeric id kept for clients that already hold UI selection ids; UUID is primary.
    candidate_id: Number(c.id),
    review_decision: reviewDecisionOf(c),
    indicator_membership: union,
    // Original-document occurrence flag from the snapshot (false = linked-only row).
    original_document_member: c.has_original_document_occurrence !== false && union,
    linked_source_member: linked,
    linked_only_member: linked && union && c.has_original_document_occurrence === false,
    source_assertion: c.source_assertion || ev.source_assertion || null,
    promotion_outcome: c.promotion_outcome || null,
    promotion_detail: c.promotion_detail || null,
    create_eligibility: elig.outcome,
    create_eligibility_detail: elig.detail || null,
    publisher_evidence: ev.policy_decision || ev.decision_source
      ? {
          policy_decision: ev.policy_decision || null,
          decision_source: ev.decision_source || null,
          occurrence_count: Number.isFinite(Number(ev.occurrence_count)) ? Number(ev.occurrence_count) : null
        }
      : null
  };
}

function filterCandidates(candidates, { review_status, membership } = {}) {
  let rows = candidates;
  const status = String(review_status || 'all').toLowerCase();
  if (status !== 'all' && REVIEW_STATUS_FILTERS.includes(status)) {
    rows = rows.filter((c) => {
      if (status === 'context_only') return isContextOnlyCandidate(c) || reviewDecisionOf(c) === 'context_only';
      if (status === 'approved') return reviewDecisionOf(c) === 'approved';
      if (status === 'pending') return reviewDecisionOf(c) === 'pending';
      if (status === 'ignored') return reviewDecisionOf(c) === 'ignored';
      if (status === 'created_ioc') return String(c.review_status || '').toLowerCase() === 'created_ioc';
      return true;
    });
  }
  const mem = String(membership || 'all').toLowerCase();
  if (mem === 'indicators' || mem === 'union') {
    rows = rows.filter((c) => isUnionReportIndicatorMember(c));
  } else if (mem === 'pending_actionable') {
    rows = rows.filter((c) => isPendingActionableCandidate(c));
  } else if (mem === 'creatable') {
    rows = rows.filter((c) => classifyCreateEligibility(c).outcome === PROMOTION_OUTCOMES.WILL_CREATE);
  } else if (mem === 'linked_only') {
    rows = rows.filter((c) => c.has_linked_source_occurrence === true && isUnionReportIndicatorMember(c));
  }
  return rows;
}

function gatesFromSnapshot(report, candidates, linkedSources) {
  const phase = resolveReportPhase(report);
  const decisions = countReviewDecisions(candidates);
  const reviewReady = isReviewMutationAllowed(report);
  // Eligibility over the full roster — same classifyCreateEligibility the UI uses.
  const allPreview = previewCreateIocPromotion(candidates);
  const pendingSources = Number(linkedSources?.pending || 0) + Number(linkedSources?.unresolved || 0);
  const createPermitted = reviewReady && allPreview.summary.eligible > 0;
  const finalizeBlocked = [];
  if (!isFinalizeAllowed(report)) {
    finalizeBlocked.push({
      code: 'report_not_ready_for_review',
      message: phase === REPORT_PHASES.FAILED
        ? 'Analysis failed before the final indicator set was prepared.'
        : 'The indicator set is still being refined.'
    });
  }
  if (decisions.pending_actionable > 0) {
    finalizeBlocked.push({
      code: 'pending_review_remaining',
      message: `${decisions.pending_actionable} indicator${decisions.pending_actionable === 1 ? '' : 's'} still need review.`,
      pending_count: decisions.pending_actionable
    });
  }
  // Same linked-source rule the finalize write enforces (finalizeGuard.js).
  const sourceBlocker = linkedSourceBlocker(linkedSources);
  if (sourceBlocker) finalizeBlocked.push(sourceBlocker);
  return {
    review_phase: phase,
    review_mutations_permitted: reviewReady,
    create_iocs_permitted: createPermitted,
    create_iocs_eligible_count: allPreview.summary.eligible,
    create_iocs_preview_summary: allPreview.summary,
    finalize_permitted: finalizeBlocked.length === 0 && phase === REPORT_PHASES.REVIEW_READY,
    finalize_blockers: finalizeBlocked,
    linked_ioc_sources_pending: pendingSources,
    // Quality never blocks finalize (same as UI); surfaced as warnings only.
    quality_blocks_finalize: false
  };
}

async function serializeLinkedSources(pool, rows) {
  const out = [];
  for (const row of rows || []) {
    let files = null;
    try {
      files = await listSourceFiles(pool, row.id);
    } catch {
      files = null;
    }
    out.push(publicIocSource({ ...row, report_public_id: row.report_public_id }, files));
  }
  return out;
}

/**
 * Resolve MCP candidate_ids (numeric or candidate public UUID) to numeric ids
 * for reviewService.
 */
async function resolveCandidateIds(pool, reportId, rawIds) {
  if (!Array.isArray(rawIds) || !rawIds.length) return { ok: true, ids: [] };
  const numeric = [];
  const uuids = [];
  for (const raw of rawIds) {
    if (typeof raw === 'number' && Number.isInteger(raw) && raw > 0) {
      numeric.push(raw);
      continue;
    }
    const s = String(raw ?? '').trim();
    if (/^\d+$/.test(s)) {
      numeric.push(Number(s));
      continue;
    }
    if (UUID_RE.test(s)) {
      uuids.push(s);
      continue;
    }
    return {
      ok: false,
      status: 400,
      error: { code: 'INVALID_CANDIDATE_ID', message: `Invalid candidate id: ${s}` }
    };
  }
  const ids = [...numeric];
  if (uuids.length) {
    const { rows } = await pool.query(
      `SELECT id, public_id FROM threat_report_candidates
       WHERE report_id = $1 AND public_id = ANY($2::uuid[])`,
      [reportId, uuids]
    );
    const found = new Map(rows.map((r) => [String(r.public_id), Number(r.id)]));
    for (const u of uuids) {
      const id = found.get(u);
      if (!id) {
        return {
          ok: false,
          status: 404,
          error: { code: 'CANDIDATE_NOT_FOUND', message: `Candidate not found on this report: ${u}` }
        };
      }
      ids.push(id);
    }
  }
  // Stable unique order.
  const seen = new Set();
  const unique = [];
  for (const id of ids) {
    if (!seen.has(id)) {
      seen.add(id);
      unique.push(id);
    }
  }
  return { ok: true, ids: unique };
}

function mapServiceFailure(result) {
  return {
    status: result.status || 400,
    error: {
      code: result.code || 'REVIEW_FAILED',
      message: result.error || 'Review action failed',
      phase: result.phase || undefined,
      pending_count: result.pending_count,
      blockers: result.blockers,
      linked_sources: result.linked_sources,
      summary: result.summary,
      results: result.results,
      matching: result.matching,
      eligible: result.eligible,
      ineligible: result.ineligible,
      excluded: result.excluded,
      scope_token: result.scope_token
    }
  };
}

function reviewActorContext(ctx) {
  const req = ctx.req || null;
  const user = ctx.user || req?.user || null;
  const actorFields = mcpActorAuditFields(ctx.mcpAuth || req?.mcpAuth, user);
  return { req, user, actorFields, audit: ctx.audit || null };
}

/**
 * threat_library_get_review
 */
export async function mcpThreatLibraryGetReview(pool, args = {}) {
  const resolved = await resolveReport(pool, args.report_id);
  if (resolved.error) return resolved.error;
  const { report } = resolved;
  if (!THREAT_REPORT_READABLE_IMPORT_STATUSES.includes(String(report.import_status || ''))) {
    return notReadable(report);
  }

  const snapshot = await loadReviewSnapshot(pool, report);
  const buckets = countCandidateBuckets(snapshot.candidates);
  const decisions = countReviewDecisions(snapshot.candidates);
  const gates = gatesFromSnapshot(report, snapshot.candidates, snapshot.linkedSources);
  const filtered = filterCandidates(snapshot.candidates, {
    review_status: args.review_status,
    membership: args.membership
  });
  const { limit, offset } = clampIndicatorPage({
    limit: args.limit ?? args.candidate_limit,
    offset: args.offset ?? args.candidate_offset
  });
  const pageRows = filtered.slice(offset, offset + limit);
  const quality = extractionQualitySummary(
    withLinkedSourceQuality(storedExtractionQuality(report), snapshot.linkedSources || null)
  );

  return {
    status: 200,
    body: {
      report_id: report.public_id,
      report: {
        id: report.public_id,
        title: report.title ?? null,
        source_name: report.source_name ?? null,
        source_type: report.source_type ?? null,
        source_url: report.source_url ?? null,
        publisher: report.source_name ?? null,
        ...serializePublicationDate(report),
        tlp: report.tlp ?? null,
        tlp_display: report.tlp ? (TLP_DISPLAY[report.tlp] || `TLP:${String(report.tlp).toUpperCase()}`) : null,
        import_status: report.import_status ?? null,
        analysis_status: report.analysis_status ?? null,
        review_phase: resolveReportPhase(report),
        finalized_at: iso(report.finalized_at),
        updated_at: iso(report.updated_at),
        created_at: iso(report.created_at)
      },
      report_revision: reportRevision(report, snapshot.candidates),
      counts: {
        all: buckets.all,
        indicators: buckets.indicators,
        total_unique: buckets.total_unique,
        linked_only: buckets.linked_only,
        context_only: buckets.context_only,
        ...decisions,
        linked_ioc_sources: snapshot.linkedSources || null,
        ioc_source_summary: snapshot.iocSourceSummary || null
      },
      gates: {
        create_iocs_permitted: gates.create_iocs_permitted,
        create_iocs_eligible_count: gates.create_iocs_eligible_count,
        finalize_permitted: gates.finalize_permitted,
        finalize_blockers: gates.finalize_blockers,
        review_mutations_permitted: gates.review_mutations_permitted,
        linked_ioc_sources_pending: gates.linked_ioc_sources_pending,
        quality_blocks_finalize: gates.quality_blocks_finalize
      },
      extraction_quality: quality,
      linked_ioc_sources: await serializeLinkedSources(pool, snapshot.iocSources),
      candidates: {
        total: filtered.length,
        offset,
        limit,
        returned: pageRows.length,
        has_more: offset + pageRows.length < filtered.length,
        filter: {
          review_status: args.review_status || 'all',
          membership: args.membership || 'all'
        },
        items: pageRows.map(serializeReviewCandidate)
      }
    }
  };
}

/**
 * threat_library_get_workflow_status — read-only lifecycle map.
 */
export async function mcpThreatLibraryGetWorkflowStatus(pool, args = {}) {
  const resolved = await resolveReport(pool, args.report_id);
  if (resolved.error) return resolved.error;
  const { report } = resolved;
  const phase = resolveReportPhase(report);
  const job = await loadLatestJob(pool, report.id);

  let candidates = [];
  let linkedSources = null;
  let iocSourceSummary = null;
  if (THREAT_REPORT_READABLE_IMPORT_STATUSES.includes(String(report.import_status || ''))) {
    const snapshot = await loadReviewSnapshot(pool, report);
    candidates = snapshot.candidates;
    linkedSources = snapshot.linkedSources;
    iocSourceSummary = snapshot.iocSourceSummary;
  }
  const decisions = countReviewDecisions(candidates);
  const gates = candidates.length || phase === REPORT_PHASES.REVIEW_READY || phase === REPORT_PHASES.FINALIZED
    ? gatesFromSnapshot(report, candidates, linkedSources)
    : {
        review_mutations_permitted: false,
        create_iocs_permitted: false,
        create_iocs_eligible_count: 0,
        finalize_permitted: false,
        finalize_blockers: [{ code: 'report_not_ready_for_review', message: 'Report is not review-ready yet.' }],
        linked_ioc_sources_pending: Number(linkedSources?.pending || 0) + Number(linkedSources?.unresolved || 0)
      };

  const stages = [
    {
      id: 'import',
      label: 'Import',
      status: report.id ? (phase === REPORT_PHASES.FAILED && !report.source_url ? 'failed' : 'completed') : 'pending'
    },
    {
      id: 'extraction',
      label: 'Extraction / analysis',
      status: phase === REPORT_PHASES.PREPARING
        ? 'in_progress'
        : phase === REPORT_PHASES.FAILED
          ? 'failed'
          : 'completed'
    },
    {
      id: 'review',
      label: 'Candidate review',
      status: phase === REPORT_PHASES.PREPARING || phase === REPORT_PHASES.FAILED
        ? 'blocked'
        : decisions.pending_actionable > 0
          ? 'in_progress'
          : phase === REPORT_PHASES.FINALIZED || decisions.pending_actionable === 0
            ? 'completed'
            : 'pending'
    },
    {
      id: 'create_iocs',
      label: 'Create IOCs',
      status: !gates.create_iocs_permitted && decisions.creatable === 0 && decisions.already_existing_ioc >= 0
        && decisions.pending_actionable === 0 && phase !== REPORT_PHASES.PREPARING
        ? (decisions.matched_ioc > 0 || decisions.already_existing_ioc > 0 || decisions.creatable === 0
          ? (gates.create_iocs_eligible_count > 0 ? 'pending' : 'completed')
          : 'pending')
        : gates.create_iocs_permitted
          ? 'pending'
          : phase === REPORT_PHASES.PREPARING || phase === REPORT_PHASES.FAILED
            ? 'blocked'
            : 'completed'
    },
    {
      id: 'finalize',
      label: 'Finalize report',
      status: phase === REPORT_PHASES.FINALIZED
        ? 'completed'
        : gates.finalize_permitted
          ? 'pending'
          : phase === REPORT_PHASES.PREPARING || phase === REPORT_PHASES.FAILED
            ? 'blocked'
            : 'blocked'
    }
  ];

  // Normalize create_iocs stage: pending when eligible creates remain; completed otherwise once review done.
  const createStage = stages.find((s) => s.id === 'create_iocs');
  if (createStage && phase !== REPORT_PHASES.PREPARING && phase !== REPORT_PHASES.FAILED) {
    createStage.status = gates.create_iocs_eligible_count > 0 ? 'pending' : 'completed';
  }

  const current = stages.find((s) => s.status === 'in_progress')
    || stages.find((s) => s.status === 'pending')
    || stages.find((s) => s.status === 'blocked')
    || stages[stages.length - 1];

  const remaining = [];
  if (phase === REPORT_PHASES.PREPARING) {
    remaining.push({ action: 'wait_extraction', tool: 'get_threat_library_import_status', detail: 'Poll until ingestion_complete.' });
  }
  if (gates.linked_ioc_sources_pending > 0) {
    remaining.push({
      action: 'review_ioc_sources',
      tool: 'threat_library_review_ioc_source',
      detail: `${gates.linked_ioc_sources_pending} linked IOC Source(s) still pending or unresolved.`
    });
  }
  if (decisions.pending_actionable > 0) {
    remaining.push({
      action: 'review_candidates',
      tool: 'threat_library_review_iocs',
      detail: `${decisions.pending_actionable} actionable indicator(s) still pending.`
    });
  }
  if (gates.create_iocs_eligible_count > 0) {
    remaining.push({
      action: 'create_iocs',
      tool: 'threat_library_create_iocs',
      detail: `${gates.create_iocs_eligible_count} approved indicator(s) eligible for Create IOCs.`
    });
  }
  if (gates.finalize_permitted) {
    remaining.push({ action: 'finalize', tool: 'threat_library_finalize_report', detail: 'Report is ready to finalize.' });
  }

  return {
    status: 200,
    body: {
      report_id: report.public_id,
      report: serializeImportReportState(report),
      latest_job: serializeImportJobState(job),
      finalized: phase === REPORT_PHASES.FINALIZED,
      current_stage: current?.id || null,
      stages,
      completed_stages: stages.filter((s) => s.status === 'completed').map((s) => s.id),
      remaining_actions: remaining,
      blockers: gates.finalize_blockers || [],
      counts: {
        pending_actionable: decisions.pending_actionable,
        creatable: gates.create_iocs_eligible_count,
        approved: decisions.approved,
        linked_ioc_sources: linkedSources,
        ioc_source_summary: iocSourceSummary
      },
      gates: {
        create_iocs_permitted: gates.create_iocs_permitted,
        finalize_permitted: gates.finalize_permitted,
        review_mutations_permitted: gates.review_mutations_permitted
      },
      next_steps: remaining.map((r) => r.detail)
    }
  };
}

async function assertOptionalRevision(pool, report, expected) {
  if (expected == null || expected === '') return null;
  const snapshot = await loadReviewSnapshot(pool, report);
  const actual = reportRevision(report, snapshot.candidates);
  if (String(expected) !== actual) return staleRevision(String(expected), actual);
  return null;
}

/**
 * threat_library_review_iocs
 */
export async function mcpThreatLibraryReviewIocs(pool, args = {}, ctx = {}) {
  const resolved = await resolveReport(pool, args.report_id);
  if (resolved.error) return resolved.error;
  const { report } = resolved;

  const action = String(args.action || '').trim();
  if (!REVIEW_ACTIONS.includes(action)) {
    return {
      status: 400,
      error: {
        code: 'INVALID_ACTION',
        message: `action must be one of: ${REVIEW_ACTIONS.join(', ')}`
      }
    };
  }

  const stale = await assertOptionalRevision(pool, report, args.expected_revision);
  if (stale) return stale;

  const { req, user, actorFields, audit } = reviewActorContext(ctx);
  const dryRun = args.dry_run === true || args.preview === true;

  let candidateIds;
  if (args.selection?.mode === 'all_matching') {
    candidateIds = undefined;
  } else {
    const resolvedIds = await resolveCandidateIds(pool, report.id, args.candidate_ids);
    if (!resolvedIds.ok) return { status: resolvedIds.status, error: resolvedIds.error };
    candidateIds = resolvedIds.ids;
    if (!candidateIds.length && action !== 'approve_high_confidence_malicious') {
      return {
        status: 400,
        error: {
          code: 'CANDIDATE_IDS_REQUIRED',
          message: 'Provide candidate_ids (numeric or candidate UUID) or an all_matching selection. Broad approval without an explicit set is not allowed.'
        }
      };
    }
  }

  // promote_to_ioc always materializes; dry_run only reports eligibility.
  if (action === 'promote_to_ioc' && dryRun) {
    if (!candidateIds || candidateIds.length !== 1) {
      return {
        status: 400,
        error: {
          code: 'promote_single_row_only',
          message: 'Promote to IOC is a single-row action: select exactly one Context Only indicator.'
        }
      };
    }
    const { rows } = await pool.query(
      `SELECT *, ${LINKED_PROVENANCE_SQL} FROM threat_report_candidates WHERE report_id = $1 AND id = ANY($2::bigint[])`,
      [report.id, candidateIds]
    );
    const candidate = rows[0] || null;
    if (!candidate) {
      return { status: 404, error: { code: 'promote_not_found', message: 'Candidate not found' } };
    }
    const eligibility = publicPromoteEligibility(candidate, { corroboration: args.corroboration });
    return {
      status: 200,
      body: {
        report_id: report.public_id,
        action,
        dry_run: true,
        preview: true,
        would_promote: eligibility.ok,
        promote_eligibility: eligibility,
        code: eligibility.ok ? undefined : eligibility.code,
        detail: eligibility.ok ? null : eligibility.detail,
        candidate_id: Number(candidate.id),
        create_preview: eligibility.promotable
          ? previewCreateIocPromotion([asPromotedRow(candidate)])
          : null
      }
    };
  }

  const result = await applyCandidateReviewActions(pool, report.id, {
    action,
    candidateIds,
    selection: args.selection,
    // Explicit approve/ignore/context_only commit unless dry_run; create/promote use confirm.
    confirm: action === 'promote_to_ioc' ? true : !dryRun,
    preview: dryRun,
    corroboration: args.corroboration,
    user,
    audit,
    req
  });

  if (!result.ok) return mapServiceFailure(result);

  return {
    status: 200,
    body: {
      report_id: report.public_id,
      action,
      dry_run: Boolean(result.preview) || dryRun,
      preview: Boolean(result.preview),
      updated: result.updated,
      skipped_context_only: result.skipped_context_only,
      matching: result.matching,
      eligible: result.eligible,
      ineligible: result.ineligible,
      excluded: result.excluded,
      scope_token: result.scope_token,
      summary: result.summary,
      results: result.results,
      created: result.created,
      errors: result.errors,
      operation_id: result.operation_id,
      promoted: result.promoted,
      candidate_id: result.candidate_id,
      audit_via: 'mcp',
      actor: actorFields.metadataExtras
    }
  };
}

/**
 * threat_library_create_iocs — same Create IOCs path as the UI button.
 */
export async function mcpThreatLibraryCreateIocs(pool, args = {}, ctx = {}) {
  const resolved = await resolveReport(pool, args.report_id);
  if (resolved.error) return resolved.error;
  const { report } = resolved;

  const stale = await assertOptionalRevision(pool, report, args.expected_revision);
  if (stale) return stale;

  const { req, user, actorFields, audit } = reviewActorContext(ctx);
  const dryRun = args.dry_run === true || args.confirm !== true;

  let candidateIds;
  if (args.selection?.mode === 'all_matching') {
    candidateIds = undefined;
  } else if (Array.isArray(args.candidate_ids) && args.candidate_ids.length) {
    const resolvedIds = await resolveCandidateIds(pool, report.id, args.candidate_ids);
    if (!resolvedIds.ok) return { status: resolvedIds.status, error: resolvedIds.error };
    candidateIds = resolvedIds.ids;
  } else {
    // Explicit empty selection is rejected — never silently create every approved row.
    return {
      status: 400,
      error: {
        code: 'CANDIDATE_SELECTION_REQUIRED',
        message: 'Provide candidate_ids for the approved indicators to create, or an all_matching selection with scope_token on confirm. Create IOCs never defaults to every extracted observable.'
      }
    };
  }

  const result = await applyCandidateReviewActions(pool, report.id, {
    action: 'create_iocs',
    candidateIds,
    selection: args.selection,
    confirm: !dryRun,
    user,
    audit,
    req,
    operationId: args.operation_id || undefined
  });

  if (!result.ok) return mapServiceFailure(result);

  const summary = result.summary || {};
  const createdCount = Number(summary.created || 0);
  const existingCount = Number(summary.already_existing || 0);
  const failedCount = Number(summary.failed || 0);
  const skippedCount = Number(summary.not_approved || 0)
    + Number(summary.not_applicable || 0)
    + Number(summary.unsupported || 0);
  let outcome = 'success';
  if (result.preview) outcome = 'preview';
  else if (failedCount > 0 && createdCount === 0 && existingCount === 0) outcome = 'failed';
  else if (failedCount > 0) outcome = 'partial';

  return {
    status: 200,
    body: {
      report_id: report.public_id,
      dry_run: Boolean(result.preview) || dryRun,
      preview: Boolean(result.preview),
      outcome,
      eligible_count: Number(summary.eligible || 0),
      newly_created_count: createdCount,
      existing_reused_count: existingCount,
      skipped_count: skippedCount,
      failed_count: failedCount,
      summary,
      results: result.results,
      created: result.created,
      errors: result.errors,
      operation_id: result.operation_id,
      matching: result.matching,
      eligible: result.eligible,
      ineligible: result.ineligible,
      excluded: result.excluded,
      scope_token: result.scope_token,
      audit_via: 'mcp',
      actor: actorFields.metadataExtras
    }
  };
}

/**
 * threat_library_finalize_report
 */
export async function mcpThreatLibraryFinalizeReport(pool, args = {}, ctx = {}) {
  const resolved = await resolveReport(pool, args.report_id);
  if (resolved.error) return resolved.error;
  const { report } = resolved;

  const stale = await assertOptionalRevision(pool, report, args.expected_revision);
  if (stale) return stale;

  const dryRun = args.dry_run === true;

  if (dryRun) {
    // Same readiness contract as finalizeReport, without writing.
    if (!isFinalizeAllowed(report)) {
      const err = mapServiceFailure({
        ok: false,
        status: 409,
        code: 'report_not_ready_for_review',
        error: 'The indicator set is still being refined. Review actions are available once analysis completes.',
        phase: resolveReportPhase(report)
      });
      return {
        status: 200,
        body: {
          report_id: report.public_id,
          dry_run: true,
          would_finalize: false,
          blockers: [{ code: err.error.code, message: err.error.message, phase: err.error.phase }],
          report: serializeImportReportState(report)
        }
      };
    }
    const { rows: candidates } = await pool.query(
      `SELECT *, ${LINKED_PROVENANCE_SQL} FROM threat_report_candidates WHERE report_id = $1`,
      [report.id]
    );
    const linked = await loadReportLinkedSourceCandidateIds(pool, report.id);
    const withProv = withLinkedSourceProvenance(candidates, linked);
    const pendingCount = withProv.filter((c) => isPendingActionableCandidate(c)).length;
    // MCP never overrides the linked-source rule (administrator UI/API only).
    const blockers = finalizeBlockers({ pendingCount, sources: await loadReportSources(pool, report.id) });
    if (blockers.length) {
      return {
        status: 200,
        body: {
          report_id: report.public_id,
          dry_run: true,
          would_finalize: false,
          blockers,
          report: serializeImportReportState(report)
        }
      };
    }
    return {
      status: 200,
      body: {
        report_id: report.public_id,
        dry_run: true,
        would_finalize: true,
        blockers: [],
        report: serializeImportReportState(report)
      }
    };
  }

  const { req, user, actorFields, audit } = reviewActorContext(ctx);
  const result = await finalizeReport(pool, report.id, { user, audit, req });
  if (!result.ok) return mapServiceFailure(result);

  const updated = (await getReportByPublicId(pool, report.public_id)) || report;
  return {
    status: 200,
    body: {
      report_id: updated.public_id,
      dry_run: false,
      finalized: true,
      report: serializeImportReportState(updated),
      audit_via: 'mcp',
      actor: actorFields.metadataExtras
    }
  };
}

/**
 * threat_library_review_ioc_source — approve or dismiss a linked IOC Source.
 */
export async function mcpThreatLibraryReviewIocSource(pool, args = {}, ctx = {}, deps = {}) {
  const resolved = await resolveReport(pool, args.report_id);
  if (resolved.error) return resolved.error;
  const { report } = resolved;

  const action = String(args.action || '').trim();
  if (action !== 'approve' && action !== 'dismiss') {
    return {
      status: 400,
      error: { code: 'INVALID_ACTION', message: 'action must be approve or dismiss' }
    };
  }
  const sourceId = String(args.source_id || '').trim();
  if (!UUID_RE.test(sourceId)) {
    return {
      status: 400,
      error: { code: 'INVALID_SOURCE_ID', message: 'source_id must be a linked IOC Source uuid' }
    };
  }

  const { req, user, actorFields, audit } = reviewActorContext(ctx);
  if (action === 'approve') {
    const result = await approveLinkedIocSource(pool, deps.threatLibraryQueue || null, {
      sourcePublicId: sourceId,
      report,
      actor: user,
      selectedPaths: Array.isArray(args.selected_paths) ? args.selected_paths : null,
      audit,
      req,
      auditMetadataExtras: { ...actorFields.metadataExtras, tool: 'threat_library_review_ioc_source' }
    });
    if (!result.ok) {
      return {
        status: result.status || 400,
        error: { code: result.code || 'IOC_SOURCE_REVIEW_FAILED', message: result.error }
      };
    }
    return {
      status: 200,
      body: {
        report_id: report.public_id,
        action: 'approve',
        source: result.source,
        job_id: result.job_id,
        audit_via: 'mcp',
        actor: actorFields.metadataExtras
      }
    };
  }

  const result = await dismissLinkedIocSource(pool, {
    sourcePublicId: sourceId,
    report,
    actor: user,
    audit,
    req,
    auditMetadataExtras: { ...actorFields.metadataExtras, tool: 'threat_library_review_ioc_source' }
  });
  if (!result.ok) {
    return {
      status: result.status || 400,
      error: { code: result.code || 'IOC_SOURCE_REVIEW_FAILED', message: result.error }
    };
  }
  return {
    status: 200,
    body: {
      report_id: report.public_id,
      action: 'dismiss',
      source: result.source,
      audit_via: 'mcp',
      actor: actorFields.metadataExtras
    }
  };
}

export {
  REVIEW_ACTIONS,
  REVIEW_STATUS_FILTERS,
  reportRevision,
  countReviewDecisions,
  serializeReviewCandidate
};
