/**
 * Pure helpers for the Threat Library review table: evidence-filtered review
 * set, provenance labels, and checkpoint-aware failure detail.
 */

export const REVIEW_FILTERS = Object.freeze([
  { id: 'indicators', label: 'Indicators' },
  { id: 'existing', label: 'Existing' },
  { id: 'new', label: 'New' },
  { id: 'needs_review', label: 'Needs Review' },
  { id: 'context_only', label: 'Context Only' },
  { id: 'all', label: 'All' }
]);

export const DEFAULT_REVIEW_FILTER = 'indicators';

const NON_IOC_TYPES = new Set(['cve', 'attack_technique']);

/**
 * A row belongs in the IOC review set when it is a network/file observable with
 * a real source occurrence that was not resolved as pure context (reference,
 * source URL, footer) or a non-IOC artifact.
 */
export function isReviewIndicator(candidate) {
  if (!candidate) return false;
  if (candidate.is_ioc === false) return false;
  if (NON_IOC_TYPES.has(String(candidate.candidate_type || '').toLowerCase())) return false;
  const ev = candidate.evidence || {};
  if (ev.is_parser_derived_metadata === true) return false;
  if (ev.is_direct_source_observable === false) return false;
  const state = String(candidate.match_state || '').toLowerCase();
  const review = String(candidate.review_status || '').toLowerCase();
  if (state === 'context_only' || review === 'context_only' || candidate.assessment === 'context_only') return false;
  if (state === 'invalid' || candidate.assessment === 'invalid') return false;
  return true;
}

export function matchReviewFilter(candidate, filter) {
  if (filter === 'all') return true;
  const state = String(candidate.match_state || '').toLowerCase();
  const review = String(candidate.review_status || '').toLowerCase();
  if (filter === 'indicators') return isReviewIndicator(candidate);
  if (filter === 'existing') return state === 'existing' || Boolean(candidate.matched_ioc_id);
  if (filter === 'new') return state === 'new';
  if (filter === 'context_only') return state === 'context_only' || review === 'context_only' || candidate.assessment === 'context_only';
  if (filter === 'needs_review') return (state === 'needs_review' || review === 'pending') && isReviewIndicator(candidate);
  return true;
}

const SOURCE_ASSERTION_LABELS = Object.freeze({
  explicit_ioc: 'Explicit IOC',
  explicit_c2: 'Explicit C2',
  explicit_operational_infrastructure: 'Operational infrastructure',
  body_mention: 'Body assertion',
  provider_service: 'Provider/service',
  reference_only: 'Reference',
  source_metadata: 'Source/footer',
  non_ioc: 'Not an IOC'
});

export function sourceAssertionLabel(value) {
  const key = String(value || '').toLowerCase();
  return SOURCE_ASSERTION_LABELS[key] || (key ? key.replace(/_/g, ' ') : 'Ambiguous');
}

const EXPLICIT_ASSERTIONS = new Set(['explicit_ioc', 'explicit_c2', 'explicit_operational_infrastructure']);

/**
 * True when the row is a publisher assertion resolved without the model — its
 * confidence is source-asserted, not an AI estimate.
 */
export function isSourceAsserted(candidate) {
  const ev = (candidate && candidate.evidence) || {};
  const assertion = String(candidate?.source_assertion || ev.source_assertion || '').toLowerCase();
  return EXPLICIT_ASSERTIONS.has(assertion) && ev.decision_source !== 'ai';
}

/**
 * Confidence cell text: a percentage only when the model (or a reviewer) produced
 * one; explicit source assertions show their provenance instead of a number.
 */
export function confidenceLabel(candidate) {
  if (isSourceAsserted(candidate)) return 'Source asserted';
  if (candidate?.confidence == null) return '—';
  return `${Math.round(Number(candidate.confidence) * 100)}%`;
}

/**
 * Compact provenance summary for one candidate row.
 * @returns {{ assertion: string, section: string|null, pages: string|null, occurrences: number, direct: boolean, ports: string|null, decision: string|null, description: string|null, tableRow: string|null, declaredType: string|null, sourceAsserted: boolean }}
 */
export function describeCandidateProvenance(candidate) {
  const ev = (candidate && candidate.evidence) || {};
  const occurrences = Array.isArray(ev.occurrences) ? ev.occurrences : [];
  const tableRows = Array.isArray(ev.table_rows) ? ev.table_rows : [];
  const firstRow = tableRows[0] || null;
  const pages = [...new Set(occurrences.map((o) => o.page).filter((p) => p != null))].sort((a, b) => a - b);
  const heading = occurrences.map((o) => o.section_heading).find(Boolean) || null;
  const zones = Array.isArray(ev.zones) && ev.zones.length ? ev.zones : occurrences.map((o) => o.zone).filter(Boolean);
  const ports = Array.isArray(ev.parsed?.ports) && ev.parsed.ports.length ? ev.parsed.ports.join('/') : null;
  const decision = ev.decision_source === 'ai' ? 'AI' : ev.decision_source === 'deterministic' ? 'Report evidence' : null;
  return {
    assertion: sourceAssertionLabel(candidate?.source_assertion || ev.source_assertion),
    section: heading || (zones.length ? [...new Set(zones)].join(', ').replace(/_/g, ' ') : null) || candidate?.section || null,
    pages: pages.length ? `p${pages.slice(0, 6).join(', p')}${pages.length > 6 ? '…' : ''}` : null,
    occurrences: Number(ev.occurrence_count) || occurrences.length || 0,
    direct: ev.is_direct_source_observable !== false && ev.is_parser_derived_metadata !== true,
    ports,
    decision,
    urlHost: candidate?.candidate_type === 'url' && ev.parsed?.host ? ev.parsed.host : null,
    description: firstRow?.description || null,
    tableRow: firstRow ? `table ${firstRow.table_id || '?'} row ${Number.isInteger(firstRow.row_index) ? firstRow.row_index + 1 : '?'}` : null,
    declaredType: firstRow?.type_cell || null,
    sourceAsserted: isSourceAsserted(candidate)
  };
}

/**
 * Checkpoint-aware failure detail lines for the failed panel.
 * @returns {string[]}
 */
export function describeAnalysisFailureDetail(report) {
  if (!report) return [];
  const code = String(report.failure_code || '').toLowerCase();
  const progress = report.failure_details?.progress || null;
  const lines = [];
  if (progress && Number.isFinite(Number(progress.analysis_chunks_total))) {
    const total = Number(progress.analysis_chunks_total);
    const done = Number(progress.analysis_chunks_completed) || 0;
    const remaining = Number.isFinite(Number(progress.analysis_chunks_remaining))
      ? Number(progress.analysis_chunks_remaining)
      : Math.max(total - done, 0);
    lines.push(`Completed semantic chunks: ${done} / ${total}`);
    lines.push(`Remaining chunks: ${remaining}`);
    if (Number.isFinite(Number(progress.ai_calls))) lines.push(`AI calls made: ${Number(progress.ai_calls)}`);
    if (Number.isFinite(Number(progress.elapsed_ms)) && Number.isFinite(Number(progress.total_analysis_timeout_ms))) {
      const mins = (n) => `${Math.round(Number(n) / 6000) / 10} min`;
      lines.push(`Elapsed ${mins(progress.elapsed_ms)} of ${mins(progress.total_analysis_timeout_ms)} ceiling`);
    }
    if (progress.resumable !== false) lines.push('Retry Analysis will resume from completed checkpoints.');
  } else if (code === 'total_analysis_deadline_exceeded') {
    lines.push('Retry Analysis reuses the stored document and resumes compatible checkpoints.');
  }
  return lines;
}
