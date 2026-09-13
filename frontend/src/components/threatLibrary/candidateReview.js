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

export const PAGE_SIZES = Object.freeze([25, 50, 100]);
export const DEFAULT_PAGE_SIZE = 50;

export const TYPE_FILTERS = Object.freeze([
  { id: 'all', label: 'All types' },
  { id: 'ip', label: 'IP' },
  { id: 'domain', label: 'Domain' },
  { id: 'url', label: 'URL' },
  { id: 'hash', label: 'Hash' },
  { id: 'cidr', label: 'CIDR' }
]);

export const RESULT_FILTERS = Object.freeze([
  { id: 'all', label: 'All results' },
  { id: 'created', label: 'Created' },
  { id: 'already_existing', label: 'Already exists' },
  { id: 'unsupported', label: 'Not supported' },
  { id: 'not_created', label: 'Not created' }
]);

const HASH_TYPES = new Set(['md5', 'sha1', 'sha256']);
const IP_TYPES = new Set(['ip', 'ipv6']);
const REVIEW_FILTER_IDS = new Set(REVIEW_FILTERS.map((f) => f.id));
const TYPE_FILTER_IDS = new Set(TYPE_FILTERS.map((f) => f.id));
const RESULT_FILTER_IDS = new Set(RESULT_FILTERS.map((f) => f.id));

export function candidateMatchesQuery(candidate, query) {
  const needle = String(query || '').trim().toLowerCase();
  if (!needle) return true;
  const hay = [
    candidate?.normalized_value,
    candidate?.original_value,
    candidate?.candidate_type,
    candidate?.role,
    candidate?.assessment
  ].map((v) => String(v || '').toLowerCase()).join('\n');
  return hay.includes(needle);
}

export function candidateMatchesTypeFilter(candidate, type) {
  if (!type || type === 'all') return true;
  const t = String(candidate?.candidate_type || '').toLowerCase();
  if (type === 'hash') return HASH_TYPES.has(t);
  if (type === 'ip') return IP_TYPES.has(t);
  return t === type;
}

export function candidateMatchesResultFilter(candidate, result) {
  if (!result || result === 'all') return true;
  const outcome = String(candidate?.promotion_outcome || '').toLowerCase();
  if (result === 'not_created') {
    return !outcome || outcome === 'not_approved' || outcome === 'not_applicable' || outcome === 'failed';
  }
  return outcome === result;
}

export function filterReviewCandidates(candidates, { tab, q, type, result } = {}) {
  return (Array.isArray(candidates) ? candidates : []).filter((c) => (
    matchReviewFilter(c, tab || DEFAULT_REVIEW_FILTER)
    && candidateMatchesQuery(c, q)
    && candidateMatchesTypeFilter(c, type)
    && candidateMatchesResultFilter(c, result)
  ));
}

export function paginateRows(rows, page, pageSize) {
  const size = PAGE_SIZES.includes(Number(pageSize)) ? Number(pageSize) : DEFAULT_PAGE_SIZE;
  const total = Array.isArray(rows) ? rows.length : 0;
  const totalPages = Math.max(1, Math.ceil(total / size) || 1);
  const safePage = Math.min(Math.max(1, Number(page) || 1), totalPages);
  const start = (safePage - 1) * size;
  return {
    page: safePage,
    pageSize: size,
    total,
    totalPages,
    rows: (rows || []).slice(start, start + size)
  };
}

export function parseReviewTableUrlState(searchParams) {
  const params = searchParams && typeof searchParams.get === 'function'
    ? searchParams
    : new URLSearchParams(String(searchParams || ''));
  const tabRaw = params.get('tab') || params.get('filter') || DEFAULT_REVIEW_FILTER;
  const typeRaw = params.get('type') || 'all';
  const resultRaw = params.get('result') || 'all';
  let pageSize = Number(params.get('pageSize'));
  if (!PAGE_SIZES.includes(pageSize)) pageSize = DEFAULT_PAGE_SIZE;
  let page = Number(params.get('page'));
  if (!Number.isInteger(page) || page < 1) page = 1;
  return {
    tab: REVIEW_FILTER_IDS.has(tabRaw) ? tabRaw : DEFAULT_REVIEW_FILTER,
    q: params.get('q') || '',
    type: TYPE_FILTER_IDS.has(typeRaw) ? typeRaw : 'all',
    result: RESULT_FILTER_IDS.has(resultRaw) ? resultRaw : 'all',
    page,
    pageSize
  };
}

export function serializeReviewTableUrlState(state) {
  const params = new URLSearchParams();
  if (state.tab && state.tab !== DEFAULT_REVIEW_FILTER) params.set('tab', state.tab);
  if (state.q) params.set('q', String(state.q));
  if (state.type && state.type !== 'all') params.set('type', state.type);
  if (state.result && state.result !== 'all') params.set('result', state.result);
  if (state.pageSize && state.pageSize !== DEFAULT_PAGE_SIZE) params.set('pageSize', String(state.pageSize));
  if (state.page && Number(state.page) > 1) params.set('page', String(state.page));
  return params;
}

export function iocResultLabel(candidate) {
  const outcome = String(candidate?.promotion_outcome || '').toLowerCase();
  if (!outcome || outcome === 'will_create') return '—';
  if (outcome === 'created') return 'Created';
  if (outcome === 'already_existing') return 'Already exists';
  if (outcome === 'unsupported') return 'Not supported';
  if (outcome === 'not_approved') return 'Not approved';
  if (outcome === 'not_applicable') return 'Not applicable';
  if (outcome === 'failed') return 'Failed';
  return outcome.replace(/_/g, ' ');
}

export function applyPromotionResults(candidates, results) {
  const byId = new Map((results || []).map((r) => [Number(r.candidate_id), r]));
  return (candidates || []).map((c) => {
    const row = byId.get(Number(c.id));
    if (!row) return c;
    return {
      ...c,
      promotion_outcome: row.outcome,
      promotion_detail: row.detail || c.promotion_detail || null,
      matched_ioc_id: row.ioc_id ?? c.matched_ioc_id,
      match_state: row.ioc_id ? 'existing' : c.match_state,
      matched_ioc_observable_type: row.ioc_id
        ? (row.observable_type || c.matched_ioc_observable_type || c.candidate_type)
        : c.matched_ioc_observable_type
    };
  });
}

export function formatCreateIocSummary(summary) {
  const s = summary || {};
  const lines = [
    `Selected: ${s.selected || 0}`,
    `Approved + new + supported: ${s.eligible || 0}`,
    `Already existing: ${s.already_existing || 0}`,
    `Not approved: ${s.not_approved || 0}`,
    `Unsupported type: ${s.unsupported || 0}`
  ];
  if (s.not_applicable) lines.push(`Not applicable: ${s.not_applicable}`);
  const eligible = s.eligible || 0;
  const existing = s.already_existing || 0;
  const notApproved = s.not_approved || 0;
  const unsupported = s.unsupported || 0;
  lines.push('');
  lines.push('Result:');
  lines.push(`- ${eligible} new IOC record${eligible === 1 ? '' : 's'} will be created`);
  lines.push(`- ${existing} existing IOC record${existing === 1 ? '' : 's'} will not be duplicated`);
  if (notApproved) lines.push(`- ${notApproved} unapproved row${notApproved === 1 ? '' : 's'} will be skipped`);
  if (unsupported) lines.push(`- ${unsupported} unsupported row${unsupported === 1 ? '' : 's'} cannot currently be created`);
  if (eligible > 0 && (notApproved || unsupported || existing)) {
    lines.push('');
    lines.push(`Only the ${eligible} eligible approved indicators will be created.`);
  }
  return lines.join('\n');
}
