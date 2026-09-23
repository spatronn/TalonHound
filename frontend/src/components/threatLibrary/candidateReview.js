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

/**
 * Context Only != IOC candidate. Mirrors backend `isContextOnlyCandidate`:
 * any of the three review fields marks the row as context, and such a row is
 * never part of Approve / Create IOCs / high-confidence approval no matter
 * which filter is active. The only exit is the explicit row-level promotion.
 */
export function isContextOnlyCandidate(candidate) {
  if (!candidate) return false;
  const state = String(candidate.match_state || '').toLowerCase();
  const review = String(candidate.review_status || '').toLowerCase();
  const assessment = String(candidate.assessment || '').toLowerCase();
  return state === 'context_only' || review === 'context_only' || assessment === 'context_only';
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

const ARTIFACT_KIND_LABELS = Object.freeze({
  mutex: 'Mutex / single-instance name',
  code: 'Code identifier',
  config: 'Configuration key',
  registry: 'Registry path',
  file: 'File name',
  path: 'Path',
  command: 'Command',
  process: 'Process / service name',
  metadata: 'Metadata',
  identifier: 'Technical identifier'
});

const RESOLVED_TYPE_LABELS = Object.freeze({
  technical_artifact: 'Not a network IOC',
  relative_path: 'Relative path (no scheme / host)',
  file_path: 'File system path'
});

/**
 * Why a row was kept out of the IOC set: resolved type, artifact family and
 * the resolver reason (e.g. "Not a network IOC · Mutex / single-instance name ·
 * mutex_label"). Null for real network / file observables.
 */
export function describeTypeResolution(candidate) {
  const ev = (candidate && candidate.evidence) || {};
  const tr = ev.type_resolution || null;
  const resolved = String(tr?.resolved_type || ev.resolved_type || candidate?.candidate_type || '').toLowerCase();
  if (!RESOLVED_TYPE_LABELS[resolved]) return null;
  const parts = [RESOLVED_TYPE_LABELS[resolved]];
  const kind = ev.artifact_kind || tr?.artifact_kind || null;
  if (kind && ARTIFACT_KIND_LABELS[kind] && resolved === 'technical_artifact') parts.push(ARTIFACT_KIND_LABELS[kind]);
  const reason = tr?.reason || ev.typing_reason || null;
  if (reason) parts.push(String(reason).replace(/_/g, ' '));
  const details = [];
  if (tr?.normalized_path && tr.normalized_path !== candidate?.normalized_value) details.push(`path ${tr.normalized_path}`);
  if (tr?.port != null) details.push(`port ${tr.port}`);
  return { label: parts.join(' · '), detail: details.length ? details.join(' · ') : null, syntaxGuess: tr?.syntax_guess || null };
}

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
 * @returns {{ assertion: string, section: string|null, pages: string|null, occurrences: number, direct: boolean, ports: string|null, decision: string|null, description: string|null, tableRow: string|null, declaredType: string|null, sourceAsserted: boolean, resolution: { label: string, detail: string|null, syntaxGuess: string|null }|null }}
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
    sourceAsserted: isSourceAsserted(candidate),
    resolution: describeTypeResolution(candidate)
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
  const outcome = iocResultOutcome(candidate) || '';
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

/** Observable types that can be stored as IOC records (backend CREATABLE_IOC_TYPES). */
const PROMOTABLE_TYPES = new Set(['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256']);

const lower = (v) => String(v || '').toLowerCase();

/**
 * Mirror of backend `classifyCreateEligibility` (promotion.js), same rule
 * order: what Create IOCs would do with this row right now. Pure read of the
 * persisted row — `already_existing` rests on the stored IOC link, never on a
 * value comparison.
 * @returns {'will_create'|'already_existing'|'not_approved'|'unsupported'|'not_applicable'}
 */
export function classifyCreateOutcome(candidate) {
  const c = candidate || {};
  const review = lower(c.review_status || 'pending');
  const assessment = lower(c.assessment);
  const state = lower(c.match_state);
  const type = lower(c.candidate_type);
  if (c.is_ioc === false
    || review === 'ignored' || review === 'context_only'
    || assessment === 'context_only' || assessment === 'invalid'
    || state === 'context_only' || state === 'invalid') return 'not_applicable';
  if (!PROMOTABLE_TYPES.has(type)) return 'unsupported';
  if (review !== 'approved' && review !== 'created_ioc') return 'not_approved';
  if (assessment !== 'malicious' && assessment !== 'suspicious') return 'not_applicable';
  if (c.matched_ioc_id || review === 'created_ioc' || state === 'existing' || lower(c.promotion_outcome) === 'created') {
    return 'already_existing';
  }
  return 'will_create';
}

/**
 * Effective IOC Result outcome. A persisted `created` / `already_existing`
 * (last Create IOCs run) wins; otherwise a row that Create IOCs would record as
 * already existing shows that deterministically from its stored IOC link, so an
 * existing-only selection needs no no-op mutation and survives a refresh.
 * Anything else falls back to the persisted outcome (null = not run).
 */
export function iocResultOutcome(candidate) {
  const persisted = lower(candidate?.promotion_outcome);
  if (persisted === 'created' || persisted === 'already_existing') return persisted;
  if (classifyCreateOutcome(candidate) === 'already_existing') return 'already_existing';
  return persisted && persisted !== 'will_create' ? persisted : null;
}

/**
 * IOC details route for the record this row resolved to, only when the
 * backend returned its public id (exact PK lookup). Null otherwise — a link is
 * never derived from the observable value.
 */
export function iocResultLink(candidate) {
  const outcome = iocResultOutcome(candidate);
  if (outcome !== 'created' && outcome !== 'already_existing') return null;
  const publicId = typeof candidate?.matched_ioc_public_id === 'string' ? candidate.matched_ioc_public_id.trim() : '';
  if (!publicId || !candidate?.matched_ioc_id) return null;
  return `/ioc/details/${encodeURIComponent(publicId)}`;
}

export function iocResultLabel(candidate) {
  const outcome = iocResultOutcome(candidate);
  if (!outcome) return '—';
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

/**
 * Informational copy when a Create IOCs preview has nothing to create
 * (approved + new + supported = 0): no mutation follows, so the modal only
 * explains why. Null when at least one IOC would be created.
 * @returns {{ title: string, description: string }|null}
 */
export function describeNoCreatableIocs(summary) {
  const s = summary || {};
  if ((Number(s.eligible) || 0) > 0) return null;
  const selected = Number(s.selected) || 0;
  const existing = Number(s.already_existing) || 0;
  const notApproved = Number(s.not_approved) || 0;
  const existingLine = existing > 0
    ? ` ${existing} selected ${existing === 1 ? 'indicator already exists' : 'indicators already exist'} as IOC records.`
    : '';
  if (notApproved > 0 && notApproved === selected) {
    return {
      title: 'Approve indicators first',
      description: 'Only approved indicators can be created as IOCs. Review and approve the selected indicators before creating IOC records.'
    };
  }
  return {
    title: 'No new IOC records',
    description: existing > 0
      ? `No new IOC records will be created.${existingLine}`
      : 'No new IOC records will be created. None of the selected indicators can be created as IOC records.'
  };
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

export const REVIEW_TOOLBAR_LABELS = Object.freeze({
  approve: 'Approve',
  context_only: 'Context only',
  ignore: 'Ignore',
  create_iocs: 'Create IOCs',
  approve_high_confidence_malicious: 'Approve high-confidence malicious',
  promote_to_ioc: 'Promote to IOC…'
});

/** Actions whose request body must only carry IOC-candidate rows (context-only rows are excluded). */
const IOC_CANDIDATE_ACTIONS = new Set(['approve', 'context_only', 'create_iocs']);

/**
 * Split the current selection for one review action: `ids` is what may be
 * sent, `excluded` counts the Context Only rows that were left out. Item-level
 * eligibility is canonical here; the filter only decides which buttons show.
 */
export function selectionForAction(action, selectedRows) {
  const rows = Array.isArray(selectedRows) ? selectedRows : [];
  if (!IOC_CANDIDATE_ACTIONS.has(String(action || ''))) {
    return { ids: rows.map((c) => c.id), excluded: 0 };
  }
  const eligible = rows.filter((c) => !isContextOnlyCandidate(c));
  return { ids: eligible.map((c) => c.id), excluded: rows.length - eligible.length };
}

/**
 * Why a single selected row cannot be promoted (null when it can). Promotion
 * is deliberately single-row: it is an analyst override, never a bulk path.
 */
export function describePromoteBlocker(selectedRows) {
  const rows = Array.isArray(selectedRows) ? selectedRows : [];
  if (rows.length === 0) return 'Select one Context Only indicator to promote it.';
  if (rows.length > 1) return 'Promote to IOC is a single-row action: select exactly one indicator.';
  const row = rows[0];
  if (!isContextOnlyCandidate(row)) return 'Only Context Only indicators can be promoted.';
  if (!PROMOTABLE_TYPES.has(String(row.candidate_type || '').toLowerCase())) {
    return 'This indicator type cannot be stored as an IOC record.';
  }
  return null;
}

export const NO_CREATABLE_HINT = 'No new approved indicators selected.';

/**
 * Toolbar for the active filter and selection.
 *
 * Context Only view: no IOC lifecycle actions at all (they are not rendered,
 * not merely disabled) — only the single-row `Promote to IOC…` override and
 * `Ignore`. Every other view keeps the IOC actions, but Approve / Context only
 * enable only when the selection holds at least one IOC candidate, so a
 * Context Only row selected in the All view can never drive them on its own.
 * Create IOCs additionally needs one row Create IOCs would actually create.
 *
 * @returns {{ actions: Array<{ id: string, label: string, enabled: boolean, primary?: boolean, hint?: string|null }>, contextOnlySelected: number, iocSelected: number }}
 */
export function describeReviewToolbar({ filter, selectedRows, busy = false } = {}) {
  const rows = Array.isArray(selectedRows) ? selectedRows : [];
  const iocSelected = rows.filter((c) => !isContextOnlyCandidate(c)).length;
  const contextOnlySelected = rows.length - iocSelected;
  const isBusy = Boolean(busy);
  const item = (id, enabled, extra = {}) => ({ id, label: REVIEW_TOOLBAR_LABELS[id], enabled: enabled && !isBusy, ...extra });

  if (filter === 'context_only') {
    const blocker = describePromoteBlocker(rows);
    return {
      actions: [
        item('promote_to_ioc', blocker == null, { hint: blocker }),
        item('ignore', rows.length > 0)
      ],
      contextOnlySelected,
      iocSelected
    };
  }

  const noIocHint = rows.length > 0 && iocSelected === 0 ? 'Context Only rows are not IOC candidates.' : null;
  // Create IOCs needs at least one approved + new + supported row; existing
  // rows in a mixed selection never block the new ones.
  const creatable = rows.filter((c) => classifyCreateOutcome(c) === 'will_create').length;
  const createHint = noIocHint || (rows.length > 0 && creatable === 0 ? NO_CREATABLE_HINT : null);
  return {
    actions: [
      item('approve', iocSelected > 0, { hint: noIocHint }),
      item('context_only', iocSelected > 0, { hint: noIocHint }),
      item('ignore', rows.length > 0),
      item('create_iocs', creatable > 0, { primary: true, hint: createHint }),
      item('approve_high_confidence_malicious', true)
    ],
    contextOnlySelected,
    iocSelected
  };
}

const REVIEW_FEEDBACK = Object.freeze({
  approve: { one: 'Indicator approved.', many: (n) => `${n} indicators approved.`, some: 'Indicators approved.' },
  context_only: {
    one: 'Indicator marked as Context Only.',
    many: (n) => `${n} indicators marked as Context Only.`,
    some: 'Indicators marked as Context Only.'
  },
  ignore: { one: 'Indicator ignored.', many: (n) => `${n} indicators ignored.`, some: 'Indicators ignored.' },
  approve_high_confidence_malicious: {
    one: '1 high-confidence malicious indicator approved.',
    many: (n) => `${n} high-confidence malicious indicators approved.`,
    some: 'High-confidence malicious indicators approved.'
  }
});

/**
 * Success banner for a review action from the Indicators page. `count` is the
 * backend's `updated` count when present, else the number of selected rows.
 * Errors reported by the backend keep the explicit error wording.
 */
export function describeReviewFeedback(action, { count = null, errors = 0, excluded = 0 } = {}) {
  const errs = Number(errors) || 0;
  if (errs > 0) return `Completed with ${errs} error${errs === 1 ? '' : 's'}.`;
  const entry = REVIEW_FEEDBACK[String(action || '')];
  if (!entry) return 'Review action applied.';
  const n = count == null || count === '' ? NaN : Number(count);
  const head = !Number.isFinite(n) || n < 0 ? entry.some : n === 1 ? entry.one : entry.many(n);
  const skipped = Number(excluded) || 0;
  if (skipped > 0) return `${head} ${skipped} Context Only row${skipped === 1 ? ' was' : 's were'} not included.`;
  return head;
}

/** Success banner after the single-row Context Only override. */
export function describePromoteFeedback(data, value) {
  const label = value ? `${value} promoted to IOC.` : 'Indicator promoted to IOC.';
  const summary = data?.summary || {};
  if ((Number(summary.created) || 0) > 0) return `${label} IOC created.`;
  if ((Number(summary.already_existing) || 0) > 0) return `${label} An IOC record already existed and was linked.`;
  if ((Number(summary.failed) || 0) > 0 || (Array.isArray(data?.errors) && data.errors.length)) {
    return `${label} IOC creation failed; the row is now an approved IOC candidate.`;
  }
  return label;
}

/** Success banner after Create IOCs (confirmed run). */
export function describeCreateIocFeedback({ created = 0, existing = 0, errors = 0 } = {}) {
  const c = Number(created) || 0;
  const e = Number(existing) || 0;
  const errs = Number(errors) || 0;
  const head = c === 1 ? 'IOC created.' : `${c} IOCs created.`;
  const parts = [head];
  if (e > 0) parts.push(`${e} already existed.`);
  if (errs > 0) parts.push(`${errs} error${errs === 1 ? '' : 's'}.`);
  return parts.join(' ');
}
