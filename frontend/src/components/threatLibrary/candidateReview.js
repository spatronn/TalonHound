/**
 * Pure helpers for the Threat Library review table: evidence-filtered review
 * set, provenance labels, and checkpoint-aware failure detail.
 *
 * Membership / Context Only predicates MUST stay behaviourally identical to
 * `backend/lib/threatLibrary/indicatorMembership.js`. Parity is enforced by
 * `backend/lib/threatLibrary/indicatorMembership.parity.test.js` (imports this
 * module and the backend contract against the same fixture matrix).
 */

export const REVIEW_FILTERS = Object.freeze([
  { id: 'indicators', label: 'Original' },
  { id: 'total_unique', label: 'Total unique' },
  { id: 'linked_only', label: 'Linked only' },
  { id: 'existing', label: 'Existing' },
  { id: 'new', label: 'New' },
  { id: 'needs_review', label: 'Needs Review' },
  { id: 'context_only', label: 'Context Only' },
  { id: 'all', label: 'All' }
]);

export const DEFAULT_REVIEW_FILTER = 'indicators';

const LINKED_SOURCE_IOC_ASSERTION = 'linked_source_ioc';

/** Keep in lockstep with backend indicatorMembership.NON_IOC_CANDIDATE_TYPES */
const NON_IOC_TYPES = new Set(['cve', 'attack_technique']);

/** Keep in lockstep with backend indicatorMembership.EXPLICIT_PUBLISHER_IOC_ASSERTIONS */
const EXPLICIT_PUBLISHER_IOC_ASSERTIONS = new Set([
  'explicit_ioc',
  'explicit_c2',
  'explicit_operational_infrastructure'
]);

/** Keep in lockstep with backend indicatorMembership.AUTHORITATIVE_PUBLISHER_OCCURRENCE_ZONES */
const AUTHORITATIVE_PUBLISHER_OCCURRENCE_ZONES = new Set([
  'explicit_ioc_section',
  'c2_section',
  'sample_table',
  'operational_infrastructure'
]);

function hasAuthoritativePublisherIocScope(candidate) {
  const ev = (candidate && candidate.evidence) || {};
  return candidate?.document_has_authoritative_scope === true
    || ev.document_has_authoritative_scope === true;
}

function candidateOccurrences(candidate) {
  const ev = (candidate && candidate.evidence) || {};
  if (Array.isArray(candidate?.occurrences) && candidate.occurrences.length) return candidate.occurrences;
  return Array.isArray(ev.occurrences) ? ev.occurrences : [];
}

// Zone alone is never membership: the occurrence must be a publisher assertion.
// Occurrences without relation annotations (older extracts) keep the zone reading.
function hasPublisherIocSectionOccurrence(candidate) {
  return candidateOccurrences(candidate).some((occ) => {
    if (!AUTHORITATIVE_PUBLISHER_OCCURRENCE_ZONES.has(String(occ?.zone || ''))) return false;
    if (occ?.asserted === true) return true;
    return !occ?.occurrence_kind;
  });
}

function isPublisherAssertedReportIoc(candidate) {
  const ev = (candidate && candidate.evidence) || {};
  const assertion = String(candidate?.source_assertion || ev.source_assertion || '').toLowerCase();
  if (EXPLICIT_PUBLISHER_IOC_ASSERTIONS.has(assertion)) return true;
  return hasPublisherIocSectionOccurrence(candidate);
}

/**
 * MODE A: publisher-curated IOC section is authoritative for Indicators.
 * MODE B: no such section — existing review predicates still apply.
 * Canonical: backend indicatorMembership.isPublisherAuthoritativeReportIocMember.
 */
export function isPublisherAuthoritativeReportIocMember(candidate) {
  if (!hasAuthoritativePublisherIocScope(candidate)) return true;
  return isPublisherAssertedReportIoc(candidate);
}

/**
 * The report detail API historically omitted document_has_authoritative_scope
 * from public evidence. If the loaded set already contains publisher-asserted
 * IOC identities, treat the document as MODE A so narrative-only rows cannot
 * enter Indicators solely because they are malicious.
 */
export function withInferredPublisherIocScope(candidates) {
  const list = Array.isArray(candidates) ? candidates : [];
  if (!list.some((c) => isPublisherAssertedReportIoc(c))) return list;
  return list.map((c) => {
    if (hasAuthoritativePublisherIocScope(c)) return c;
    // Linked-only identities keep source-scoped semantics; do not stamp MODE A.
    if (c.has_original_document_occurrence === false) return c;
    const ev = c.evidence && typeof c.evidence === 'object' ? c.evidence : {};
    return {
      ...c,
      document_has_authoritative_scope: true,
      evidence: { ...ev, document_has_authoritative_scope: true }
    };
  });
}

function passesIndicatorTypeGates(candidate) {
  if (!candidate) return false;
  if (candidate.is_ioc === false) return false;
  if (NON_IOC_TYPES.has(String(candidate.candidate_type || '').toLowerCase())) return false;
  const ev = candidate.evidence || {};
  if (ev.is_parser_derived_metadata === true) return false;
  if (ev.is_direct_source_observable === false) return false;
  if (
    candidate.reserved_address === true
    || candidate.non_actionable_local === true
    || ev.reserved_address === true
    || ev.non_actionable_local === true
  ) {
    return false;
  }
  const state = String(candidate.match_state || '').toLowerCase();
  const review = String(candidate.review_status || '').toLowerCase();
  if (state === 'context_only' || review === 'context_only' || candidate.assessment === 'context_only') return false;
  if (state === 'invalid' || candidate.assessment === 'invalid') return false;
  return true;
}

export function isLinkedSourceAssertedIoc(candidate) {
  if (!candidate) return false;
  const ev = candidate.evidence || {};
  const assertion = String(candidate?.source_assertion || ev.source_assertion || '').toLowerCase();
  if (assertion === LINKED_SOURCE_IOC_ASSERTION) return true;
  if (Array.isArray(candidate.sources) && candidate.sources.length > 0) return true;
  return Array.isArray(ev.linked_sources) && ev.linked_sources.length > 0;
}

export function isLinkedSourceIndicatorMember(candidate) {
  return passesIndicatorTypeGates(candidate) && isLinkedSourceAssertedIoc(candidate);
}

/**
 * Original-document Indicator membership (default Indicators filter).
 * Linked-only identities are excluded so attaching an external pack never
 * inflates MODE A publisher counts. Canonical: backend isReportIndicatorMember.
 */
export function isReviewIndicator(candidate) {
  if (!candidate) return false;
  if (candidate.has_original_document_occurrence === false) return false;
  if (!passesIndicatorTypeGates(candidate)) return false;
  if (!isPublisherAuthoritativeReportIocMember(candidate)) return false;
  return true;
}

/** Total unique inventory: original ∪ linked-source Indicators. */
export function isUnionReviewIndicator(candidate) {
  return isReviewIndicator(candidate) || isLinkedSourceIndicatorMember(candidate);
}

export function isLinkedOnlyReviewIndicator(candidate) {
  return isUnionReviewIndicator(candidate) && !isReviewIndicator(candidate);
}

/** Alias matching the backend canonical name. */
export function isReportIndicatorMember(candidate) {
  return isReviewIndicator(candidate);
}

/**
 * Approve / Create IOCs actionability (union membership).
 * Mirrors backend isReviewActionableIndicator.
 */
export function isReviewActionableIndicator(candidate) {
  return isUnionReviewIndicator(candidate);
}

/**
 * Context Only != IOC candidate. Canonical: backend isContextOnlyCandidate.
 * Any of the three review fields marks the row as context.
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
  if (filter === 'total_unique') return isUnionReviewIndicator(candidate);
  if (filter === 'linked_only') return isLinkedOnlyReviewIndicator(candidate);
  if (filter === 'existing') {
    return isUnionReviewIndicator(candidate) && (state === 'existing' || Boolean(candidate.matched_ioc_id));
  }
  if (filter === 'new') return isUnionReviewIndicator(candidate) && state === 'new';
  if (filter === 'context_only') return state === 'context_only' || review === 'context_only' || candidate.assessment === 'context_only';
  if (filter === 'needs_review') {
    return (state === 'needs_review' || review === 'pending') && isUnionReviewIndicator(candidate);
  }
  // Source-scoped filter: `source:<public_id>`
  if (String(filter || '').startsWith('source:')) {
    const sourceId = String(filter).slice('source:'.length);
    if (!isUnionReviewIndicator(candidate)) return false;
    return (candidate.sources || []).some((s) => s.id === sourceId);
  }
  return true;
}

const SOURCE_ASSERTION_LABELS = Object.freeze({
  explicit_ioc: 'Explicit IOC',
  explicit_c2: 'Explicit C2',
  explicit_operational_infrastructure: 'Operational infrastructure',
  linked_source_ioc: 'Linked IOC source',
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
 * Compact title for a linked IOC source — prefer path/name over a long URL.
 */
export function linkedSourceEvidenceLabel(source) {
  if (!source || typeof source !== 'object') return null;
  if (source.file_path) {
    const path = String(source.file_path);
    const base = path.includes('/') ? path.slice(path.lastIndexOf('/') + 1) : path;
    const urlLabel = (() => {
      const url = String(source.canonical_url || source.original_url || '').trim();
      if (!url) return null;
      try {
        const u = new URL(url);
        const parts = u.pathname.split('/').filter(Boolean);
        if (parts.length >= 2 && /github\.com$/i.test(u.hostname)) return `${parts[0]}/${parts[1]}`;
      } catch { /* ignore */ }
      return null;
    })();
    return urlLabel ? `${urlLabel} · ${base}` : base;
  }
  const url = String(source.canonical_url || source.original_url || '').trim();
  if (!url) return source.id ? 'Linked IOC source' : null;
  try {
    const u = new URL(url);
    if (/github\.com$/i.test(u.hostname) || /githubusercontent\.com$/i.test(u.hostname)) {
      const parts = u.pathname.split('/').filter(Boolean);
      if (parts.length >= 2) {
        const ownerRepo = `${parts[0]}/${parts[1]}`;
        const pathStart = parts[2] && /^(tree|blob)$/i.test(parts[2]) ? 4 : 2;
        const pathParts = parts.slice(pathStart);
        if (pathParts.length) return `${ownerRepo} · ${pathParts.join('/')}`;
        return ownerRepo;
      }
    }
    return u.hostname;
  } catch {
    return url.length > 48 ? `${url.slice(0, 45)}…` : url;
  }
}

/**
 * Compact provenance summary for one candidate row.
 * @returns {{ assertion: string, section: string|null, pages: string|null, occurrences: number, direct: boolean, ports: string|null, decision: string|null, description: string|null, tableRow: string|null, declaredType: string|null, sourceAsserted: boolean, linkedOnly: boolean, linkedSource: string|null, resolution: { label: string, detail: string|null, syntaxGuess: string|null }|null }}
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
  const linkedOnly = candidate?.has_original_document_occurrence === false
    || String(candidate?.source_assertion || ev.source_assertion || '').toLowerCase() === LINKED_SOURCE_IOC_ASSERTION;
  const linkedSources = Array.isArray(candidate?.sources) ? candidate.sources : [];
  const linkedLabel = linkedSources.map(linkedSourceEvidenceLabel).find(Boolean)
    || (ev.linked_source_path ? String(ev.linked_source_path) : null);
  const zoneLabel = zones.length ? [...new Set(zones)].join(', ').replace(/_/g, ' ') : null;
  // Linked-only rows often inherit extract zones like report_body with 0
  // original-document occurrences — prefer source provenance instead.
  const section = linkedOnly
    ? (linkedLabel || heading || null)
    : (heading || zoneLabel || candidate?.section || null);
  return {
    assertion: sourceAssertionLabel(candidate?.source_assertion || ev.source_assertion),
    section,
    pages: linkedOnly ? null : (pages.length ? `p${pages.slice(0, 6).join(', p')}${pages.length > 6 ? '…' : ''}` : null),
    occurrences: linkedOnly ? 0 : (Number(ev.occurrence_count) || occurrences.length || 0),
    direct: ev.is_direct_source_observable !== false && ev.is_parser_derived_metadata !== true,
    ports,
    decision: linkedOnly ? 'Linked source' : decision,
    urlHost: candidate?.candidate_type === 'url' && ev.parsed?.host ? ev.parsed.host : null,
    description: firstRow?.description || null,
    tableRow: linkedOnly ? null : (firstRow ? `table ${firstRow.table_id || '?'} row ${Number.isInteger(firstRow.row_index) ? firstRow.row_index + 1 : '?'}` : null),
    declaredType: firstRow?.type_cell || null,
    sourceAsserted: isSourceAsserted(candidate) || linkedOnly,
    linkedOnly,
    linkedSource: linkedLabel,
    sourceType: linkedSources[0]?.source_type || null,
    repoRevision: linkedSources[0]?.repo_revision || null,
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
  return withInferredPublisherIocScope(candidates).filter((c) => (
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
    tab: REVIEW_FILTER_IDS.has(tabRaw) || String(tabRaw).startsWith('source:')
      ? tabRaw
      : DEFAULT_REVIEW_FILTER,
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
  if (!isUnionReviewIndicator(c)) return 'not_applicable';
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
  const eligible = String(action) === 'context_only'
    ? rows.filter((c) => !isContextOnlyCandidate(c))
    : rows.filter((c) => isReviewActionableIndicator(c));
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
  // Union membership: original publisher Indicators + linked-source Indicators.
  const iocSelected = rows.filter((c) => isReviewActionableIndicator(c)).length;
  const markableSelected = rows.filter((c) => !isContextOnlyCandidate(c)).length;
  const contextOnlySelected = rows.length - markableSelected;
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
  const noMarkHint = rows.length > 0 && markableSelected === 0 ? 'Context Only rows are not IOC candidates.' : null;
  // Create IOCs needs at least one approved + new + supported row; existing
  // rows in a mixed selection never block the new ones.
  const creatable = rows.filter((c) => classifyCreateOutcome(c) === 'will_create').length;
  const createHint = noIocHint || (rows.length > 0 && creatable === 0 ? NO_CREATABLE_HINT : null);
  return {
    actions: [
      item('approve', iocSelected > 0, { hint: noIocHint }),
      item('context_only', markableSelected > 0, { hint: noMarkHint }),
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

/**
 * Indicator-table selection. Explicit mode is a set of candidate ids (page
 * checks accumulate across pagination). All-matching mode is the active
 * filter set minus excluded ids — the client does not materialize that set.
 */
export function toggleExplicitSelection(selectedIds, id) {
  const next = new Set(selectedIds);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  return next;
}

export function togglePageExplicit(selectedIds, pageIds) {
  const next = new Set(selectedIds);
  const ids = Array.isArray(pageIds) ? pageIds : [];
  const allOn = ids.length > 0 && ids.every((id) => next.has(id));
  if (allOn) ids.forEach((id) => next.delete(id));
  else ids.forEach((id) => next.add(id));
  return next;
}

export function toggleExcludedId(excludedIds, id) {
  const next = new Set(excludedIds);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  return next;
}

export function togglePageExcluded(excludedIds, pageIds) {
  const next = new Set(excludedIds);
  const ids = Array.isArray(pageIds) ? pageIds : [];
  const allSelected = ids.length > 0 && ids.every((id) => !next.has(id));
  if (allSelected) ids.forEach((id) => next.add(id));
  else ids.forEach((id) => next.delete(id));
  return next;
}

export function headerCheckState({ mode, selectedIds, excludedIds, pageIds } = {}) {
  const ids = Array.isArray(pageIds) ? pageIds : [];
  if (!ids.length) return 'unchecked';
  const selected = new Set(mode === 'all_matching' ? [] : selectedIds);
  const excluded = new Set(mode === 'all_matching' ? excludedIds : []);
  const count = ids.filter((id) => (mode === 'all_matching' ? !excluded.has(id) : selected.has(id))).length;
  if (count === 0) return 'unchecked';
  if (count === ids.length) return 'checked';
  return 'indeterminate';
}

export function reviewFiltersEqual(a, b) {
  const norm = (f) => ({
    tab: f?.tab || DEFAULT_REVIEW_FILTER,
    type: f?.type || 'all',
    result: f?.result || 'all',
    search: f?.search || ''
  });
  const x = norm(a);
  const y = norm(b);
  return x.tab === y.tab && x.type === y.type && x.result === y.result && x.search === y.search;
}

export function selectionScopeLabel({ tab, type, result, search } = {}) {
  const tabLabel = REVIEW_FILTERS.find((f) => f.id === tab)?.label || 'Indicators';
  const extras = [];
  if (type && type !== 'all') extras.push(TYPE_FILTERS.find((t) => t.id === type)?.label || type);
  if (result && result !== 'all') extras.push(RESULT_FILTERS.find((t) => t.id === result)?.label || result);
  const q = String(search || '').trim();
  if (q) extras.push(`search “${q}”`);
  return extras.length ? `${tabLabel} (${extras.join(', ')})` : tabLabel;
}

/**
 * Gmail-style banner. Page selection offers promotion only when the filter
 * contains rows beyond the explicit set. All-matching copy uses the filtered
 * count minus exclusions.
 */
export function describeSelectionBanner({
  mode,
  selectedCount = 0,
  pageIds = [],
  pageSelectedCount = 0,
  matchingCount = 0,
  excludedCount = 0,
  scopeLabel = 'Indicators'
} = {}) {
  if (mode === 'all_matching') {
    const count = Math.max(0, Number(matchingCount) - Number(excludedCount));
    const message = count <= 0
      ? `No indicators in ${scopeLabel} are selected.`
      : excludedCount > 0
        ? `${count} indicators in ${scopeLabel} are selected across all pages.`
        : `All ${matchingCount} indicators in ${scopeLabel} are selected across all pages.`;
    return { message, action: { id: 'clear', label: 'Clear selection' } };
  }
  if (!pageIds.length || pageSelectedCount !== pageIds.length) return null;
  const message = `${pageSelectedCount} indicator${pageSelectedCount === 1 ? '' : 's'} on this page selected.`;
  if (Number(matchingCount) > Number(selectedCount)) {
    return {
      message,
      action: { id: 'all_matching', label: `Select all ${matchingCount} indicators in ${scopeLabel}` }
    };
  }
  return { message, action: null };
}

export function buildAllMatchingReviewBody({
  action,
  filters,
  excludedIds = [],
  scopeToken = null,
  confirm = null,
  preview = false
} = {}) {
  const selection = {
    mode: 'all_matching',
    filters: {
      tab: filters?.tab || DEFAULT_REVIEW_FILTER,
      type: filters?.type || 'all',
      result: filters?.result || 'all',
      search: filters?.search || ''
    },
    excluded_candidate_ids: [...excludedIds]
  };
  if (scopeToken) selection.scope_token = scopeToken;
  const body = { action, selection };
  if (confirm != null) body.confirm = confirm === true;
  if (preview) body.preview = true;
  return body;
}

function bulkActionPhrase(action, n) {
  const indicators = `${n} eligible indicator${n === 1 ? '' : 's'}`;
  if (action === 'approve') return `approve ${indicators}`;
  if (action === 'context_only') return `mark ${indicators} as Context Only`;
  if (action === 'ignore') return `ignore ${indicators}`;
  if (action === 'approve_high_confidence_malicious') {
    return `approve ${n} eligible high-confidence malicious indicator${n === 1 ? '' : 's'}`;
  }
  if (action === 'create_iocs') return `create ${n} IOC record${n === 1 ? '' : 's'} from eligible indicators`;
  return `update ${indicators}`;
}

export function describeBulkActionConfirm({
  action,
  eligible = 0,
  matching = 0,
  tabLabel = 'Indicators',
  acrossPages = false,
  excluded = 0
} = {}) {
  const n = Number(eligible) || 0;
  const match = Number(matching) || 0;
  const skipped = Math.max(0, match - n);
  const titles = {
    approve: `Approve ${n} indicators?`,
    context_only: `Mark ${n} indicators as Context Only?`,
    ignore: `Ignore ${n} indicators?`,
    create_iocs: `Create ${n} IOC${n === 1 ? '' : 's'}?`,
    approve_high_confidence_malicious: `Approve ${n} high-confidence malicious indicators?`
  };
  const labels = {
    approve: `Approve ${n}`,
    context_only: `Mark ${n}`,
    ignore: `Ignore ${n}`,
    create_iocs: `Create ${n} IOC${n === 1 ? '' : 's'}`,
    approve_high_confidence_malicious: `Approve ${n}`
  };
  const where = acrossPages
    ? `matching the current ${tabLabel} filters across all pages`
    : 'in the current selection';
  let description = `This will ${bulkActionPhrase(action, n)} ${where}.`;
  if (skipped > 0) {
    description += ` ${skipped} selected indicator${skipped === 1 ? ' is' : 's are'} not eligible for this action and will be left unchanged.`;
  }
  const leftOut = Number(excluded) || 0;
  if (leftOut > 0) {
    description += ` ${leftOut} unchecked indicator${leftOut === 1 ? ' was' : 's were'} excluded.`;
  }
  return {
    title: titles[action] || `Update ${n} indicators?`,
    description,
    confirmLabel: labels[action] || `Update ${n}`,
    cancelLabel: 'Cancel',
    eligible: n,
    matching: match
  };
}

/**
 * Outcome copy for an across-pages action. Uses the server's counts and does
 * not describe a failure as a clean success.
 */
export function describeAcrossPagesOutcome(action, data) {
  if (action === 'create_iocs') {
    const errors = Array.isArray(data?.errors) ? data.errors.length : Number(data?.summary?.failed || 0);
    return describeCreateIocFeedback({
      created: data?.summary?.created ?? 0,
      existing: data?.summary?.already_existing ?? 0,
      errors
    });
  }
  const updated = Number(data?.updated);
  const errors = Array.isArray(data?.errors) ? data.errors.length : 0;
  const ineligible = Number(data?.ineligible || 0);
  const base = describeReviewFeedback(action, {
    count: Number.isFinite(updated) ? updated : null,
    errors
  });
  if (errors > 0) return base;
  if (ineligible > 0) return `${base} ${ineligible} not eligible and left unchanged.`;
  return base;
}

/** Success banner after Create IOCs (confirmed run). */
export function describeCreateIocFeedback({ created = 0, existing = 0, errors = 0, skipped = 0 } = {}) {
  const c = Number(created) || 0;
  const e = Number(existing) || 0;
  const errs = Number(errors) || 0;
  const skip = Number(skipped) || 0;
  const head = c === 1 ? 'IOC created.' : `${c} IOCs created.`;
  const parts = [head];
  if (e > 0) parts.push(`${e} already existed.`);
  if (skip > 0) parts.push(`${skip} skipped.`);
  if (errs > 0) parts.push(`${errs} error${errs === 1 ? '' : 's'}.`);
  return parts.join(' ');
}

/** sessionStorage key for an in-flight Create IOCs request (refresh awareness). */
export const CREATE_IOC_SESSION_KEY = 'talonhound.tl.createIocs';

export function formatElapsedMs(ms) {
  const n = Math.max(0, Number(ms) || 0);
  const sec = Math.floor(n / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  const rem = sec % 60;
  return `${min}m ${rem}s`;
}

/**
 * True when the browser lost the response and server-side creation may have
 * committed rows. Never treat these as "zero IOCs created".
 */
export function isCreateIocAmbiguousFailure(err) {
  if (!err) return false;
  if (err?.response?.data?.code === 'create_iocs_in_progress') return false;
  if (err?.response?.data?.code === 'create_iocs_none_eligible') return false;
  if (err?.response?.data?.code === 'selection_conflict') return false;
  if (err?.response?.data?.code === 'report_not_ready_for_review') return false;
  const status = Number(err?.response?.status);
  if (status === 409 || status === 400 || status === 403 || status === 404) return false;
  if (status >= 500) return true;
  if (status === 504 || status === 502 || status === 408) return true;
  if (!err.response) return true;
  const msg = String(err?.message || err?.code || '');
  return /timeout|network|aborted|econnaborted|err_network/i.test(msg);
}

export function writeCreateIocSession(payload) {
  if (typeof sessionStorage === 'undefined') return;
  try {
    sessionStorage.setItem(CREATE_IOC_SESSION_KEY, JSON.stringify({
      reportId: payload?.reportId || null,
      startedAt: payload?.startedAt || Date.now(),
      eligible: Number(payload?.eligible) || 0,
      selected: Number(payload?.selected) || 0,
      acrossPages: payload?.acrossPages === true
    }));
  } catch {
    /* best-effort */
  }
}

export function readCreateIocSession(reportId) {
  if (typeof sessionStorage === 'undefined') return null;
  try {
    const raw = sessionStorage.getItem(CREATE_IOC_SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || String(parsed.reportId) !== String(reportId)) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function clearCreateIocSession() {
  if (typeof sessionStorage === 'undefined') return;
  try {
    sessionStorage.removeItem(CREATE_IOC_SESSION_KEY);
  } catch {
    /* best-effort */
  }
}

/**
 * Presentation model for the Create IOCs operation panel.
 * Progress is indeterminate unless the caller supplies committed counts
 * (never a fabricated percentage).
 *
 * @returns {{
 *   phase: 'processing'|'completed'|'failed'|'ambiguous',
 *   title: string,
 *   body: string,
 *   detail: string|null,
 *   counts: { eligible: number, selected: number, created: number, existing: number, skipped: number, failed: number }|null,
 *   elapsedLabel: string|null,
 *   dismissible: boolean,
 *   indeterminate: boolean
 * }|null}
 */
export function describeCreateIocOperationPanel({
  phase,
  eligible = 0,
  selected = 0,
  summary = null,
  elapsedMs = 0,
  error = null
} = {}) {
  const elig = Number(eligible) || 0;
  const sel = Number(selected) || elig;
  if (phase === 'processing') {
    return {
      phase: 'processing',
      title: 'Creating IOCs',
      body: elig > 0
        ? `Processing ${elig.toLocaleString()} eligible indicator${elig === 1 ? '' : 's'}… Please wait.`
        : 'Creating IOCs… Please wait.',
      detail: 'Do not refresh or navigate away while this request is in progress. Duplicate submissions are blocked.',
      counts: { eligible: elig, selected: sel, created: 0, existing: 0, skipped: 0, failed: 0 },
      elapsedLabel: formatElapsedMs(elapsedMs),
      dismissible: false,
      indeterminate: true
    };
  }
  if (phase === 'completed') {
    const created = Number(summary?.created) || 0;
    const existing = Number(summary?.already_existing ?? summary?.existing) || 0;
    const failed = Number(summary?.failed) || 0;
    const notApproved = Number(summary?.not_approved) || 0;
    const notApplicable = Number(summary?.not_applicable) || 0;
    const unsupported = Number(summary?.unsupported) || 0;
    const skipped = notApproved + notApplicable + unsupported;
    const bits = [
      `${created.toLocaleString()} IOC${created === 1 ? '' : 's'} created`,
      `${existing.toLocaleString()} already existed`
    ];
    if (skipped > 0) bits.push(`${skipped.toLocaleString()} skipped`);
    if (failed > 0) bits.push(`${failed.toLocaleString()} failed`);
    return {
      phase: 'completed',
      title: 'IOC creation complete',
      body: bits.join(' · '),
      detail: elig > 0 ? `Eligible for creation: ${elig.toLocaleString()}.` : null,
      counts: { eligible: elig, selected: sel, created, existing, skipped, failed },
      elapsedLabel: elapsedMs > 0 ? formatElapsedMs(elapsedMs) : null,
      dismissible: true,
      indeterminate: false
    };
  }
  if (phase === 'ambiguous') {
    return {
      phase: 'ambiguous',
      title: 'Create IOCs response interrupted',
      body: 'The browser lost the response. IOC records may already have been created on the server.',
      detail: 'Indicator results were refreshed. Review the IOC Result column before running Create IOCs again. Do not assume zero IOCs were created.',
      counts: null,
      elapsedLabel: elapsedMs > 0 ? formatElapsedMs(elapsedMs) : null,
      dismissible: true,
      indeterminate: false
    };
  }
  if (phase === 'failed') {
    return {
      phase: 'failed',
      title: 'IOC creation failed',
      body: String(error || 'Create IOCs failed before a result could be confirmed.'),
      detail: 'No automatic retry was started. Review indicators and try again only if needed.',
      counts: null,
      elapsedLabel: elapsedMs > 0 ? formatElapsedMs(elapsedMs) : null,
      dismissible: true,
      indeterminate: false
    };
  }
  return null;
}

/** Compact counter line for the completed Create IOCs panel. */
export function formatCreateIocCountLine(counts) {
  if (!counts) return '';
  const parts = [];
  if (counts.created != null) parts.push(`Created ${Number(counts.created) || 0}`);
  if (counts.existing != null) parts.push(`Existing ${Number(counts.existing) || 0}`);
  if (counts.skipped) parts.push(`Skipped ${Number(counts.skipped) || 0}`);
  if (counts.failed) parts.push(`Failed ${Number(counts.failed) || 0}`);
  return parts.join(' · ');
}
