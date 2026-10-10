/**
 * Across-pages Threat Library indicator selection.
 *
 * Explicit mode keeps the historical candidate_ids contract.
 * All-matching mode resolves the analyst's active tab, type, result, and
 * search on the server, minus individually excluded candidate ids. The browser
 * never uploads the matching id list.
 *
 * Filter predicates match the review table (candidateReview.js). Membership
 * stays on indicatorMembership — Context Only and MODE A narrative rows are
 * not turned into Indicators here.
 */

import crypto from 'node:crypto';
import {
  isContextOnlyCandidate,
  isLinkedOnlyIndicatorMember,
  isPublisherAssertedReportIoc,
  isReportIndicatorMember,
  isUnionReportIndicatorMember,
  hasAuthoritativePublisherIocScope
} from './indicatorMembership.js';

export const SELECTION_TABS = Object.freeze([
  'indicators', 'total_unique', 'linked_only', 'existing', 'new', 'needs_review', 'context_only', 'all'
]);
export const SELECTION_SOURCES = Object.freeze(['all', 'original', 'linked', 'linked_only']);
export const SELECTION_MATCHES = Object.freeze(['all', 'existing', 'new']);
export const SELECTION_TYPES = Object.freeze(['all', 'ip', 'domain', 'url', 'hash', 'cidr']);
export const SELECTION_RESULTS = Object.freeze([
  'all', 'created', 'already_existing', 'unsupported', 'not_created'
]);

const TAB_SET = new Set(SELECTION_TABS);
const SOURCE_SET = new Set(SELECTION_SOURCES);
const MATCH_SET = new Set(SELECTION_MATCHES);
const TYPE_SET = new Set(SELECTION_TYPES);
const RESULT_SET = new Set(SELECTION_RESULTS);
const PRIMARY_SCOPE_TABS = new Set(['total_unique', 'needs_review', 'context_only', 'all']);
const HASH_TYPES = new Set(['md5', 'sha1', 'sha256']);
const IP_TYPES = new Set(['ip', 'ipv6']);
const PROMOTABLE_TYPES = new Set(['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256']);
const MAX_EXCLUSIONS = 10000;
const MAX_SEARCH = 200;
const TOKEN_RE = /^[a-f0-9]{64}$/;

const lower = (v) => String(v || '').toLowerCase();

function fail(error, code = 'selection_malformed') {
  return { ok: false, status: 400, code, error };
}

function normalizeIdList(value, label, max = MAX_EXCLUSIONS) {
  if (value == null) return { ok: true, ids: [] };
  if (!Array.isArray(value)) return fail(`${label} must be an array`);
  if (value.length > max) return fail(`Too many ${label}`);
  const ids = [];
  const seen = new Set();
  for (const raw of value) {
    const n = Number(raw);
    if (!Number.isInteger(n) || n <= 0) return fail(`Invalid ${label}`);
    if (!seen.has(n)) {
      seen.add(n);
      ids.push(n);
    }
  }
  return { ok: true, ids };
}

/**
 * @param {{ candidateIds?: unknown, selection?: object }} opts
 */
export function parseReviewSelection(opts = {}) {
  const selection = opts.selection;
  const hasIds = Array.isArray(opts.candidateIds) && opts.candidateIds.length > 0;
  if (selection != null && (typeof selection !== 'object' || Array.isArray(selection))) {
    return fail('Selection must be an object');
  }
  if (selection?.mode === 'all_matching') {
    if (hasIds) return fail('Send either candidate_ids or an all-matching selection, not both');
    const filters = selection.filters;
    if (filters == null || typeof filters !== 'object' || Array.isArray(filters)) {
      return fail('All-matching selection requires filters');
    }
    const tab = filters.tab == null ? '' : String(filters.tab);
    const source = filters.source == null || filters.source === '' ? 'all' : String(filters.source);
    const match = filters.match == null || filters.match === '' ? 'all' : String(filters.match);
    const type = filters.type == null || filters.type === '' ? 'all' : String(filters.type);
    const result = filters.result == null || filters.result === '' ? 'all' : String(filters.result);
    const tabOk = TAB_SET.has(tab) || String(tab).startsWith('source:');
    if (!tabOk) return fail('Invalid selection tab');
    if (!SOURCE_SET.has(source)) return fail('Invalid selection source');
    if (!MATCH_SET.has(match)) return fail('Invalid selection match');
    if (!TYPE_SET.has(type)) return fail('Invalid selection type');
    if (!RESULT_SET.has(result)) return fail('Invalid selection result');
    if (filters.search != null && typeof filters.search !== 'string') return fail('Invalid selection search');
    const search = String(filters.search || '');
    if (search.length > MAX_SEARCH) return fail('Selection search is too long');
    const excluded = normalizeIdList(selection.excluded_candidate_ids, 'excluded candidate ids');
    if (!excluded.ok) return excluded;
    let scopeToken = null;
    if (selection.scope_token != null && selection.scope_token !== '') {
      scopeToken = String(selection.scope_token);
      if (!TOKEN_RE.test(scopeToken)) return fail('Invalid selection token');
    }
    const dims = normalizeSelectionFilters({ tab, source, match });
    return {
      ok: true,
      mode: 'all_matching',
      ids: [],
      filters: { tab: dims.tab, source: dims.source, match: dims.match, type, result, search },
      excludedIds: excluded.ids,
      scopeToken
    };
  }
  if (selection?.mode != null && selection.mode !== 'explicit') {
    return fail('Unknown selection mode');
  }
  const ids = normalizeIdList(opts.candidateIds, 'candidate ids', 50000);
  if (!ids.ok) return ids;
  return {
    ok: true,
    mode: 'explicit',
    ids: ids.ids,
    filters: null,
    excludedIds: [],
    scopeToken: null
  };
}

/**
 * Same document-scope inference as the review table: if any loaded row is a
 * publisher-asserted IOC, narrative rows cannot enter Indicators just because
 * their own scope flag was omitted.
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
  const t = lower(candidate?.candidate_type);
  if (type === 'hash') return HASH_TYPES.has(t);
  if (type === 'ip') return IP_TYPES.has(t);
  return t === type;
}

/** Mirror of frontend classifyCreateOutcome, used only to match the result filter. */
function classifyCreateOutcome(candidate) {
  const c = candidate || {};
  const review = lower(c.review_status || 'pending');
  const assessment = lower(c.assessment);
  const state = lower(c.match_state);
  const type = lower(c.candidate_type);
  if (c.is_ioc === false
    || review === 'ignored' || review === 'context_only'
    || assessment === 'context_only' || assessment === 'invalid'
    || state === 'context_only' || state === 'invalid') return 'not_applicable';
  if (!isUnionReportIndicatorMember(c)) return 'not_applicable';
  if (!PROMOTABLE_TYPES.has(type)) return 'unsupported';
  if (review !== 'approved' && review !== 'created_ioc') return 'not_approved';
  if (assessment !== 'malicious' && assessment !== 'suspicious') return 'not_applicable';
  if (c.matched_ioc_id || review === 'created_ioc' || state === 'existing' || lower(c.promotion_outcome) === 'created') {
    return 'already_existing';
  }
  return 'will_create';
}

function iocResultOutcome(candidate) {
  const persisted = lower(candidate?.promotion_outcome);
  if (persisted === 'created' || persisted === 'already_existing') return persisted;
  if (classifyCreateOutcome(candidate) === 'already_existing') return 'already_existing';
  return persisted && persisted !== 'will_create' ? persisted : null;
}

export function candidateMatchesResultFilter(candidate, result) {
  if (!result || result === 'all') return true;
  const outcome = iocResultOutcome(candidate) || '';
  if (result === 'not_created') {
    return !outcome || outcome === 'not_approved' || outcome === 'not_applicable' || outcome === 'failed';
  }
  return outcome === result;
}

export function matchSelectionTab(candidate, tab) {
  if (tab === 'all') return true;
  const state = lower(candidate?.match_state);
  const review = lower(candidate?.review_status);
  if (tab === 'indicators') return isReportIndicatorMember(candidate);
  if (tab === 'total_unique') return isUnionReportIndicatorMember(candidate);
  if (tab === 'linked_only') return isLinkedOnlyIndicatorMember(candidate);
  if (tab === 'existing') {
    return isUnionReportIndicatorMember(candidate) && (state === 'existing' || Boolean(candidate?.matched_ioc_id));
  }
  if (tab === 'new') return isUnionReportIndicatorMember(candidate) && state === 'new';
  if (tab === 'context_only') {
    return state === 'context_only' || review === 'context_only' || candidate?.assessment === 'context_only';
  }
  if (tab === 'needs_review') {
    return (state === 'needs_review' || review === 'pending') && isUnionReportIndicatorMember(candidate);
  }
  if (String(tab || '').startsWith('source:')) {
    const sourceId = String(tab).slice('source:'.length);
    if (!isUnionReportIndicatorMember(candidate)) return false;
    return (candidate.sources || []).some((s) => s.id === sourceId);
  }
  return false;
}

/**
 * Expand legacy exclusive tabs into scope + source + match dimensions.
 * Mirrors frontend normalizeReviewFilterState.
 */
export function normalizeSelectionFilters(input = {}) {
  let tab = input.tab == null || input.tab === '' ? 'total_unique' : String(input.tab);
  let source = input.source == null || input.source === '' ? 'all' : String(input.source);
  let match = input.match == null || input.match === '' ? 'all' : String(input.match);

  if (tab === 'indicators') {
    tab = 'total_unique';
    if (source === 'all') source = 'original';
  } else if (tab === 'linked_only') {
    tab = 'total_unique';
    if (source === 'all') source = 'linked_only';
  } else if (tab === 'existing') {
    tab = 'total_unique';
    if (match === 'all') match = 'existing';
  } else if (tab === 'new') {
    tab = 'total_unique';
    if (match === 'all') match = 'new';
  }

  if (!(PRIMARY_SCOPE_TABS.has(tab) || TAB_SET.has(tab) || String(tab).startsWith('source:'))) {
    tab = 'total_unique';
  }
  if (!SOURCE_SET.has(source)) source = 'all';
  if (!MATCH_SET.has(match)) match = 'all';
  return { tab, source, match };
}

export function matchSelectionSource(candidate, source) {
  if (!source || source === 'all') return true;
  if (source === 'original') return candidate?.has_original_document_occurrence !== false;
  if (source === 'linked') {
    const ev = (candidate && candidate.evidence) || {};
    const assertion = lower(candidate?.source_assertion || ev.source_assertion);
    if (assertion === 'linked_source_ioc') return true;
    if (Array.isArray(candidate?.sources) && candidate.sources.length > 0) return true;
    return Array.isArray(ev.linked_sources) && ev.linked_sources.length > 0;
  }
  if (source === 'linked_only') return candidate?.has_original_document_occurrence === false;
  return true;
}

export function matchSelectionMatch(candidate, match) {
  if (!match || match === 'all') return true;
  const state = lower(candidate?.match_state);
  if (match === 'existing') return state === 'existing' || Boolean(candidate?.matched_ioc_id);
  if (match === 'new') return state === 'new';
  return true;
}

export function candidateMatchesSelectionFilters(candidate, filters) {
  const dims = normalizeSelectionFilters(filters || {});
  return matchSelectionTab(candidate, dims.tab)
    && matchSelectionSource(candidate, dims.source)
    && matchSelectionMatch(candidate, dims.match)
    && candidateMatchesQuery(candidate, filters.search)
    && candidateMatchesTypeFilter(candidate, filters.type)
    && candidateMatchesResultFilter(candidate, filters.result);
}

/**
 * @param {object[]} candidates persisted rows for one report
 * @param {{ mode: string, ids?: number[], filters?: object, excludedIds?: number[] }} selection
 */
export function filterCandidatesForSelection(candidates, selection) {
  const scoped = withInferredPublisherIocScope(candidates);
  if (selection.mode === 'explicit') {
    const ids = new Set((selection.ids || []).map(Number));
    return scoped.filter((c) => ids.has(Number(c.id)));
  }
  const excluded = new Set((selection.excludedIds || []).map(Number));
  return scoped.filter((c) => (
    candidateMatchesSelectionFilters(c, selection.filters)
    && !excluded.has(Number(c.id))
  ));
}

/**
 * Stable fingerprint of the resolved selection. Identity plus the fields a
 * review, match, or extraction refresh changes. Evidence JSON is not hashed;
 * those writes also bump updated_at.
 */
export function selectionScopeToken(rows) {
  const lines = (Array.isArray(rows) ? rows : []).map((r) => {
    let updated = '';
    if (r?.updated_at instanceof Date) updated = r.updated_at.toISOString();
    else if (r?.updated_at != null && r.updated_at !== '') updated = String(r.updated_at);
    const matched = r?.matched_ioc_id == null || r.matched_ioc_id === '' ? '' : String(Number(r.matched_ioc_id));
    return [
      Number(r.id),
      r.review_status || '',
      r.match_state || '',
      r.assessment || '',
      r.promotion_outcome || '',
      matched,
      r.is_ioc === false ? '0' : '1',
      updated
    ].join('\u001f');
  });
  lines.sort();
  return crypto.createHash('sha256').update(lines.join('\n')).digest('hex');
}

/**
 * Ids this action may change. Approve uses union Indicator membership
 * (original publisher ∪ linked-source). Context only skips rows that are
 * already context-only. Ignore applies to the whole selection. Create keeps
 * every selected row so the existing classifier can count skips.
 */
export function eligibleCandidateIds(action, rows) {
  const list = Array.isArray(rows) ? rows : [];
  if (action === 'approve') {
    return list.filter((c) => isUnionReportIndicatorMember(c)).map((c) => Number(c.id));
  }
  if (action === 'context_only') {
    return list.filter((c) => !isContextOnlyCandidate(c)).map((c) => Number(c.id));
  }
  return list.map((c) => Number(c.id));
}

/**
 * One indexed read of this report's candidates (idx_threat_report_candidates_report).
 * Filtering stays in process so it cannot drift from the table predicates or
 * from MODE A inference, which needs the whole report set.
 */
export async function loadSelectionScope(pool, reportId, selection) {
  const { rows } = await pool.query(
    `SELECT * FROM threat_report_candidates
     WHERE report_id = $1
     ORDER BY id`,
    [reportId]
  );
  const owned = rows.filter((r) => r.report_id == null || Number(r.report_id) === Number(reportId));
  const matched = filterCandidatesForSelection(owned, selection);
  return { rows: matched, token: selectionScopeToken(matched) };
}

export function selectionConflictResult({ matching, eligible, excluded, scopeToken }) {
  const matchCount = Number(matching) || 0;
  const eligibleCount = Number(eligible) || 0;
  return {
    ok: false,
    status: 409,
    code: 'selection_conflict',
    error: 'The selected indicators changed before this action ran. Review the updated count and confirm again.',
    matching: matchCount,
    eligible: eligibleCount,
    ineligible: Math.max(0, matchCount - eligibleCount),
    excluded: Number(excluded) || 0,
    scope_token: scopeToken
  };
}

const LOCK_SQL = `SELECT id, review_status, match_state, assessment, promotion_outcome, matched_ioc_id, is_ioc, updated_at
  FROM threat_report_candidates
  WHERE report_id = $1 AND id = ANY($2::bigint[])
  ORDER BY id
  FOR UPDATE`;

/**
 * Re-read the confirmed id list under row locks when the pool can open a
 * transaction. A mismatch aborts before any write. Callers that must not hold
 * the lock (Create IOCs) commit immediately after the check.
 * Fake pools without connect() rely on the pre-check token comparison.
 */
export async function confirmSelectionSnapshot(pool, reportId, matchingRows, expectedToken, work) {
  const ids = (matchingRows || []).map((r) => Number(r.id)).filter((n) => n > 0);
  if (typeof pool.connect !== 'function') {
    if (selectionScopeToken(matchingRows) !== expectedToken) {
      return { ok: false, conflict: true };
    }
    const result = await work(pool);
    return { ok: true, result };
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = ids.length
      ? await client.query(LOCK_SQL, [reportId, ids])
      : { rows: [] };
    if (selectionScopeToken(rows) !== expectedToken) {
      await client.query('ROLLBACK');
      return { ok: false, conflict: true };
    }
    const result = await work(client);
    if (result && result.ok === false) {
      await client.query('ROLLBACK');
      return { ok: true, result };
    }
    await client.query('COMMIT');
    return { ok: true, result };
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* already aborted */ }
    throw err;
  } finally {
    client.release();
  }
}
