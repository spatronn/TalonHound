// Presentation helpers for IOC Deep Search (async broad-query path). Pure functions so the
// IOC List / Action Center UI stays thin and the behavior is unit-testable.

export const DEEP_SEARCH_TASK_TYPE = 'ioc_deep_search';

// Human-friendly labels for the machine reason codes the backend classifier emits. Kept
// deliberately non-technical — never surface SQL internals to analysts.
const REASON_LABELS = Object.freeze({
  leading_wildcard: 'a broad wildcard match',
  negative_predicate: 'a negative (NOT) condition',
  broad_or: 'many OR conditions',
  source_scan: 'a source-wide match',
  no_selective_predicate: 'no narrowly-indexed condition',
  interactive_statement_timeout: 'exceeding the interactive time limit'
});

export function deepSearchReasonLabel(reason) {
  return REASON_LABELS[String(reason || '')] || 'a broad query';
}

/**
 * Calm, non-error banner text shown on the IOC List when a search is (or was auto-)continued
 * as a Deep Search. `fallback` distinguishes the classifier path from the timeout conversion.
 * Copy directs the analyst to Action Center — never imply results will appear on this page.
 */
export function deepSearchNotice({ fallback = false } = {}) {
  const body = 'This search is running in the background. View its progress and results in Action Center.';
  if (fallback) {
    return {
      title: 'Search continued in the background',
      body
    };
  }
  return {
    title: 'Deep search started',
    body
  };
}

/** True when an /api/iocs/search response indicates the query was routed to Deep Search. */
export function isDeepSearchResponse(data) {
  return Boolean(data) && data.mode === 'deep_search' && Boolean(data.deep_search_id);
}

/**
 * IOC List is in the queued/running handoff state: a Deep Search was created and the analyst
 * has not opened a completed result set yet. Mutually exclusive with result-browsing mode.
 */
export function isDeepSearchPending({ deepNotice, deepResult } = {}) {
  return Boolean(deepNotice) && !deepResult;
}

/**
 * Whether the normal IOC List result chrome (page size, empty-state, table, browse prev/next)
 * should render. Hidden for pending Deep Search and for non-ready Deep Search result states
 * (expired / failed / cancelled / still processing / load error) so those never leak a
 * misleading "0 matching IOCs" empty table.
 */
export function shouldShowIocListResultChrome({ deepNotice, deepResult } = {}) {
  if (isDeepSearchPending({ deepNotice, deepResult })) return false;
  if (deepResult && deepResult.result_state !== 'ready') return false;
  return true;
}

/** URL that opens the IOC List in Deep Search result-browsing mode. */
export function deepSearchResultsPath(id) {
  return `/ioc?deep_search=${encodeURIComponent(String(id || ''))}`;
}

/** URL that opens Action Center and highlights a specific Deep Search (or other) task. */
export function deepSearchActionCenterPath(id) {
  const tid = String(id || '').trim();
  if (!tid) return '/action-center';
  return `/action-center?task=${encodeURIComponent(tid)}`;
}

/**
 * Merge export + deep-search Action Center rows into one list sorted by created_at DESC.
 * Both serializers share the same envelope fields (id, task_type, status, created_at), so a
 * single table renders them uniformly.
 */
export function mergeActionCenterItems(exports = [], deepSearches = []) {
  const all = [...(exports || []), ...(deepSearches || [])];
  return all.sort((a, b) => {
    const ta = new Date(a?.created_at || 0).getTime();
    const tb = new Date(b?.created_at || 0).getTime();
    return tb - ta;
  });
}

/** Compact "Matches" cell for a deep-search Action Center row. A completed Deep Search holds
 *  the complete matching set, so match_count is exact (no truncation indicator). */
export function deepSearchMatchLabel(row) {
  if (!row || row.task_type !== DEEP_SEARCH_TASK_TYPE) return null;
  if (row.match_count == null) return '—';
  return Number(row.match_count).toLocaleString('en-US');
}

/** Duration cell (seconds, one decimal) for a completed deep-search row. */
export function deepSearchDurationLabel(row) {
  if (!row || row.duration_ms == null) return '—';
  const ms = Number(row.duration_ms);
  if (!Number.isFinite(ms)) return '—';
  return `${(ms / 1000).toFixed(1)} s`;
}
