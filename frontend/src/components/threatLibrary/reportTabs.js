/**
 * Top-level sections of the Threat Library report page and their URL state.
 *
 * The section lives in the `view` query parameter so a deep link can open a
 * report on its Indicators or Source tab. The review table already owns
 * `tab` / `q` / `type` / `result` / `page` / `pageSize` (candidateReview.js);
 * `view` is carried alongside them, never mixed into them.
 */

export const REPORT_VIEWS = Object.freeze({
  OVERVIEW: 'overview',
  INDICATORS: 'indicators',
  ENTITIES: 'entities',
  SOURCE: 'source'
});

export const DEFAULT_REPORT_VIEW = REPORT_VIEWS.OVERVIEW;
export const REPORT_VIEW_PARAM = 'view';

const VIEW_IDS = new Set(Object.values(REPORT_VIEWS));
const REVIEW_TABLE_PARAMS = ['tab', 'filter', 'q', 'type', 'result', 'page', 'pageSize'];

function toParams(searchParams) {
  return searchParams && typeof searchParams.get === 'function'
    ? searchParams
    : new URLSearchParams(String(searchParams || ''));
}

/**
 * Resolve the active section from the URL. An explicit `view` wins; a link
 * that only carries review-table state (pre-redesign deep links such as
 * `?tab=needs_review`) still lands on the Indicators tab.
 */
export function parseReportView(searchParams) {
  const params = toParams(searchParams);
  const raw = String(params.get(REPORT_VIEW_PARAM) || '').toLowerCase();
  if (VIEW_IDS.has(raw)) return raw;
  if (REVIEW_TABLE_PARAMS.some((k) => params.has(k))) return REPORT_VIEWS.INDICATORS;
  return DEFAULT_REPORT_VIEW;
}

/** Add the section to serialized review-table params; Overview stays implicit. */
export function withReportView(params, view) {
  const next = new URLSearchParams(params ? params.toString() : '');
  next.delete(REPORT_VIEW_PARAM);
  if (view && view !== DEFAULT_REPORT_VIEW && VIEW_IDS.has(view)) next.set(REPORT_VIEW_PARAM, view);
  return next;
}

/**
 * Tab descriptors with live counts. A count is shown only when it is a stable
 * number: the indicator count is omitted while the candidate set is still
 * preliminary so an in-flight total is never presented as the report's size.
 *
 * @param {{ indicatorCount?: number|null, indicatorCountStable?: boolean, entityCount?: number|null }} counts
 * @returns {{ id: string, label: string, count: number|null }[]}
 */
export function buildReportTabs({ indicatorCount = null, indicatorCountStable = false, entityCount = null } = {}) {
  const indicators = indicatorCountStable && indicatorCount != null && Number.isFinite(Number(indicatorCount))
    ? Number(indicatorCount)
    : null;
  const entities = entityCount != null && Number.isFinite(Number(entityCount)) ? Number(entityCount) : null;
  return [
    { id: REPORT_VIEWS.OVERVIEW, label: 'Overview', count: null },
    { id: REPORT_VIEWS.INDICATORS, label: 'Indicators', count: indicators },
    { id: REPORT_VIEWS.ENTITIES, label: 'Entities', count: entities },
    { id: REPORT_VIEWS.SOURCE, label: 'Source', count: null }
  ];
}
