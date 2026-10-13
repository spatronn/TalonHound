/**
 * Request state machine for the Threat Library report list. Owns the
 * "latest request wins" sequence token, the AbortController hand-off and the
 * post-load page clamp, and reports a plain outcome the page maps onto state.
 * Pure (no React) so search / page / Refresh races are unit-testable.
 */

import {
  REPORT_LIST_PAGE_SIZE,
  buildReportListQueryParams,
  clampReportListPage,
  normalizeReportListPhaseCounts
} from './reportList.js';

function isCancel(err) {
  return err?.code === 'ERR_CANCELED' || err?.name === 'CanceledError' || err?.name === 'AbortError';
}

/**
 * @param {object} deps
 * @param {(params: object, signal: AbortSignal) => Promise<{ items?: object[], total?: number }>} deps.fetchPage
 * @param {number} [deps.pageSize]
 * @param {() => AbortController} [deps.createAbortController]
 */
export function createReportListLoader({ fetchPage, pageSize = REPORT_LIST_PAGE_SIZE, createAbortController } = {}) {
  let seq = 0;
  let controller = null;
  const makeController = createAbortController || (() => new AbortController());

  return {
    /** Abort the in-flight request, if any (component unmount). */
    abort() {
      if (controller) controller.abort();
    },

    /**
     * Issue the request for { search, page, pageSize, sort, order, ...filters }
     * (filters = status / tlp / source / imported). Resolves to one of:
     *  - { kind: 'applied', items, total, phaseCounts }  newest response, page is valid
     *  - { kind: 'clamped', total, page, phaseCounts }   newest response but the page is past the end -> reload `page`
     *  - { kind: 'stale' }                   superseded by a later load (or aborted): ignore
     *  - { kind: 'error', message }          newest response failed
     * `phaseCounts` is the API's status-tab counts, or null when absent.
     */
    async load({ search = '', page = 1, pageSize: size = pageSize, sort = '', order = '', ...filters } = {}) {
      seq += 1;
      const mySeq = seq;
      if (controller) controller.abort();
      controller = makeController();
      const params = buildReportListQueryParams({ search, page, pageSize: size, sort, order, ...filters });
      try {
        const data = await fetchPage(params, controller.signal);
        if (mySeq !== seq) return { kind: 'stale' };
        const total = Number(data?.total || 0);
        const phaseCounts = normalizeReportListPhaseCounts(data?.phase_counts);
        const clamped = clampReportListPage(page, total, params.limit);
        if (clamped !== page) return { kind: 'clamped', total, page: clamped, phaseCounts };
        return { kind: 'applied', items: Array.isArray(data?.items) ? data.items : [], total, phaseCounts };
      } catch (err) {
        if (isCancel(err) || mySeq !== seq) return { kind: 'stale' };
        return { kind: 'error', message: err?.response?.data?.message || 'Failed to load Threat Library' };
      }
    }
  };
}
