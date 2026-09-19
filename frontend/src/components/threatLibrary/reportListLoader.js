/**
 * Request state machine for the Threat Library report list. Owns the
 * "latest request wins" sequence token, the AbortController hand-off and the
 * post-load page clamp, and reports a plain outcome the page maps onto state.
 * Pure (no React) so search / page / Refresh races are unit-testable.
 */

import { REPORT_LIST_PAGE_SIZE, buildReportListQueryParams, clampReportListPage } from './reportList.js';

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
     * Issue the request for { search, page }. Resolves to one of:
     *  - { kind: 'applied', items, total }   newest response, page is valid
     *  - { kind: 'clamped', total, page }    newest response but the page is past the end -> reload `page`
     *  - { kind: 'stale' }                   superseded by a later load (or aborted): ignore
     *  - { kind: 'error', message }          newest response failed
     */
    async load({ search = '', page = 1 } = {}) {
      seq += 1;
      const mySeq = seq;
      if (controller) controller.abort();
      controller = makeController();
      const params = buildReportListQueryParams({ search, page, pageSize });
      try {
        const data = await fetchPage(params, controller.signal);
        if (mySeq !== seq) return { kind: 'stale' };
        const total = Number(data?.total || 0);
        const clamped = clampReportListPage(page, total, pageSize);
        if (clamped !== page) return { kind: 'clamped', total, page: clamped };
        return { kind: 'applied', items: Array.isArray(data?.items) ? data.items : [], total };
      } catch (err) {
        if (isCancel(err) || mySeq !== seq) return { kind: 'stale' };
        return { kind: 'error', message: err?.response?.data?.message || 'Failed to load Threat Library' };
      }
    }
  };
}
