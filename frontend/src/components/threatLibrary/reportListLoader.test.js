import test from 'node:test';
import assert from 'node:assert/strict';
import { createReportListLoader } from './reportListLoader.js';

/** In-memory library: 157 reports, odd ids are threat_report. */
const LIBRARY = Array.from({ length: 157 }, (_, i) => ({
  id: `rep-${i + 1}`,
  title: `Library report ${String(i + 1).padStart(3, '0')}`,
  report_type: (i + 1) % 2 ? 'threat_report' : 'blog'
}));

function serverPage(params) {
  const q = String(params.search || '').toLowerCase();
  const rows = q ? LIBRARY.filter((r) => r.title.toLowerCase().includes(q) || r.report_type.includes(q)) : LIBRARY;
  return { items: rows.slice(params.offset, params.offset + params.limit), total: rows.length };
}

/** fetchPage whose resolution order is controlled by the test. */
function deferredFetch() {
  const calls = [];
  const fetchPage = (params, signal) => new Promise((resolve, reject) => {
    const call = { params, signal, resolve: () => resolve(serverPage(params)), reject };
    signal.addEventListener('abort', () => reject(Object.assign(new Error('canceled'), { name: 'CanceledError', code: 'ERR_CANCELED' })));
    calls.push(call);
  });
  return { calls, fetchPage };
}

test('initial load requests limit 25 / offset 0 and applies items + total', async () => {
  const { calls, fetchPage } = deferredFetch();
  const loader = createReportListLoader({ fetchPage });
  const p = loader.load({ search: '', page: 1 });
  assert.deepEqual(calls[0].params, { limit: 25, offset: 0 });
  calls[0].resolve();
  const r = await p;
  assert.equal(r.kind, 'applied');
  assert.equal(r.total, 157);
  assert.equal(r.items.length, 25);
  assert.equal(r.items[0].title, 'Library report 001');
});

test('Next then Previous request the next and previous offsets; final page holds 151-157', async () => {
  const { calls, fetchPage } = deferredFetch();
  const loader = createReportListLoader({ fetchPage });
  const p2 = loader.load({ page: 2 }); calls.at(-1).resolve();
  assert.deepEqual(calls.at(-1).params, { limit: 25, offset: 25 });
  assert.equal((await p2).items[0].title, 'Library report 026');
  const p1 = loader.load({ page: 1 }); calls.at(-1).resolve();
  assert.deepEqual(calls.at(-1).params, { limit: 25, offset: 0 });
  assert.equal((await p1).items[0].title, 'Library report 001');
  const p7 = loader.load({ page: 7 }); calls.at(-1).resolve();
  assert.deepEqual(calls.at(-1).params, { limit: 25, offset: 150 });
  const last = await p7;
  assert.equal(last.kind, 'applied');
  assert.equal(last.items.length, 7);
  assert.equal(last.items.at(-1).title, 'Library report 157');
});

test('a stale page-1 response cannot overwrite a newer page-2 response (page 2 resolves first)', async () => {
  const { calls, fetchPage } = deferredFetch();
  const loader = createReportListLoader({ fetchPage });
  const page1 = loader.load({ page: 1 });
  const page2 = loader.load({ page: 2 });
  // The older request is aborted the moment the newer one is issued.
  assert.equal(calls[0].signal.aborted, true);
  assert.equal(calls[1].signal.aborted, false);
  calls[1].resolve();
  const r2 = await page2;
  assert.equal(r2.kind, 'applied');
  assert.equal(r2.items[0].title, 'Library report 026');
  const r1 = await page1;
  assert.equal(r1.kind, 'stale');
});

test('a stale response that is not aborted (server still answers) is still ignored by sequence', async () => {
  // Fetch that ignores the abort signal, so ordering alone must protect us.
  const calls = [];
  const fetchPage = (params) => new Promise((resolve) => { calls.push({ params, resolve: () => resolve(serverPage(params)) }); });
  const loader = createReportListLoader({ fetchPage });
  const a = loader.load({ search: 'threat', page: 1 });
  const b = loader.load({ search: 'threat_report', page: 3 });
  calls[1].resolve();
  calls[0].resolve();
  assert.equal((await b).kind, 'applied');
  assert.equal((await a).kind, 'stale');
});

test('search resets pagination: a filtered load on page 1 carries the term and the filtered total', async () => {
  const { calls, fetchPage } = deferredFetch();
  const loader = createReportListLoader({ fetchPage });
  const p = loader.load({ search: 'threat_report', page: 1 }); calls[0].resolve();
  assert.deepEqual(calls[0].params, { limit: 25, offset: 0, search: 'threat_report' });
  const r = await p;
  assert.equal(r.total, 79, 'filtered total, not 157');
  assert.equal(r.items.length, 25);
  // Page 4 of the filtered set holds the last 4 matches.
  const p4 = loader.load({ search: 'threat_report', page: 4 }); calls[1].resolve();
  assert.deepEqual(calls[1].params, { limit: 25, offset: 75, search: 'threat_report' });
  assert.equal((await p4).items.length, 4);
});

test('clearing the search on page 1 sends the byte-identical unfiltered request', async () => {
  const { calls, fetchPage } = deferredFetch();
  const loader = createReportListLoader({ fetchPage });
  loader.load({ search: '', page: 1 });
  assert.deepEqual(calls[0].params, { limit: 25, offset: 0 });
  assert.equal('search' in calls[0].params, false);
});

test('result-count shrink: page 6 against a 2-page result set clamps to page 2 instead of stranding', async () => {
  const { calls, fetchPage } = deferredFetch();
  const loader = createReportListLoader({ fetchPage });
  // "Library report 00" matches 001-009 -> 9 rows -> 1 page; "1" matches many. Use a 2-page term.
  const p = loader.load({ search: 'Library report 0', page: 6 }); // matches 001-099 -> 99 rows -> 4 pages
  calls[0].resolve();
  const r = await p;
  assert.equal(r.kind, 'clamped');
  assert.equal(r.total, 99);
  assert.equal(r.page, 4);
  // The page then reloads the clamped page and gets rows, never an empty "no match".
  const p2 = loader.load({ search: 'Library report 0', page: r.page }); calls[1].resolve();
  const r2 = await p2;
  assert.equal(r2.kind, 'applied');
  assert.equal(r2.items.length, 24);
});

test('zero search results stay a valid page-1 "applied" outcome with total 0 (no clamp loop)', async () => {
  const { calls, fetchPage } = deferredFetch();
  const loader = createReportListLoader({ fetchPage });
  const p = loader.load({ search: 'zzz-nothing', page: 1 }); calls[0].resolve();
  const r = await p;
  assert.deepEqual(r, { kind: 'applied', items: [], total: 0 });
  // Even from a deep page the empty set clamps to page 1, once.
  const p3 = loader.load({ search: 'zzz-nothing', page: 3 }); calls[1].resolve();
  assert.deepEqual(await p3, { kind: 'clamped', total: 0, page: 1 });
});

test('Refresh re-issues the same search + page and applies fresh data', async () => {
  const { calls, fetchPage } = deferredFetch();
  const loader = createReportListLoader({ fetchPage });
  const first = loader.load({ search: 'blog', page: 2 }); calls[0].resolve(); await first;
  const refresh = loader.load({ search: 'blog', page: 2 }); calls[1].resolve();
  assert.deepEqual(calls[1].params, calls[0].params);
  assert.equal((await refresh).kind, 'applied');
});

test('errors surface only for the newest request; cancellations are stale', async () => {
  const calls = [];
  const fetchPage = (params, signal) => new Promise((resolve, reject) => {
    calls.push({ reject, resolve: () => resolve(serverPage(params)) });
    signal.addEventListener('abort', () => reject(Object.assign(new Error('x'), { name: 'AbortError' })));
  });
  const loader = createReportListLoader({ fetchPage });
  const a = loader.load({ page: 1 });
  const b = loader.load({ page: 2 });
  calls[1].reject(Object.assign(new Error('boom'), { response: { data: { message: 'DB down' } } }));
  assert.deepEqual(await b, { kind: 'error', message: 'DB down' });
  assert.equal((await a).kind, 'stale');
  const c = loader.load({ page: 1 });
  calls[2].reject(new Error('generic'));
  assert.deepEqual(await c, { kind: 'error', message: 'Failed to load Threat Library' });
});

test('abort() cancels the in-flight request (unmount) and reports stale', async () => {
  const { calls, fetchPage } = deferredFetch();
  const loader = createReportListLoader({ fetchPage });
  const p = loader.load({ page: 1 });
  loader.abort();
  assert.equal(calls[0].signal.aborted, true);
  assert.equal((await p).kind, 'stale');
});

test('rows per page: a 50-row load requests limit 50 and pages through 157 rows in 4 pages without gaps or repeats', async () => {
  const seen = [];
  const requested = [];
  const loader = createReportListLoader({ fetchPage: async (params) => { requested.push(params); return serverPage(params); } });
  for (let page = 1; page <= 4; page += 1) {
    const r = await loader.load({ page, pageSize: 50 });
    assert.equal(r.kind, 'applied');
    assert.equal(r.total, 157);
    seen.push(...r.items.map((x) => x.id));
  }
  assert.deepEqual(requested.map((p) => [p.limit, p.offset]), [[50, 0], [50, 50], [50, 100], [50, 150]]);
  assert.equal(seen.length, 157);
  assert.equal(new Set(seen).size, 157);
  assert.equal(seen.at(-1), 'rep-157');
});

test('rows per page: page 7 at 25/page is past the end at 50/page and clamps to page 4', async () => {
  const loader = createReportListLoader({ fetchPage: async (params) => serverPage(params) });
  assert.deepEqual(await loader.load({ page: 7, pageSize: 50 }), { kind: 'clamped', total: 157, page: 4 });
  const r = await loader.load({ page: 7, pageSize: 25 });
  assert.equal(r.kind, 'applied');
  assert.deepEqual(r.items.map((x) => x.id), ['rep-151', 'rep-152', 'rep-153', 'rep-154', 'rep-155', 'rep-156', 'rep-157']);
});

test('rows per page + search: the filtered total drives 25 vs 50 paging', async () => {
  const requested = [];
  const loader = createReportListLoader({ fetchPage: async (params) => { requested.push(params); return serverPage(params); } });
  // "threat_report" matches the 79 odd ids.
  const a = await loader.load({ search: 'threat_report', page: 2, pageSize: 50 });
  assert.equal(a.total, 79);
  assert.equal(a.items.length, 29);
  const b = await loader.load({ search: 'threat_report', page: 4, pageSize: 25 });
  assert.equal(b.items.length, 4);
  assert.deepEqual(requested.map((p) => p.limit), [50, 25]);
  // An unsupported size never reaches the API.
  await loader.load({ page: 1, pageSize: 200 });
  assert.equal(requested.at(-1).limit, 25);
});
