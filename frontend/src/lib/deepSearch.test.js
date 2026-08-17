import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isDeepSearchResponse,
  isDeepSearchPending,
  shouldShowIocListResultChrome,
  deepSearchNotice,
  deepSearchReasonLabel,
  deepSearchResultsPath,
  deepSearchActionCenterPath,
  mergeActionCenterItems,
  deepSearchMatchLabel,
  deepSearchDurationLabel
} from './deepSearch.js';

test('isDeepSearchResponse detects the 202 async contract', () => {
  assert.equal(isDeepSearchResponse({ mode: 'deep_search', deep_search_id: 'ds-1' }), true);
  assert.equal(isDeepSearchResponse({ mode: 'deep_search' }), false);
  assert.equal(isDeepSearchResponse({ items: [] }), false);
  assert.equal(isDeepSearchResponse(null), false);
});

test('deepSearchNotice: Action Center-focused copy for classified and timeout fallback', () => {
  const classified = deepSearchNotice({ fallback: false });
  assert.equal(classified.title, 'Deep search started');
  assert.equal(
    classified.body,
    'This search is running in the background. View its progress and results in Action Center.'
  );
  const fallback = deepSearchNotice({ fallback: true });
  assert.equal(fallback.title, 'Search continued in the background');
  assert.equal(fallback.body, classified.body);
  // Do not use phrases that imply results will appear on the IOC List page.
  assert.doesNotMatch(classified.body, /Searching|Loading results|Please wait/i);
});

test('isDeepSearchPending / shouldShowIocListResultChrome are mutually exclusive modes', () => {
  // A. Normal interactive search
  assert.equal(isDeepSearchPending({ deepNotice: null, deepResult: null }), false);
  assert.equal(shouldShowIocListResultChrome({ deepNotice: null, deepResult: null }), true);

  // B. Deep Search queued/running (handoff on IOC List)
  const pendingNotice = { fallback: false, deep_search_id: 'ds-1' };
  assert.equal(isDeepSearchPending({ deepNotice: pendingNotice, deepResult: null }), true);
  assert.equal(shouldShowIocListResultChrome({ deepNotice: pendingNotice, deepResult: null }), false);

  // C. Completed Deep Search opened from Action Center
  const ready = { result_state: 'ready', deep_search_id: 'ds-1' };
  assert.equal(isDeepSearchPending({ deepNotice: null, deepResult: ready }), false);
  assert.equal(shouldShowIocListResultChrome({ deepNotice: null, deepResult: ready }), true);

  // D. Expired — do not show normal zero-result chrome
  const expired = { result_state: 'expired', deep_search_id: 'ds-1' };
  assert.equal(shouldShowIocListResultChrome({ deepNotice: null, deepResult: expired }), false);

  // E. Failed / cancelled / load error — same: hide normal empty table
  for (const state of ['failed', 'cancelled', 'error', 'queued', 'running']) {
    assert.equal(
      shouldShowIocListResultChrome({ deepNotice: null, deepResult: { result_state: state } }),
      false,
      `chrome must be hidden for result_state=${state}`
    );
  }
});

test('deepSearchReasonLabel never leaks SQL and maps known codes', () => {
  assert.equal(deepSearchReasonLabel('source_scan'), 'a source-wide match');
  assert.equal(deepSearchReasonLabel('interactive_statement_timeout'), 'exceeding the interactive time limit');
  assert.equal(deepSearchReasonLabel('unknown_code'), 'a broad query');
});

test('deepSearchResultsPath builds the IOC List result-mode URL', () => {
  assert.equal(deepSearchResultsPath('ds-1'), '/ioc?deep_search=ds-1');
});

test('deepSearchActionCenterPath targets the specific task when an id is present', () => {
  assert.equal(deepSearchActionCenterPath('ds-1'), '/action-center?task=ds-1');
  assert.equal(deepSearchActionCenterPath(''), '/action-center');
  assert.equal(deepSearchActionCenterPath(null), '/action-center');
});

test('mergeActionCenterItems sorts both task types by created_at desc', () => {
  const exports = [{ id: 'e1', task_type: 'ioc_search_export', created_at: '2026-08-01T00:00:00Z' }];
  const deeps = [{ id: 'd1', task_type: 'ioc_deep_search', created_at: '2026-08-05T00:00:00Z' }];
  const merged = mergeActionCenterItems(exports, deeps);
  assert.equal(merged.length, 2);
  assert.equal(merged[0].id, 'd1');
  assert.equal(merged[1].id, 'e1');
});

test('mergeActionCenterItems includes query-wide bulk jobs', () => {
  const merged = mergeActionCenterItems(
    [{ id: 'e1', task_type: 'ioc_search_export', created_at: '2026-08-01T00:00:00Z' }],
    [{ id: 'd1', task_type: 'ioc_deep_search', created_at: '2026-08-05T00:00:00Z' }],
    [{ id: 'b1', task_type: 'ioc_bulk_query', created_at: '2026-08-17T00:00:00Z' }]
  );
  assert.equal(merged[0].id, 'b1');
  assert.equal(merged.length, 3);
});

test('deepSearchMatchLabel formats the exact complete count (no truncation marker)', () => {
  assert.equal(deepSearchMatchLabel({ task_type: 'ioc_deep_search', match_count: 485031 }), '485,031');
  assert.equal(deepSearchMatchLabel({ task_type: 'ioc_deep_search', match_count: 2000000 }), '2,000,000');
  assert.equal(deepSearchMatchLabel({ task_type: 'ioc_deep_search', match_count: null }), '—');
  assert.equal(deepSearchMatchLabel({ task_type: 'ioc_search_export' }), null);
});

test('deepSearchDurationLabel formats seconds', () => {
  assert.equal(deepSearchDurationLabel({ duration_ms: 8400 }), '8.4 s');
  assert.equal(deepSearchDurationLabel({ duration_ms: null }), '—');
});

test('IOC List Deep Search pending UX gates results and keeps Refine search', async () => {
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const here = path.dirname(fileURLToPath(import.meta.url));
  const mainJsx = await fs.readFile(path.join(here, '../main.jsx'), 'utf8');

  // Wiring: derived pending gate + Action Center path with task id.
  assert.match(mainJsx, /isDeepSearchPending\(\{ deepNotice, deepResult \}\)/);
  assert.match(mainJsx, /shouldShowIocListResultChrome\(\{ deepNotice, deepResult \}\)/);
  assert.match(mainJsx, /deepSearchActionCenterPath\(deepNotice\.deep_search_id\)/);
  assert.match(mainJsx, /deepSearchPending && \(\(\) => \{/);
  assert.match(mainJsx, /showIocListResultChrome && \(/);

  // Banner copy + CTA present.
  assert.match(mainJsx, /View in Action Center/);
  assert.match(mainJsx, /deepSearchNotice\(/);

  // Pending branch keeps Refine search and must not render the local "still going" result chrome.
  assert.match(mainJsx, /deepSearchPending \? \(/);
  assert.match(mainJsx, /Refine search/);
  assert.ok(
    !/Running in the background/.test(mainJsx),
    'pending Deep Search must not show "Running in the background..." on IOC List'
  );

  // Normal interactive + completed Deep Search result browsing still exist.
  assert.match(mainJsx, /ioc-table ioc-list-table/);
  assert.match(mainJsx, /Deep Search results/);
  assert.match(mainJsx, /View Results/);
  assert.match(mainJsx, /deepSearchResultsPath\(/);
  assert.match(mainJsx, /Export matching IOCs/);
  assert.match(mainJsx, /Page size:/);
  assert.match(mainJsx, /No matching IOC found across active, expired, and suppressed records\./);

  // Expired Deep Search copy preserved; Action Center open still wired.
  assert.match(mainJsx, /This deep search result set has expired/);
  assert.match(mainJsx, /deepSearchActionCenterPath\(deepResult\.deep_search_id\)/);

  // The old red "Search timed out because the query is too broad" client error is gone.
  assert.ok(!/Search timed out because the query is too broad/.test(mainJsx),
    'client must not surface the legacy red timeout error');
});
