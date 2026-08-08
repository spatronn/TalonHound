import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isDeepSearchResponse,
  deepSearchNotice,
  deepSearchReasonLabel,
  deepSearchResultsPath,
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

test('deepSearchNotice: classified vs timeout-fallback copy, both non-alarming', () => {
  const classified = deepSearchNotice({ fallback: false });
  assert.match(classified.title, /Deep search started/i);
  assert.match(classified.body, /background/i);
  const fallback = deepSearchNotice({ fallback: true });
  assert.match(fallback.title, /continued/i);
  assert.match(fallback.body, /exceeded the time limit/i);
});

test('deepSearchReasonLabel never leaks SQL and maps known codes', () => {
  assert.equal(deepSearchReasonLabel('source_scan'), 'a source-wide match');
  assert.equal(deepSearchReasonLabel('interactive_statement_timeout'), 'exceeding the interactive time limit');
  assert.equal(deepSearchReasonLabel('unknown_code'), 'a broad query');
});

test('deepSearchResultsPath builds the IOC List result-mode URL', () => {
  assert.equal(deepSearchResultsPath('ds-1'), '/ioc?deep_search=ds-1');
});

test('mergeActionCenterItems sorts both task types by created_at desc', () => {
  const exports = [{ id: 'e1', task_type: 'ioc_search_export', created_at: '2026-08-01T00:00:00Z' }];
  const deeps = [{ id: 'd1', task_type: 'ioc_deep_search', created_at: '2026-08-05T00:00:00Z' }];
  const merged = mergeActionCenterItems(exports, deeps);
  assert.equal(merged.length, 2);
  assert.equal(merged[0].id, 'd1');
  assert.equal(merged[1].id, 'e1');
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

test('IOC List wires the Deep Search UX (calm banner, result mode, no red timeout)', async () => {
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const here = path.dirname(fileURLToPath(import.meta.url));
  const mainJsx = await fs.readFile(path.join(here, '../main.jsx'), 'utf8');
  // Deep Search response is detected and rendered with the calm banner + Action Center link.
  assert.match(mainJsx, /isDeepSearchResponse\(data\)/);
  assert.match(mainJsx, /deepSearchNotice\(/);
  assert.match(mainJsx, /View in Action Center/);
  // Result-browsing mode + Action Center "View Results".
  assert.match(mainJsx, /Deep Search results/);
  assert.match(mainJsx, /View Results/);
  assert.match(mainJsx, /deepSearchResultsPath\(/);
  // The old red "Search timed out because the query is too broad" client error is gone —
  // a queued Deep Search must never render as an error.
  assert.ok(!/Search timed out because the query is too broad/.test(mainJsx),
    'client must not surface the legacy red timeout error');
});
