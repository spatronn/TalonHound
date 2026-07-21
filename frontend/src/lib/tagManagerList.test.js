import test from 'node:test';
import assert from 'node:assert/strict';
import {
  TAG_MANAGER_PAGE_SIZE,
  buildTagManagerQueryParams,
  buildTagManagerUrlSearchParams,
  clampTagManagerPage,
  formatTagManagerShowingLabel,
  parseTagManagerUrlState
} from './tagManagerList.js';

test('formatTagManagerShowingLabel', () => {
  assert.equal(formatTagManagerShowingLabel({ page: 1, totalItems: 1243 }), 'Showing 1–25 of 1243');
  assert.equal(formatTagManagerShowingLabel({ page: 50, totalItems: 1243 }), 'Showing 1226–1243 of 1243');
  assert.equal(formatTagManagerShowingLabel({ page: 1, totalItems: 0 }), 'Showing 0 of 0');
});

test('buildTagManagerQueryParams defaults and search', () => {
  assert.deepEqual(buildTagManagerQueryParams({}), {
    page: 1,
    page_size: TAG_MANAGER_PAGE_SIZE,
    include_inactive: 'true'
  });
  assert.deepEqual(buildTagManagerQueryParams({ page: 2, search: ' mirai ', showInactive: false }), {
    page: 2,
    page_size: TAG_MANAGER_PAGE_SIZE,
    include_inactive: 'false',
    search: 'mirai'
  });
});

test('URL state round-trip omits defaults', () => {
  const params = buildTagManagerUrlSearchParams({ page: 2, search: 'elf', showInactive: false });
  assert.equal(params.get('page'), '2');
  assert.equal(params.get('search'), 'elf');
  assert.equal(params.get('show_inactive'), 'false');

  const parsed = parseTagManagerUrlState(params);
  assert.deepEqual(parsed, { page: 2, search: 'elf', showInactive: false });

  const defaults = parseTagManagerUrlState(new URLSearchParams());
  assert.deepEqual(defaults, { page: 1, search: '', showInactive: true });
});

test('clampTagManagerPage after disable empties last page', () => {
  assert.equal(clampTagManagerPage(5, 100), 4); // 100/25=4
  assert.equal(clampTagManagerPage(1, 0), 1);
  assert.equal(clampTagManagerPage(2, 25), 1);
});
