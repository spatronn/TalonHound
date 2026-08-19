import test from 'node:test';
import assert from 'node:assert/strict';
import {
  EMPTY_TAG_FORM,
  TAG_MANAGER_PAGE_SIZE,
  TAG_MANAGER_TABLE_COLUMNS,
  buildTagFormFromTag,
  buildTagManagerQueryParams,
  buildTagManagerUrlSearchParams,
  buildTagSavePayload,
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

test('Tag Manager table has no Category column', () => {
  assert.deepEqual(TAG_MANAGER_TABLE_COLUMNS, ['Name', 'Source', 'Description', 'Active', 'Actions']);
  assert.ok(!TAG_MANAGER_TABLE_COLUMNS.includes('Category'));
});

test('Add Tag form has no category or color field', () => {
  assert.deepEqual(EMPTY_TAG_FORM, { name: '', description: '', is_active: true });
  assert.ok(!('category' in EMPTY_TAG_FORM));
  assert.ok(!('color' in EMPTY_TAG_FORM));
});

test('Edit Tag form is built from a tag without carrying category or legacy color', () => {
  const form = buildTagFormFromTag({
    id: 7,
    name: '.net',
    category: 'behavior',
    description: 'legacy note',
    color: '#ef4444',
    is_active: false
  });
  assert.deepEqual(form, { name: '.net', description: 'legacy note', is_active: false });
  assert.ok(!('category' in form));
  assert.ok(!('color' in form));
});

test('Edit Tag form defaults to active for tags missing is_active', () => {
  assert.equal(buildTagFormFromTag({ name: 'x' }).is_active, true);
  assert.deepEqual(buildTagFormFromTag(null), { name: '', description: '', is_active: true });
});

test('Create payload omits category and color (name preserved)', () => {
  const payload = buildTagSavePayload({
    editingTag: null,
    form: { name: 'ransomware', description: 'd', color: '#fff', is_active: true }
  });
  assert.deepEqual(payload, { name: 'ransomware', description: 'd', is_active: true });
  assert.ok(!('category' in payload));
  assert.ok(!('color' in payload));
});

test('Update payload omits category, name and color (rename/color unsupported here)', () => {
  const payload = buildTagSavePayload({
    editingTag: { id: 3, name: '.net' },
    form: { name: '.net', description: 'updated', color: '#ef4444', is_active: false }
  });
  assert.deepEqual(payload, { description: 'updated', is_active: false });
  assert.ok(!('category' in payload));
  assert.ok(!('name' in payload));
  assert.ok(!('color' in payload));
});
