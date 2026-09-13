import test from 'node:test';
import assert from 'node:assert/strict';
import { validateReportSourceUrl } from './sourceUrl.js';

test('empty source URL clears provenance', () => {
  assert.deepEqual(validateReportSourceUrl(''), { ok: true, value: null });
  assert.deepEqual(validateReportSourceUrl('   '), { ok: true, value: null });
  assert.deepEqual(validateReportSourceUrl(null), { ok: true, value: null });
});

test('http and https URLs are accepted and normalized', () => {
  const a = validateReportSourceUrl('https://example.com/report/cta-nk-2026-0121');
  assert.equal(a.ok, true);
  assert.equal(a.value, 'https://example.com/report/cta-nk-2026-0121');

  const b = validateReportSourceUrl('  HTTP://example.com/path#frag  ');
  assert.equal(b.ok, true);
  assert.equal(b.value.startsWith('http://example.com/path'), true);
  assert.equal(b.value.includes('#'), false);
});

test('javascript, file, and data schemes are rejected', () => {
  assert.equal(validateReportSourceUrl('javascript:alert(1)').ok, false);
  assert.equal(validateReportSourceUrl('javascript:alert(1)').error, 'invalid_scheme');
  assert.equal(validateReportSourceUrl('file:///etc/passwd').ok, false);
  assert.equal(validateReportSourceUrl('data:text/html,hi').ok, false);
});

test('malformed values are rejected', () => {
  assert.equal(validateReportSourceUrl('not a url').ok, false);
  assert.equal(validateReportSourceUrl('not a url').error, 'malformed_url');
  assert.equal(validateReportSourceUrl('https://').ok, false);
});
