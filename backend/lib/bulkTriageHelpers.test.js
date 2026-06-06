import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  normalizeDetectionBulkVerdict,
  normalizeIncidentBulkVerdict,
  parseBulkIds,
  parseIncidentBulkIds
} from './bulkTriageHelpers.js';

test('parseBulkIds enforces limit and dedupes', () => {
  const many = Array.from({ length: 101 }, (_, i) => i + 1);
  const over = parseBulkIds(many);
  assert.equal(over.ok, false);
  const ok = parseBulkIds([1, 1, 2, '3']);
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.ids, [1, 2, 3]);
});

test('normalizeDetectionBulkVerdict maps security test to fp', () => {
  assert.deepEqual(normalizeDetectionBulkVerdict('security_test'), { verdict: 'fp', securityTest: true });
  assert.deepEqual(normalizeDetectionBulkVerdict('tp'), { verdict: 'tp', securityTest: false });
  assert.equal(normalizeDetectionBulkVerdict('bad'), null);
});

test('normalizeIncidentBulkVerdict maps security test to FP', () => {
  assert.deepEqual(normalizeIncidentBulkVerdict('Security Test'), { verdict: 'FP', securityTest: true });
  assert.deepEqual(normalizeIncidentBulkVerdict('Suspicious'), { verdict: 'Suspicious', securityTest: false });
});

test('parseIncidentBulkIds accepts string incident ids', () => {
  const parsed = parseIncidentBulkIds(['892', '891', '892']);
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.ids, ['892', '891']);
});
