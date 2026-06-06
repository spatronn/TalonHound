import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRequiredReason } from './reasonValidation.js';

test('parseRequiredReason rejects empty reason', () => {
  const result = parseRequiredReason('');
  assert.equal(result.ok, false);
});

test('parseRequiredReason accepts valid reason', () => {
  const result = parseRequiredReason('Analyst confirmed benign');
  assert.equal(result.ok, true);
  assert.equal(result.reason, 'Analyst confirmed benign');
});
