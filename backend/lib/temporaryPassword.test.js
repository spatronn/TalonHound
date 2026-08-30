import test from 'node:test';
import assert from 'node:assert/strict';
import { generateTemporaryPassword, TEMP_PASSWORD_POLICY } from './temporaryPassword.js';

const AMBIGUOUS = /[0O1lI]/;

test('has expected grouped shape and length', () => {
  const pw = generateTemporaryPassword();
  const groups = pw.split(TEMP_PASSWORD_POLICY.separator);
  assert.equal(groups.length, TEMP_PASSWORD_POLICY.groups);
  for (const g of groups) {
    assert.equal(g.length, TEMP_PASSWORD_POLICY.groupLength);
  }
  const raw = pw.replace(/-/g, '');
  assert.equal(raw.length, TEMP_PASSWORD_POLICY.length);
});

test('satisfies policy: upper, lower, digit and no ambiguous characters', () => {
  for (let i = 0; i < 500; i += 1) {
    const pw = generateTemporaryPassword();
    assert.match(pw, /[A-Z]/, 'missing uppercase');
    assert.match(pw, /[a-z]/, 'missing lowercase');
    assert.match(pw, /[0-9]/, 'missing digit');
    assert.ok(!AMBIGUOUS.test(pw), `contains ambiguous char: ${pw}`);
  }
});

test('is effectively unique across calls', () => {
  const seen = new Set();
  for (let i = 0; i < 1000; i += 1) {
    seen.add(generateTemporaryPassword());
  }
  // Allow for astronomically-unlikely collisions but flag systemic repetition.
  assert.ok(seen.size > 995, `too many duplicates: ${seen.size}/1000 unique`);
});
