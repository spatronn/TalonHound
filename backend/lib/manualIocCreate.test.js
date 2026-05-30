import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeSourceNameInput,
  validateSourceName,
  parseManualExpirationInput
} from './iocSourceValidation.js';
import { inferObservableType } from './manualIocCreate.js';

test('normalizeSourceNameInput replaces spaces and strips invalid chars', () => {
  assert.equal(normalizeSourceNameInput('Internal Hunting'), 'Internal_Hunting');
  assert.equal(normalizeSourceNameInput('  SOC@Manual! '), 'SOCManual');
});

test('validateSourceName enforces pattern', () => {
  assert.equal(validateSourceName('ab').ok, false);
  assert.equal(validateSourceName('Internal_Hunting').ok, true);
});

test('parseManualExpirationInput never expire', () => {
  const r = parseManualExpirationInput({ expiration_policy: 'never' });
  assert.equal(r.ok, true);
  assert.equal(r.policy, 'never');
  assert.equal(r.manual_expires_at, null);
  assert.equal(r.manual_override_reason, 'manual_never_expire');
});

test('parseManualExpirationInput expire after days', () => {
  const now = new Date('2026-05-30T12:00:00.000Z');
  const r = parseManualExpirationInput(
    { expiration_policy: 'expire_after_days', expire_days: 30 },
    { now }
  );
  assert.equal(r.ok, true);
  assert.equal(r.expire_days, 30);
  assert.equal(r.manual_override_reason, 'manual_custom_expire');
  const exp = new Date(r.manual_expires_at);
  assert.equal(exp.toISOString(), '2026-06-29T12:00:00.000Z');
});

test('parseManualExpirationInput rejects past custom date', () => {
  const now = new Date('2026-05-30T12:00:00.000Z');
  const r = parseManualExpirationInput(
    { expiration_policy: 'custom_date', expires_at: '2026-05-29T12:00:00.000Z' },
    { now }
  );
  assert.equal(r.ok, false);
});

test('inferObservableType detects ip domain url hash', () => {
  assert.equal(inferObservableType('1.2.3.4'), 'ip');
  assert.equal(inferObservableType('evil.com'), 'domain');
  assert.equal(inferObservableType('https://evil.com/x'), 'url');
  assert.equal(inferObservableType('a'.repeat(64)), 'hash');
});
