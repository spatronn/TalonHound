import test from 'node:test';
import assert from 'node:assert/strict';
import { redactSensitive, pickSafeFields, REDACTED } from './auditRedaction.js';

test('redactSensitive masks known secret keys', () => {
  const input = {
    username: 'alice',
    password: 'secret123',
    api_key: 'sk-live-abc',
    nested: { token: 'jwt-here', note: 'ok' }
  };
  const out = redactSensitive(input);
  assert.equal(out.username, 'alice');
  assert.equal(out.password, REDACTED);
  assert.equal(out.api_key, REDACTED);
  assert.equal(out.nested.token, REDACTED);
  assert.equal(out.nested.note, 'ok');
});

test('pickSafeFields only includes requested fields and redacts', () => {
  const out = pickSafeFields({ id: 1, name: 'key', secret: 'x' }, ['id', 'name', 'secret']);
  assert.deepEqual(out, { id: 1, name: 'key', secret: REDACTED });
});

test('redactSensitive truncates very long strings', () => {
  const long = 'a'.repeat(5000);
  const out = redactSensitive(long);
  assert.ok(String(out).includes('[truncated]'));
  assert.ok(String(out).length < 5000);
});
