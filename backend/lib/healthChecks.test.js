import test from 'node:test';
import assert from 'node:assert/strict';
import { buildHealthPayload } from './healthChecks.js';

test('buildHealthPayload includes status, timestamp, and checks', () => {
  const payload = buildHealthPayload('ok', { postgres: 'ok' });
  assert.equal(payload.status, 'ok');
  assert.ok(payload.timestamp);
  assert.equal(payload.checks.postgres, 'ok');
  assert.equal(payload.latestVersion, undefined);
  assert.equal(payload.releaseUrl, undefined);
  assert.equal(payload.checks.update, undefined);
});
