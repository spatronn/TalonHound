import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildVtNotIndexedResponse,
  isVtResourceNotFound,
  vtHttpErrorMessage
} from './virustotalEnrichment.js';

test('isVtResourceNotFound detects VT 404 only', () => {
  assert.equal(isVtResourceNotFound(404), true);
  assert.equal(isVtResourceNotFound(403), false);
  assert.equal(isVtResourceNotFound(429), false);
});

test('buildVtNotIndexedResponse is non-error not_found payload', () => {
  const body = buildVtNotIndexedResponse({ fetched_at: '2026-05-31T00:00:00.000Z' });
  assert.equal(body.status, 'not_found');
  assert.equal(body.provider, 'virustotal');
  assert.equal(body.is_error, false);
  assert.match(body.message, /no report/i);
  assert.equal(body.fetched_at, '2026-05-31T00:00:00.000Z');
});

test('vtHttpErrorMessage distinguishes auth and rate limit', () => {
  assert.match(vtHttpErrorMessage(401), /API key/i);
  assert.match(vtHttpErrorMessage(403), /API key/i);
  assert.match(vtHttpErrorMessage(429), /rate limit/i);
  assert.match(vtHttpErrorMessage(502), /failed/i);
});
