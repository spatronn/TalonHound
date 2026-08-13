import test from 'node:test';
import assert from 'node:assert/strict';
import {
  API_IOC_PAGE_MAX,
  API_IOC_PAGE_DEFAULT,
  clampApiIocPageSize,
  encodeApiIocCursor,
  decodeApiIocCursor,
  searchApiIocs,
  exportApiIocs
} from './apiIocReadService.js';
import { API_ERROR_CODE } from './apiV1Errors.js';

test('clampApiIocPageSize bounds to 1..100', () => {
  assert.equal(clampApiIocPageSize(undefined), API_IOC_PAGE_DEFAULT);
  assert.equal(clampApiIocPageSize('nope'), API_IOC_PAGE_DEFAULT);
  assert.equal(clampApiIocPageSize(0), 1);
  assert.equal(clampApiIocPageSize(-3), 1);
  assert.equal(clampApiIocPageSize(2.9), 2);
  assert.equal(clampApiIocPageSize(5000), API_IOC_PAGE_MAX);
  assert.equal(clampApiIocPageSize(50), 50);
});

test('cursor encode/decode round-trips; garbage is invalid', () => {
  const raw = encodeApiIocCursor({ t: '2026-08-01T00:00:00.000Z', id: '42' });
  assert.deepEqual(decodeApiIocCursor(raw), { t: '2026-08-01T00:00:00.000Z', id: '42' });
  assert.equal(decodeApiIocCursor(null), null);
  assert.equal(decodeApiIocCursor(''), null);
  assert.equal(decodeApiIocCursor('%%%not-base64%%%').invalid, true);
  assert.equal(decodeApiIocCursor(Buffer.from('{}', 'utf8').toString('base64url')).invalid, true);
});

function forbiddenPool() {
  return {
    async query() {
      throw new Error('SQL must not run for rejected queries');
    },
    async connect() {
      throw new Error('SQL must not run for rejected queries');
    }
  };
}

test('search rejects empty, malformed, and expensive queries without SQL', async () => {
  const pool = forbiddenPool();
  const empty = await searchApiIocs(pool, { query: '  ' });
  assert.equal(empty.status, 400);
  assert.equal(empty.error.code, API_ERROR_CODE.VALIDATION_ERROR);

  const malformed = await searchApiIocs(pool, { query: 'severity equals "high"' });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.error.code, API_ERROR_CODE.VALIDATION_ERROR);

  const expensive = await searchApiIocs(pool, { query: 'source contains "x"' });
  assert.equal(expensive.status, 400);
  assert.equal(expensive.error.code, API_ERROR_CODE.QUERY_TOO_EXPENSIVE);
});

test('export rejects expensive queries and invalid format without SQL', async () => {
  const pool = forbiddenPool();
  const fmt = await exportApiIocs(pool, { query: 'type equals "domain"', format: 'stix' });
  assert.equal(fmt.status, 400);
  assert.equal(fmt.error.code, API_ERROR_CODE.VALIDATION_ERROR);

  const expensive = await exportApiIocs(pool, { query: 'source contains "USOM"', format: 'json' });
  assert.equal(expensive.status, 400);
  assert.equal(expensive.error.code, API_ERROR_CODE.QUERY_TOO_EXPENSIVE);
});
