import test from 'node:test';
import assert from 'node:assert/strict';
import {
  API_IOC_PAGE_MAX,
  API_IOC_PAGE_DEFAULT,
  clampApiIocPageSize,
  encodeApiIocCursor,
  decodeApiIocCursor,
  searchApiIocs,
  listApiIocs,
  apiIocNextCursor,
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

// Regression: bulk feed imports share one millisecond. A cursor built from the
// JS Date (ms) sat before the row's real µs timestamp, so the next page's
// `(created_at, id) < (t, id)` skipped the rest of that batch (MCP search_iocs
// returned 246 of 419 "artex"-tagged IOCs).
function capturingPool(rows) {
  const seen = { sql: [], params: [] };
  const run = async (sql, params) => {
    seen.sql.push(sql);
    seen.params.push(params);
    return /^\s*SELECT/i.test(sql) ? { rows } : { rows: [] };
  };
  return {
    seen,
    query: run,
    async connect() {
      return { query: run, release() {} };
    }
  };
}

const MICRO_ROWS = [
  { id: 3931549, public_id: null, observable: '45.199.130.22', observable_type: 'ip', status: 'active',
    created_at: new Date('2026-11-16T15:32:03.128Z'), cursor_created_at: '2026-11-16T15:32:03.128734Z' },
  { id: 3931548, public_id: null, observable: '45.197.4.52', observable_type: 'ip', status: 'active',
    created_at: new Date('2026-11-16T15:32:03.128Z'), cursor_created_at: '2026-11-16T15:32:03.128734Z' }
];

test('search next_cursor carries the microsecond created_at key, not the ms Date', async () => {
  const pool = capturingPool(MICRO_ROWS);
  const out = await searchApiIocs(pool, { query: 'type equals "ip"', limit: 1 });
  assert.equal(out.status, 200);
  assert.equal(out.body.has_more, true);
  assert.deepEqual(decodeApiIocCursor(out.body.next_cursor), { t: '2026-11-16T15:32:03.128734Z', id: '3931549' });
  const pageSql = pool.seen.sql.find((s) => /FROM ioc_items i/.test(s));
  assert.match(pageSql, /to_char\(i\.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS\.US"Z"'\) AS cursor_created_at/);

  // The µs key is what the next page binds into the keyset predicate.
  const pool2 = capturingPool([]);
  await searchApiIocs(pool2, { query: 'type equals "ip"', limit: 1, cursor: out.body.next_cursor });
  const idx = pool2.seen.sql.findIndex((s) => /FROM ioc_items i/.test(s));
  assert.match(pool2.seen.sql[idx], /\(i\.created_at, i\.id\) < \(\$\d+::timestamptz, \$\d+::bigint\)/);
  assert.ok(pool2.seen.params[idx].includes('2026-11-16T15:32:03.128734Z'));
});

test('list next_cursor carries the microsecond created_at key', async () => {
  const pool = capturingPool(MICRO_ROWS);
  const out = await listApiIocs(pool, { limit: 1 });
  assert.equal(out.status, 200);
  assert.deepEqual(decodeApiIocCursor(out.body.next_cursor), { t: '2026-11-16T15:32:03.128734Z', id: '3931549' });
  assert.match(pool.seen.sql[0], /AS cursor_created_at/);
});

test('apiIocNextCursor falls back to the ISO Date when no µs key was selected', () => {
  const raw = apiIocNextCursor({ id: 7, created_at: new Date('2026-08-01T00:00:00.000Z') });
  assert.deepEqual(decodeApiIocCursor(raw), { t: '2026-08-01T00:00:00.000Z', id: '7' });
});
