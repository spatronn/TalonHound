import test from 'node:test';
import assert from 'node:assert/strict';
import { buildExportBatchQuery } from './exportRows.js';
import { parseSearchQuery, buildWhereClause } from '../iocSearchDsl/index.js';

function compile(q) {
  const { ast } = parseSearchQuery(q);
  return buildWhereClause(ast, { timezone: 'UTC' });
}

function assertPlaceholdersAligned(sql, params) {
  const refs = [...sql.matchAll(/\$(\d+)/g)].map((m) => Number(m[1]));
  const max = refs.length ? Math.max(...refs) : 0;
  assert.equal(max, params.length);
  for (let i = 1; i <= params.length; i += 1) assert.ok(refs.includes(i));
}

test('first batch: snapshot cutoff appended, no keyset', () => {
  const { sql: whereSql, params: dslParams } = compile('ioc contains "evil"');
  const cutoff = '2026-07-22T00:00:00.000Z';
  const { sql, params } = buildExportBatchQuery({ whereSql, dslParams, cutoff, cursor: null, batchSize: 5000 });
  assert.match(sql, /i\.created_at <= \$2::timestamptz/);
  assert.doesNotMatch(sql, /\(i\.created_at, i\.id\) </);
  assert.match(sql, /ORDER BY i\.created_at DESC, i\.id DESC/);
  assert.equal(params[params.length - 1], 5000); // limit last
  assert.equal(params[1], cutoff);
  assertPlaceholdersAligned(sql, params);
});

test('subsequent batch: keyset predicate added with cursor params', () => {
  const { sql: whereSql, params: dslParams } = compile('ioc contains "evil"');
  const cutoff = '2026-07-22T00:00:00.000Z';
  const cursor = { t: '2026-07-20T10:00:00.000Z', id: '12345' };
  const { sql, params } = buildExportBatchQuery({ whereSql, dslParams, cutoff, cursor, batchSize: 5000 });
  assert.match(sql, /\(i\.created_at, i\.id\) < \(\$3::timestamptz, \$4::bigint\)/);
  assert.equal(params[2], cursor.t);
  assert.equal(params[3], '12345');
  assertPlaceholdersAligned(sql, params);
});

test('multi-condition DSL params precede cutoff/keyset/limit', () => {
  const { sql: whereSql, params: dslParams } = compile('tag in ("a","b") AND status equals "active"');
  const cutoff = '2026-07-22T00:00:00.000Z';
  const cursor = { t: '2026-07-20T10:00:00.000Z', id: '99' };
  const { sql, params } = buildExportBatchQuery({ whereSql, dslParams, cutoff, cursor, batchSize: 1000 });
  // dslParams first, then cutoff, then cursor(t,id), then limit
  assert.equal(params.length, dslParams.length + 4);
  assert.equal(params[dslParams.length], cutoff);
  assert.equal(params[params.length - 1], 1000);
  assertPlaceholdersAligned(sql, params);
});
