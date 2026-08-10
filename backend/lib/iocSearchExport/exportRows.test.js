import test from 'node:test';
import assert from 'node:assert/strict';
import { buildExportQuery } from './exportRows.js';
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

test('single-pass query: snapshot cutoff appended, no keyset, no LIMIT', () => {
  const { sql: whereSql, params: dslParams } = compile('ioc contains "evil"');
  const cutoff = '2026-07-22T00:00:00.000Z';
  const { sql, params } = buildExportQuery({ whereSql, dslParams, cutoff });
  // cutoff is the last bound param and gates the snapshot boundary.
  assert.match(sql, /i\.created_at <= \$2::timestamptz/);
  assert.equal(params[params.length - 1], cutoff);
  // The query is executed once through a cursor: no per-batch keyset, no LIMIT.
  assert.doesNotMatch(sql, /\(i\.created_at, i\.id\) </);
  assert.doesNotMatch(sql, /LIMIT/i);
  // Deterministic export order preserved.
  assert.match(sql, /ORDER BY i\.created_at DESC, i\.id DESC/);
  assertPlaceholdersAligned(sql, params);
});

test('predicate semantics for `ioc contains ".com"` are an ILIKE substring match', () => {
  const { sql: whereSql, params: dslParams } = compile('ioc contains ".com"');
  // The compiled predicate must remain a case-insensitive substring match on observable.
  assert.match(whereSql, /i\.observable ILIKE \$1 ESCAPE/);
  assert.equal(dslParams[0], '%.com%');
  // And the export query embeds exactly that predicate — export filtering is not weakened
  // or diverged from IOC list search semantics.
  const { sql } = buildExportQuery({ whereSql, dslParams, cutoff: 'x' });
  assert.ok(sql.includes(whereSql));
});

test('multi-condition DSL params precede the cutoff', () => {
  const { sql: whereSql, params: dslParams } = compile('tag in ("a","b") AND status equals "active"');
  const cutoff = '2026-07-22T00:00:00.000Z';
  const { sql, params } = buildExportQuery({ whereSql, dslParams, cutoff });
  // dslParams first, then cutoff (last).
  assert.equal(params.length, dslParams.length + 1);
  assert.equal(params[dslParams.length], cutoff);
  assertPlaceholdersAligned(sql, params);
});
