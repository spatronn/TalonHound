import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSearchQuery, buildWhereClause } from './index.js';
import { buildDeepSearchSpoolInsertSql, buildCanonicalResultSelectSql } from './searchPageSql.js';

function whereFor(query, fa) {
  const { ast } = parseSearchQuery(query);
  return buildWhereClause(ast, { fileArtifactsReadEnabled: fa });
}

test('spool insert (non-FA) inserts positioned canonical rows with NO row cap', () => {
  const built = whereFor('ioc contains "evil"', false);
  const cutoffIdx = built.params.length + 1;
  const sql = buildDeepSearchSpoolInsertSql({
    fileArtifactsReadEnabled: false,
    whereSql: `(${built.sql}) AND i.created_at <= $${cutoffIdx}::timestamptz`,
    deepSearchIdIdx: built.params.length + 2
  });
  assert.match(sql, /INSERT INTO ioc_deep_search_results/);
  assert.match(sql, /ROW_NUMBER\(\) OVER \(ORDER BY c\.created_at DESC, c\.id DESC\)/);
  // Parameter placeholders wired correctly.
  assert.match(sql, /\$\d+::uuid,/); // deep_search_id
  // A completed Deep Search materializes the COMPLETE set — no artificial LIMIT/cap, no OFFSET.
  assert.ok(!/\bLIMIT\b/i.test(sql), 'spool insert must not cap the result set with LIMIT');
  assert.ok(!/OFFSET/i.test(sql), 'must not use OFFSET pagination');
});

test('spool insert (FA) reuses the canonical dedup CTEs (bounds + reps), no cap', () => {
  const built = whereFor('source contains "USOM"', true);
  const cutoffIdx = built.params.length + 1;
  const sql = buildDeepSearchSpoolInsertSql({
    fileArtifactsReadEnabled: true,
    whereSql: `(${built.sql}) AND i.created_at <= $${cutoffIdx}::timestamptz`,
    deepSearchIdIdx: built.params.length + 2
  });
  assert.match(sql, /WITH annotated AS/);
  assert.match(sql, /bounds AS/);
  assert.match(sql, /reps AS/);
  assert.match(sql, /identity_key/);
  assert.match(sql, /INSERT INTO ioc_deep_search_results/);
  assert.ok(!/\bLIMIT\b/i.test(sql), 'spool insert must not cap the result set with LIMIT');
});

test('canonical select exposes the interactive display columns', () => {
  const built = whereFor('ioc equals "example.com"', false);
  const sql = buildCanonicalResultSelectSql({ fileArtifactsReadEnabled: false, whereSql: built.sql });
  for (const col of ['id', 'public_id', 'observable', 'observable_type', 'status', 'first_seen_at', 'created_at', 'artifact_id']) {
    assert.match(sql, new RegExp(`\\b${col}\\b`), `missing column ${col}`);
  }
  assert.ok(!/LIMIT/i.test(sql), 'canonical select must not paginate itself');
});
