import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSearchPageSql,
  buildSearchProbeSql,
  buildLegacyFileArtifactSearchPageSql,
  buildFileArtifactSearchPageSql,
  buildPlainSearchPageSql,
  canonicalSearchPageFromRows
} from './searchPageSql.js';
import { parseSearchQuery, buildWhereClause } from './index.js';

function dslWhere(query) {
  const { ast } = parseSearchQuery(query);
  return buildWhereClause(ast);
}

test('source contains USOM compiles to ILIKE on source_name', () => {
  const { sql, params } = dslWhere('source contains "USOM"');
  assert.match(sql, /i\.source_name ILIKE \$1/);
  assert.equal(params[0], '%USOM%');
});

test('source equals USOM:TR-CERT uses wildcard-free ILIKE (stable identity)', () => {
  const { sql, params } = dslWhere('source equals "USOM:TR-CERT"');
  assert.match(sql, /i\.source_name ILIKE \$1/);
  assert.equal(params[0], 'USOM:TR-CERT');
});

test('source + type filter keeps both predicates', () => {
  const { sql, params } = dslWhere('source contains "USOM" AND type equals "domain"');
  assert.match(sql, /source_name ILIKE/);
  assert.ok(sql.includes('observable_type') || sql.includes('file_artifact'));
  assert.ok(params.includes('%USOM%'));
  assert.ok(params.map(String).includes('domain'));
});

test('FA-off page sql applies ORDER BY + LIMIT on ioc_items (no identity aggregate)', () => {
  const sql = buildPlainSearchPageSql({
    whereSql: 'i.source_name ILIKE $1 ESCAPE \'\\\'',
    keysetClause: '',
    limitParamIdx: 2
  });
  assert.match(sql, /FROM ioc_items i/);
  assert.match(sql, /ORDER BY i\.created_at DESC, i\.id DESC/);
  assert.match(sql, /LIMIT \$2/);
  assert.doesNotMatch(sql, /identity_key|file_artifacts/);
});

test('FA-on page sql pages canonical bounds (MIN created_at) before LIMIT', () => {
  const sql = buildFileArtifactSearchPageSql({
    whereSql: 'i.source_name ILIKE $1 ESCAPE \'\\\'',
    limitParamIdx: 2
  });
  assert.match(sql, /WITH annotated AS/);
  assert.match(sql, /bounds AS/);
  assert.match(sql, /MIN\(created_at\) AS platform_imported_at/);
  assert.match(sql, /reps AS/);
  assert.match(sql, /DISTINCT ON \(identity_key\)/);
  assert.match(sql, /ORDER BY c\.platform_imported_at DESC, c\.id DESC/);
  assert.match(sql, /LIMIT \$2/);
  // Must not resurrect the legacy pattern of LIMIT-only-after full multi-col grouped SELECT
  // without a prior bounds/reps split — legacy builder still covered separately.
  assert.match(sql, /JOIN reps r ON r\.identity_key = b\.identity_key/);
});

test('FA-on page sql applies keyset on canonical (platform_imported_at, id)', () => {
  const sql = buildFileArtifactSearchPageSql({
    whereSql: 'i.source_name ILIKE $1 ESCAPE \'\\\'',
    cursorParamStart: 2,
    limitParamIdx: 4
  });
  assert.match(
    sql,
    /\(c\.platform_imported_at, c\.id\) < \(\$2::timestamptz, \$3::bigint\)/
  );
});

test('buildSearchPageSql respects FA flag', () => {
  const on = buildSearchPageSql({
    fileArtifactsReadEnabled: true,
    whereSql: 'TRUE',
    limitParamIdx: 1
  });
  const off = buildSearchPageSql({
    fileArtifactsReadEnabled: false,
    whereSql: 'TRUE',
    keysetClause: '',
    limitParamIdx: 1
  });
  assert.match(on, /platform_imported_at/);
  assert.doesNotMatch(off, /platform_imported_at/);
  assert.match(off, /ORDER BY i\.created_at DESC/);
});

test('probe FA path limits matched rows before identity distinct', () => {
  const sql = buildSearchProbeSql({
    fileArtifactsReadEnabled: true,
    whereSql: 'i.source_name ILIKE $1 ESCAPE \'\\\'',
    probeLimit: 51
  });
  assert.match(sql, /LIMIT 255/);
  assert.match(sql, /DISTINCT identity_key/);
});

test('legacy FA sql still aggregates full match set before LIMIT (documentation of root cause)', () => {
  const sql = buildLegacyFileArtifactSearchPageSql({
    whereSql: 'i.source_name ILIKE $1 ESCAPE \'\\\'',
    limitParamIdx: 2
  });
  assert.match(sql, /WITH matched AS/);
  assert.match(sql, /GROUP BY identity_key/);
  assert.match(sql, /ARRAY_AGG\(id ORDER BY/);
  const matchedCte = sql.match(/WITH matched AS \(([\s\S]*?)\)\s*,\s*ann AS/)?.[1] || '';
  assert.doesNotMatch(matchedCte, /\bLIMIT\b/i);
});

function sampleUsomRows() {
  return [
    // 1:1 domain identities (USOM typical)
    {
      id: 10, public_id: 'p10', observable: 'a.example', observable_type: 'domain',
      status: 'active', created_at: '2026-08-02T10:00:00Z',
      first_seen_at: '2026-08-02T10:00:00Z', last_seen_at: '2026-08-02T10:00:00Z',
      identity_key: 'o:domain:a.example', artifact_id: null
    },
    {
      id: 11, public_id: 'p11', observable: 'b.example', observable_type: 'domain',
      status: 'active', created_at: '2026-08-02T09:00:00Z',
      first_seen_at: '2026-08-02T09:00:00Z', last_seen_at: '2026-08-02T09:00:00Z',
      identity_key: 'o:domain:b.example', artifact_id: null
    },
    {
      id: 12, public_id: 'p12', observable: 'c.example', observable_type: 'domain',
      status: 'expired', created_at: '2026-08-02T08:00:00Z',
      first_seen_at: '2026-08-02T08:00:00Z', last_seen_at: '2026-08-02T08:00:00Z',
      identity_key: 'o:domain:c.example', artifact_id: null
    },
    // Collapsed artifact: MIN(created_at)=older md5, representative prefers sha256 primary
    {
      id: 20, public_id: 'p20', observable: 'deadbeef', observable_type: 'md5',
      status: 'active', created_at: '2026-07-01T00:00:00Z',
      first_seen_at: '2026-07-01T00:00:00Z', last_seen_at: '2026-07-01T00:00:00Z',
      identity_key: 'a:art-1', artifact_id: 'art-1',
      primary_hash_type: 'sha256', primary_hash_value: 'aa'.repeat(32)
    },
    {
      id: 21, public_id: 'p21', observable: 'aa'.repeat(32), observable_type: 'sha256',
      status: 'active', created_at: '2026-08-01T00:00:00Z',
      first_seen_at: '2026-08-01T00:00:00Z', last_seen_at: '2026-08-01T00:00:00Z',
      identity_key: 'a:art-1', artifact_id: 'art-1',
      primary_hash_type: 'sha256', primary_hash_value: 'aa'.repeat(32)
    }
  ];
}

test('canonical page1 order uses platform_imported_at = MIN(created_at)', () => {
  const page1 = canonicalSearchPageFromRows(sampleUsomRows(), { limit: 3 });
  assert.deepEqual(page1.map((r) => r.identity_key), [
    'o:domain:a.example',
    'o:domain:b.example',
    'o:domain:c.example'
  ]);
  // Artifact group has MIN=Jul 1 so sorts after August domains
  const rest = canonicalSearchPageFromRows(sampleUsomRows(), { limit: 10 });
  assert.equal(rest[3].identity_key, 'a:art-1');
  assert.equal(rest[3].created_at, '2026-07-01T00:00:00Z');
  assert.equal(rest[3].observable_type, 'sha256');
  assert.equal(rest[3].id, 21);
});

test('canonical page2 keyset continues from page1 without duplicates/missing', () => {
  const page1 = canonicalSearchPageFromRows(sampleUsomRows(), { limit: 2 });
  assert.equal(page1.length, 2);
  const cursor = { t: page1[1].created_at, id: page1[1].id };
  const page2 = canonicalSearchPageFromRows(sampleUsomRows(), { limit: 2, cursor });
  const keys1 = new Set(page1.map((r) => r.identity_key));
  for (const row of page2) assert.equal(keys1.has(row.identity_key), false);
  assert.deepEqual(page2.map((r) => r.identity_key), [
    'o:domain:c.example',
    'a:art-1'
  ]);
  const all = canonicalSearchPageFromRows(sampleUsomRows(), { limit: 100 });
  assert.equal(all.length, 4);
  assert.equal(new Set(all.map((r) => r.identity_key)).size, 4);
});

test('FA-on/off compatible: 1:1 identities match item-level created_at order', () => {
  const oneToOne = sampleUsomRows().filter((r) => r.identity_key.startsWith('o:'));
  const faPage = canonicalSearchPageFromRows(oneToOne, { limit: 10 });
  const plain = [...oneToOne].sort((a, b) => {
    const d = new Date(b.created_at) - new Date(a.created_at);
    return d !== 0 ? d : Number(b.id) - Number(a.id);
  });
  assert.deepEqual(
    faPage.map((r) => r.id),
    plain.map((r) => r.id)
  );
});
