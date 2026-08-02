import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSearchQuery, buildWhereClause } from './index.js';

function build(q, opts) {
  const { ast } = parseSearchQuery(q);
  return buildWhereClause(ast, { timezone: 'UTC', ...opts });
}

// Every placeholder $n must have a corresponding param and no value may be inlined.
function assertPlaceholdersMatchParams(sql, params) {
  const placeholders = [...sql.matchAll(/\$(\d+)/g)].map((m) => Number(m[1]));
  const maxRef = placeholders.length ? Math.max(...placeholders) : 0;
  assert.equal(maxRef, params.length, `max placeholder $${maxRef} vs ${params.length} params`);
  for (let i = 1; i <= params.length; i += 1) {
    assert.ok(placeholders.includes(i), `missing placeholder $${i}`);
  }
}

test('ioc contains is parameterized with ILIKE and escaped wildcards', () => {
  const { sql, params } = build('ioc contains "example.com"');
  assert.match(sql, /i\.observable ILIKE \$1 ESCAPE/);
  assert.deepEqual(params, ['%example.com%']);
  assertPlaceholdersMatchParams(sql, params);
});

test('ioc value is lowercased and LIKE metachars escaped', () => {
  const { params } = build('ioc contains "EXA%_MPLE"');
  assert.deepEqual(params, ['%exa\\%\\_mple%']);
});

test('injection payload is a bound parameter, never inlined SQL', () => {
  const { sql, params } = build('ioc equals "\'; DROP TABLE ioc_items; --"');
  assert.doesNotMatch(sql, /DROP TABLE/i);
  // Bound as an ILIKE parameter; the LIKE metachar `_` is escaped so it stays literal.
  assert.equal(params[0], "'; drop table ioc\\_items; --");
});

test('ioc equals uses wildcard-free ILIKE (trigram) not LOWER(col)=', () => {
  const { sql, params } = build('ioc equals "Example.COM"');
  assert.match(sql, /i\.observable ILIKE \$1 ESCAPE/);
  assert.doesNotMatch(sql, /LOWER\(i\.observable\) =/);
  assert.equal(params[0], 'example.com'); // lowercased, no % wildcards
  assert.doesNotMatch(String(params[0]), /%/);
});

test('ioc not_equals uses NOT ILIKE', () => {
  const { sql } = build('ioc not_equals "x"');
  assert.match(sql, /i\.observable NOT ILIKE \$1 ESCAPE/);
});

test('source equals uses wildcard-free ILIKE (trigram)', () => {
  const { sql, params } = build('source equals "USOM:TR-CERT"');
  assert.match(sql, /i\.source_name ILIKE \$1 ESCAPE/);
  assert.equal(params[0], 'USOM:TR-CERT');
});

test('AND / OR / NOT structure', () => {
  const { sql } = build('ioc contains "a" AND (tag equals "x" OR NOT status equals "active")');
  assert.match(sql, /AND/);
  assert.match(sql, /OR/);
  assert.match(sql, /NOT/);
});

test('type in maps to observable_type ANY (partition prunable)', () => {
  const { sql, params } = build('type in ("domain", "url")');
  assert.match(sql, /i\.observable_type = ANY\(\$1::text\[\]\)/);
  assert.deepEqual(params, [['domain', 'url']]);
});

test('type equals md5 stays raw when file-artifact read is off', () => {
  const { sql, params } = build('type equals "md5"', { fileArtifactsReadEnabled: false });
  assert.match(sql, /i\.observable_type = \$1/);
  assert.deepEqual(params, ['md5']);
  assert.doesNotMatch(sql, /file_artifact_hashes/);
});

test('type equals md5 uses canonical primary when file-artifact read is on', () => {
  const { sql, params } = build('type equals "md5"', { fileArtifactsReadEnabled: true });
  assert.match(sql, /file_artifact_ioc_links/);
  assert.match(sql, /ph\.is_primary = TRUE/);
  assert.match(sql, /ph\.hash_type = \$1/);
  assert.equal(params[0], 'md5');
  assertPlaceholdersMatchParams(sql, params);
});

test('known_hash_type equals md5 matches any known hash on artifact', () => {
  const { sql, params } = build('known_hash_type equals "md5"', { fileArtifactsReadEnabled: true });
  assert.match(sql, /file_artifact_hashes h/);
  assert.match(sql, /h\.hash_type = \$1/);
  assert.doesNotMatch(sql, /h\.is_primary/);
  assert.equal(params[0], 'md5');
  assertPlaceholdersMatchParams(sql, params);
});

test('observed_type alias maps to known_hash_type', () => {
  const { ast } = parseSearchQuery('observed_type equals "sha256"');
  assert.equal(ast.children?.[0]?.field || ast.field, 'known_hash_type');
});

test('status equals uses COALESCE default active', () => {
  const { sql } = build('status equals "active"');
  assert.match(sql, /COALESCE\(i\.status, 'active'\) = \$1/);
});

test('tag equals uses EXISTS with normalized lowercase name', () => {
  const { sql, params } = build('tag equals "MIRAI"');
  assert.match(sql, /EXISTS \(SELECT 1 FROM ioc_tags it JOIN tags t/);
  assert.match(sql, /it\.ioc_id = i\.id AND it\.ioc_observable_type = i\.observable_type/);
  assert.equal(params[0], 'mirai');
});

test('tag equals X AND tag equals Y requires both (two EXISTS)', () => {
  const { sql } = build('tag equals "mirai" AND tag equals "botnet"');
  const count = (sql.match(/EXISTS \(SELECT 1 FROM ioc_tags/g) || []).length;
  assert.equal(count, 2);
});

test('tag in matches any (single EXISTS with ANY)', () => {
  const { sql, params } = build('tag in ("mirai", "botnet")');
  const count = (sql.match(/EXISTS \(SELECT 1 FROM ioc_tags/g) || []).length;
  assert.equal(count, 1);
  assert.match(sql, /t\.name = ANY/);
  assert.deepEqual(params[0], ['mirai', 'botnet']);
});

test('tag not_contains negates EXISTS', () => {
  const { sql } = build('tag not_contains "mirai"');
  assert.match(sql, /NOT EXISTS \(SELECT 1 FROM ioc_tags/);
});

test('classification matches slug OR label', () => {
  const { sql } = build('classification equals "phishing"');
  assert.match(sql, /itc\.classification_slug = \$1 OR LOWER\(tc\.name\) = \$1/);
});

test('threat_actor equals via EXISTS on ioc_threat_actors junction', () => {
  const { sql, params } = build('threat_actor equals "APT29"');
  assert.match(sql, /EXISTS \(SELECT 1 FROM ioc_threat_actors ita/);
  assert.match(sql, /JOIN threat_actors ta ON ta\.id = ita\.threat_actor_id/);
  assert.equal(params[0], 'apt29');
});

test('item date after uses AT TIME ZONE with bound tz (created_at)', () => {
  const { sql, params } = build('created_at after "2026-07-01"', { timezone: 'Europe/Istanbul' });
  assert.match(sql, /i\.created_at > \(\$1::timestamp AT TIME ZONE \$2\)/);
  assert.deepEqual(params, ['2026-07-01 00:00:00', 'Europe/Istanbul']);
});

test('item date with explicit tz uses timestamptz cast (no AT TIME ZONE)', () => {
  const { sql, params } = build('created_at after "2026-07-01T18:00:00Z"');
  assert.match(sql, /i\.created_at > \$1::timestamptz/);
  assert.deepEqual(params, ['2026-07-01T18:00:00Z']);
});

test('item date between is inclusive range (created_at)', () => {
  const { sql } = build('created_at between "2026-07-01" AND "2026-07-22"');
  assert.match(sql, /i\.created_at >= .+ AND i\.created_at <= /);
});

test('last_seen is not a valid field (removed in v1)', () => {
  assert.throws(() => build('last_seen after "2026-07-01"'));
});

test('first_seen maps to MIN(first_seen_in_feed) with item fallback, never last_seen_in_feed', () => {
  const after = build('first_seen after "2026-07-01"');
  assert.match(after.sql, /SELECT MIN\(m\.first_seen_in_feed\) FROM ioc_feed_memberships m/);
  assert.match(after.sql, /COALESCE\(\(SELECT MIN\(m\.first_seen_in_feed\).+\), i\.first_seen_at\) > /);
  assert.doesNotMatch(after.sql, /last_seen_in_feed/);
  const between = build('first_seen between "2026-07-01" AND "2026-07-22"');
  assert.match(between.sql, />= .+ AND .+ <= /);
  assert.doesNotMatch(between.sql, /last_seen_in_feed/);
});

test('last_changed after uses EXISTS on memberships, never last_seen_in_feed', () => {
  const { sql } = build('last_changed after "2026-07-01"');
  assert.match(sql, /EXISTS \(SELECT 1 FROM ioc_feed_memberships m/);
  assert.match(sql, /COALESCE\(m\.last_changed_in_source, m\.first_seen_in_feed\) > /);
  assert.doesNotMatch(sql, /last_seen_in_feed/);
});

test('last_changed before uses MAX scalar subquery', () => {
  const { sql } = build('last_changed before "2026-07-22"');
  assert.match(sql, /SELECT MAX\(COALESCE\(m\.last_changed_in_source, m\.first_seen_in_feed\)\)/);
  assert.match(sql, /\) < /);
  assert.doesNotMatch(sql, /last_seen_in_feed/);
});

test('last_changed between uses MAX scalar subquery bounded both sides', () => {
  const { sql } = build('last_changed between "2026-07-01" AND "2026-07-22"');
  assert.match(sql, /SELECT MAX\(COALESCE\(m\.last_changed_in_source, m\.first_seen_in_feed\)\)/);
  assert.match(sql, />= .+ AND .+ <= /);
});

test('source in lowercases and binds array', () => {
  const { sql, params } = build('source in ("USOM", "URLHaus")');
  assert.match(sql, /LOWER\(i\.source_name\) = ANY\(\$1::text\[\]\)/);
  assert.deepEqual(params[0], ['usom', 'urlhaus']);
});

test('every generated query keeps placeholders and params aligned', () => {
  const queries = [
    'ioc contains "a" AND tag in ("x","y") OR NOT source equals "z"',
    'type in ("ip","ipv6") AND status equals "active" AND confidence not_equals "low"',
    'first_seen between "2026-01-01" AND "2026-12-31" AND last_changed after "2026-06-01"',
    'classification not_in ("phishing","malware") AND threat_actor contains "apt"'
  ];
  for (const q of queries) {
    const { sql, params } = build(q);
    assertPlaceholdersMatchParams(sql, params);
  }
});
