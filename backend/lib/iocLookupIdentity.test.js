/**
 * Unit regressions (no DB) for:
 *   BUG 1 — exact lookup false negative for proven file-artifact hash aliases.
 *   BUG 2 — API/MCP search serialized confidence/note/classifications/tags as empty.
 * The real-SQL proof lives in iocApiLookupConsistency.integration.test.js.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  compareArtifactAliasMemberships,
  resolveArtifactAliasMemberships,
  buildLookupMatchMetadata,
  IOC_MATCHED_VIA
} from './iocLookupIdentity.js';
import { artifactAliasIocMembershipSql } from './fileArtifacts/hashIdentitySql.js';
import { parseSearchQuery, buildWhereClause } from './iocSearchDsl/index.js';
import { buildPlainSearchPageSql } from './iocSearchDsl/searchPageSql.js';
import { hydrateIocApiMetadata } from './iocApiMetadata.js';
import { iocPairKey } from './iocThreatClassifications.js';
import { mcpLookupIoc, mcpBulkLookupIocs } from './mcpIocService.js';
import { searchApiIocs } from './apiIocReadService.js';

const CONFIG = { valueMaxChars: 2048, bulkLookupMax: 100, searchPageMax: 50 };
const MD5 = '821e593e80c598883433da88a5431e9d';
const SHA1 = '95ddd765865919f7328fef4d15f69b1ee67c0841';
const SHA256 = '3f5ff48aa4dc2c1af3deeb33a9cc576616dad37156ae9182831b1b2a5ae4ae20';
const UNKNOWN_SHA256 = 'f'.repeat(64);

const MD5_ROW = {
  id: 3475208,
  public_id: '91574d61-6ea3-464d-9bbe-1dde359b44a5',
  observable: MD5,
  observable_type: 'md5',
  status: 'active',
  confidence: 'high',
  note: 'Threat Library report',
  threat_classification: null,
  created_at: '2026-09-21T18:18:40.121Z',
  last_seen_at: '2026-09-21T18:18:40.121Z'
};

function withReadFlag(value, fn) {
  const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
  process.env.FILE_ARTIFACTS_READ_ENABLED = value;
  return Promise.resolve(fn()).finally(() => {
    if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
  });
}

/**
 * In-memory fake: one IOC row (MD5) linked to an artifact that also proves
 * SHA1 + SHA256. Answers exact lookup, bulk exact, alias LATERAL, hydrator and
 * sources queries by SQL shape.
 */
function aliasPool({ rows = [MD5_ROW], aliases = { [`sha1\0${SHA1}`]: [MD5_ROW], [`sha256\0${SHA256}`]: [MD5_ROW] }, tags = ['alpha', 'bravo'], slugs = ['phishing'] } = {}) {
  const pool = {
    queries: [],
    query: async (sql, params = []) => {
      const s = String(sql).replace(/\s+/g, ' ').trim();
      pool.queries.push({ sql: s, params });
      // Threat Library report-tag inheritance (hydrator): none unless a test seeds it.
      if (s.includes('threat_report_tags rt')) return { rows: [] };
      if (s.includes('CROSS JOIN LATERAL') && s.includes('file_artifact_hashes h')) {
        const out = [];
        params[0].forEach((type, i) => {
          for (const r of aliases[`${type}\0${params[1][i]}`] || []) {
            out.push({ alias_queried_type: type, alias_queried_value: params[1][i], ...r });
          }
        });
        return { rows: out };
      }
      if (s.includes('observable_type = $1 AND observable = $2') && s.includes('LIMIT 1')) {
        return { rows: rows.filter((r) => r.observable_type === params[0] && r.observable === params[1]).slice(0, 1) };
      }
      if (s.includes('DISTINCT ON (observable_type, observable)')) {
        return { rows: rows.filter((r) => params[0].some((t, i) => t === r.observable_type && params[1][i] === r.observable)) };
      }
      if (s.includes('WITH seeds AS')) {
        return { rows: params[0].map((id) => ({ seed_id: id, linked_id: id })) };
      }
      if (s.includes('SELECT id, observable_type, threat_classification FROM ioc_items WHERE id = ANY')) {
        return { rows: rows.filter((r) => params[0].map(Number).includes(Number(r.id))) };
      }
      if (s.includes('FROM ioc_threat_classifications')) {
        return { rows: rows.flatMap((r) => slugs.map((slug) => ({ ioc_id: r.id, ioc_observable_type: r.observable_type, classification_slug: slug }))) };
      }
      if (s.includes('ioc_tags it')) {
        const seeds = [...new Set(params[0].map(Number))];
        return { rows: seeds.flatMap((seed) => tags.map((name) => ({ seed_id: seed, name, type: 'threat', origins: ['manual'], source_name: null }))) };
      }
      if (s.includes('LEFT JOIN ioc_sources')) {
        return { rows: rows.filter((r) => r.observable_type === params[0] && r.observable === params[1]).map((r) => ({ ...r, ioc_source_id: 19, source_name: 'Threat_Library', catalog_source_name: 'Threat_Library' })) };
      }
      throw new Error(`Unexpected SQL: ${s.slice(0, 140)}`);
    }
  };
  return pool;
}

describe('BUG 1 — exact lookup through proven file-artifact aliases', () => {
  it('search DSL and lookup resolver share ONE alias SQL fragment', () => {
    const { ast } = parseSearchQuery(`sha256 equals "${SHA256}"`);
    const { sql } = buildWhereClause(ast, { timezone: 'UTC', fileArtifactsReadEnabled: true });
    assert.ok(sql.includes(artifactAliasIocMembershipSql(`'sha256'`, '$1')), 'search must embed the shared fragment');
  });

  it('lookup_ioc(SHA256) finds the MD5-backed IOC with explicit alias metadata', () => withReadFlag('1', async () => {
    const pool = aliasPool();
    const out = await mcpLookupIoc(pool, { value: SHA256 }, { config: CONFIG });
    assert.equal(out.body.found, true);
    assert.equal(out.body.id, MD5_ROW.id);
    assert.equal(out.body.type, 'md5');
    assert.equal(out.body.matched_via, IOC_MATCHED_VIA.FILE_ARTIFACT_ALIAS);
    assert.deepEqual(out.body.queried, { type: 'sha256', value: SHA256 });
    assert.deepEqual(out.body.record, { id: MD5_ROW.id, public_id: MD5_ROW.public_id, type: 'md5', value: MD5 });
    assert.deepEqual(out.body.classifications, ['phishing']);
    assert.deepEqual(out.body.tags, ['alpha', 'bravo']);
    assert.equal(out.body.sources[0].name, 'Threat_Library');
  }));

  it('lookup_ioc(SHA1) resolves the same way', () => withReadFlag('1', async () => {
    const out = await mcpLookupIoc(aliasPool(), { value: SHA1 }, { config: CONFIG });
    assert.equal(out.body.id, MD5_ROW.id);
    assert.deepEqual(out.body.queried, { type: 'sha1', value: SHA1 });
  }));

  it('direct stored hash stays exact and never runs the alias query', () => withReadFlag('1', async () => {
    const pool = aliasPool();
    const out = await mcpLookupIoc(pool, { value: MD5 }, { config: CONFIG });
    assert.equal(out.body.matched_via, IOC_MATCHED_VIA.EXACT);
    assert.equal(out.body.artifact_memberships, undefined);
    assert.ok(!pool.queries.some((q) => q.sql.includes('CROSS JOIN LATERAL')));
  }));

  it('unknown SHA256 is still found:false (no fuzzy fallback)', () => withReadFlag('1', async () => {
    const out = await mcpLookupIoc(aliasPool(), { value: UNKNOWN_SHA256 }, { config: CONFIG });
    assert.equal(out.body.found, false);
    assert.equal(out.body.type, 'sha256');
  }));

  it('read flag off: alias resolution issues no query (same gate as search)', () => withReadFlag('0', async () => {
    const pool = aliasPool();
    const out = await mcpLookupIoc(pool, { value: SHA256 }, { config: CONFIG });
    assert.equal(out.body.found, false);
    assert.ok(!pool.queries.some((q) => q.sql.includes('file_artifact_hashes')));
  }));

  it('bulk_lookup_iocs: aliases found, unknown missing, ONE alias query for the whole batch', () => withReadFlag('1', async () => {
    const pool = aliasPool();
    const out = await mcpBulkLookupIocs(pool, { iocs: [SHA256, SHA1, UNKNOWN_SHA256, MD5] }, { config: CONFIG });
    assert.equal(out.body.counts.existing, 3);
    assert.equal(out.body.counts.missing, 1);
    assert.equal(out.body.missing[0].value, UNKNOWN_SHA256);
    const sha = out.body.existing.find((e) => e.value === SHA256);
    assert.equal(sha.matched_via, 'file_artifact_alias');
    assert.equal(sha.record.type, 'md5');
    assert.deepEqual(sha.tags, ['alpha', 'bravo']);
    assert.equal(sha.note, MD5_ROW.note);
    assert.equal(out.body.existing.find((e) => e.value === MD5).matched_via, 'exact');
    const aliasQueries = pool.queries.filter((q) => q.sql.includes('CROSS JOIN LATERAL'));
    assert.equal(aliasQueries.length, 1);
    // Only hashes without a direct row reach the alias query.
    assert.deepEqual(aliasQueries[0].params[1].sort(), [SHA1, SHA256, UNKNOWN_SHA256].sort());
  }));

  it('resolver ignores non-hash inputs and issues nothing', () => withReadFlag('1', async () => {
    const pool = aliasPool();
    const out = await resolveArtifactAliasMemberships(pool, [{ type: 'domain', value: 'evil.example' }]);
    assert.equal(out.size, 0);
    assert.equal(pool.queries.length, 0);
  }));

  it('primary membership order is deterministic and independent of SQL row order', () => {
    const rows = [
      { id: 5, observable_type: 'md5', status: 'active', created_at: '2026-01-01T00:00:00Z' },
      { id: 9, observable_type: 'sha1', status: 'expired', created_at: '2025-01-01T00:00:00Z' },
      { id: 7, observable_type: 'sha1', status: 'active', created_at: '2026-02-01T00:00:00Z' },
      { id: 3, observable_type: 'sha1', status: 'active', created_at: '2026-02-01T00:00:00Z' }
    ];
    const a = [...rows].sort(compareArtifactAliasMemberships).map((r) => r.id);
    const b = [...rows].reverse().sort(compareArtifactAliasMemberships).map((r) => r.id);
    assert.deepEqual(a, [3, 7, 5, 9]);
    assert.deepEqual(b, a);
  });

  it('match metadata lists memberships only for alias matches', () => {
    const exact = buildLookupMatchMetadata({ queriedType: 'md5', queriedValue: MD5, record: MD5_ROW, matchedVia: 'exact' });
    assert.equal(exact.artifact_memberships, undefined);
    const alias = buildLookupMatchMetadata({ queriedType: 'sha256', queriedValue: SHA256, record: MD5_ROW, matchedVia: 'file_artifact_alias', memberships: [MD5_ROW] });
    assert.deepEqual(alias.artifact_memberships, [{ id: MD5_ROW.id, public_id: MD5_ROW.public_id, type: 'md5', value: MD5, status: 'active' }]);
  });
});

describe('BUG 2 — search results carry real metadata', () => {
  it('API search page SQL selects confidence/note/legacy classification; UI projection unchanged', () => {
    const api = buildPlainSearchPageSql({ whereSql: 'TRUE', limitParamIdx: 1, includeIocMetadata: true });
    assert.match(api, /i\.confidence, i\.note, i\.threat_classification/);
    const ui = buildPlainSearchPageSql({ whereSql: 'TRUE', limitParamIdx: 1 });
    assert.doesNotMatch(ui, /i\.confidence/);
  });

  it('searchApiIocs returns confidence/note/classifications/tags (were null/[] before)', async () => {
    const row = { id: 77, public_id: 'p77', observable: 'zerangbet.com', observable_type: 'domain', status: 'active', confidence: 'high', note: 'Auto-imported from ThreatFox', threat_classification: null, created_at: '2026-01-01T00:00:00Z' };
    const pool = aliasPool({ rows: [row], tags: ['clearfake', 'clickfix', 'etherhiding'], slugs: ['phishing'] });
    pool.connect = async () => ({
      query: async (sql) => (String(sql).includes('FROM ioc_items i') ? { rows: [row] } : { rows: [] }),
      release() {}
    });
    const out = await searchApiIocs(pool, { query: 'ioc equals "zerangbet.com"' });
    assert.equal(out.status, 200);
    const item = out.body.items[0];
    assert.equal(item.confidence, 'high');
    assert.equal(item.note, 'Auto-imported from ThreatFox');
    assert.deepEqual(item.classifications, ['phishing']);
    assert.deepEqual(item.tags, ['clearfake', 'clickfix', 'etherhiding']);
  });

  it('hydrator is batched: query count does not grow with row count', async () => {
    const mk = (n) => Array.from({ length: n }, (_, i) => ({ id: 1000 + i, observable_type: 'domain', observable: `d${i}.example`, threat_classification: null }));
    const small = aliasPool({ rows: mk(2) });
    const large = aliasPool({ rows: mk(40) });
    const smallMap = await hydrateIocApiMetadata(small, mk(2));
    const largeMap = await hydrateIocApiMetadata(large, mk(40));
    assert.equal(smallMap.size, 2);
    assert.equal(largeMap.size, 40);
    assert.equal(large.queries.length, small.queries.length);
    assert.ok(large.queries.length <= 3, `junction + tags + inherited report tags only when rows carry legacy column (got ${large.queries.length})`);
    assert.deepEqual(largeMap.get(iocPairKey(1039, 'domain')).classifications, ['phishing']);
  });

  it('hydrator on empty input issues no query', async () => {
    const pool = aliasPool();
    const out = await hydrateIocApiMetadata(pool, []);
    assert.equal(out.size, 0);
    assert.equal(pool.queries.length, 0);
  });
});
