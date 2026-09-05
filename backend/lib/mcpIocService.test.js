import test from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveMcpIocInput,
  mcpLookupIoc,
  mcpGetIocContext,
  mcpBulkLookupIocs,
  mcpListIocSources,
  mcpImportIocs,
  buildMcpSearchDsl
} from './mcpIocService.js';
import { parseSearchQuery } from './iocSearchDsl/index.js';
import { loadEffectiveIocClassificationSlugs } from './iocThreatClassifications.js';
import { API_SYSTEM_SOURCE_NAME } from './apiSystemSource.js';
import { API_SCOPE } from './apiKeyProfiles.js';
import { MCP_DEFAULTS } from './mcpConfig.js';

const TEST_CONFIG = Object.freeze({
  valueMaxChars: MCP_DEFAULTS.VALUE_MAX_CHARS,
  bulkLookupMax: 5,
  importMax: 5,
  searchPageMax: 50
});

test('resolveMcpIocInput normalizes IP and domain', () => {
  const ip = resolveMcpIocInput(' 8.8.8.8 ', undefined, TEST_CONFIG);
  assert.equal(ip.ok, true);
  assert.equal(ip.type, 'ip');
  assert.equal(ip.value, '8.8.8.8');

  const domain = resolveMcpIocInput('Example.COM.', undefined, TEST_CONFIG);
  assert.equal(domain.ok, true);
  assert.equal(domain.type, 'domain');
  assert.equal(domain.value, 'example.com');
});

test('resolveMcpIocInput refines hash to concrete md5/sha1/sha256 storage types', () => {
  const sha256 = 'c5763c9ad5885c5fb7e83b38c373efa7eeb9cc146e524180ab5cce8157e1abd8';
  const sha1 = 'a'.repeat(40);
  const md5 = 'b'.repeat(32);

  const h256 = resolveMcpIocInput(sha256, undefined, TEST_CONFIG);
  assert.equal(h256.ok, true);
  assert.equal(h256.type, 'sha256');
  assert.equal(h256.value, sha256);

  const h256Explicit = resolveMcpIocInput(sha256, 'hash', TEST_CONFIG);
  assert.equal(h256Explicit.ok, true);
  assert.equal(h256Explicit.type, 'sha256');

  assert.equal(resolveMcpIocInput(sha1, 'hash', TEST_CONFIG).type, 'sha1');
  assert.equal(resolveMcpIocInput(md5, undefined, TEST_CONFIG).type, 'md5');

  // SHA-512 hex is accepted by the abstract hash validator but is not a storage type.
  const sha512 = 'c'.repeat(128);
  assert.equal(resolveMcpIocInput(sha512, 'hash', TEST_CONFIG).ok, false);
});

test('mcpLookupIoc finds sha256 IOC immediately after storage-type refinement', async () => {
  const sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const existing = {
    id: 3394624,
    public_id: 'd38d8db3-526d-4989-b8c8-e95ae85389d3',
    observable: sha256,
    observable_type: 'sha256',
    status: 'active',
    confidence: 'high',
    threat_classification: 'malware',
    note: null,
    created_at: '2026-09-05T14:32:01.476Z',
    last_seen_at: '2026-09-05T14:32:01.476Z'
  };
  const pool = makeLookupPool({
    existing,
    classifications: ['malware'],
    tags: [],
    sources: [{
      id: existing.id,
      ioc_source_id: 9,
      source_name: 'ThreatFox:abuse.ch',
      catalog_source_name: 'ThreatFox:abuse.ch',
      status: 'active',
      created_at: existing.created_at
    }]
  });

  const miss = await mcpLookupIoc(pool, { value: sha256 }, { config: TEST_CONFIG });
  // First call uses makeLookupPool which returns existing for any type match on SQL shape —
  // assert the query used concrete sha256, not abstract hash.
  const lookupQuery = pool.queries.find((q) =>
    q.sql.includes('observable_type = $1 AND observable = $2')
    && q.sql.includes('ORDER BY created_at ASC')
  );
  assert.ok(lookupQuery);
  assert.deepEqual(lookupQuery.params, ['sha256', sha256]);
  assert.equal(miss.status, 200);
  assert.equal(miss.body.found, true);
  assert.equal(miss.body.id, 3394624);
  assert.equal(miss.body.type, 'sha256');
});

test('mcpBulkLookupIocs uses concrete sha256 type in exact match query', async () => {
  const sha256 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  const foundRows = [{
    id: 42,
    public_id: '22222222-2222-4222-8222-222222222222',
    observable: sha256,
    observable_type: 'sha256',
    status: 'active',
    confidence: 'medium',
    threat_classification: null,
    note: null,
    created_at: '2026-01-01T00:00:00.000Z',
    last_seen_at: null
  }];
  const pool = makeBulkPool(foundRows);
  const out = await mcpBulkLookupIocs(pool, { iocs: [sha256] }, { config: TEST_CONFIG });
  assert.equal(out.status, 200);
  assert.equal(out.body.counts.existing, 1);
  assert.equal(out.body.counts.missing, 0);
  assert.equal(out.body.existing[0].type, 'sha256');
  assert.deepEqual(pool.queries[0].params[0], ['sha256']);
  assert.deepEqual(pool.queries[0].params[1], [sha256]);
});

test('resolveMcpIocInput rejects invalid / empty / overlong', () => {
  assert.equal(resolveMcpIocInput('', undefined, TEST_CONFIG).ok, false);
  assert.equal(resolveMcpIocInput('not an ioc!!!', undefined, TEST_CONFIG).ok, false);
  assert.equal(resolveMcpIocInput('1.2.3.4', 'notatype', TEST_CONFIG).ok, false);
  const huge = 'a'.repeat(TEST_CONFIG.valueMaxChars + 1);
  assert.equal(resolveMcpIocInput(huge, 'domain', TEST_CONFIG).ok, false);
});

function makeLookupPool({ existing = null, classifications = [], tags = [], sources = [] } = {}) {
  const queries = [];
  return {
    queries,
    query: async (sql, params = []) => {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      queries.push({ sql: normalized, params: [...params] });
      if (normalized.includes('FROM ioc_items')
        && normalized.includes('observable_type = $1 AND observable = $2')
        && normalized.includes('ORDER BY created_at ASC')) {
        return { rows: existing ? [existing] : [] };
      }
      // Legacy-column fallback read from loadEffectiveIocClassificationSlugs.
      if (normalized.includes('SELECT threat_classification FROM ioc_items')
        && normalized.includes('WHERE id = $1 AND observable_type = $2')) {
        return { rows: existing ? [{ threat_classification: existing.threat_classification ?? null }] : [] };
      }
      if (normalized.includes('FROM ioc_threat_classifications')) {
        return {
          rows: classifications.map((slug) => ({
            ioc_id: existing?.id,
            ioc_observable_type: existing?.observable_type,
            classification_slug: slug
          }))
        };
      }
      if (normalized.includes('FROM ioc_tags it')) {
        // loadCatalogTags groups and returns { name, type, origins, source_name }.
        return {
          rows: tags.map((t) => ({
            name: t.name,
            type: t.type ?? null,
            origins: t.origins ?? (t.origin ? [t.origin] : ['manual']),
            source_name: t.source_name ?? null
          }))
        };
      }
      if (normalized.includes('FROM ioc_items i') && normalized.includes('LEFT JOIN ioc_sources')) {
        return { rows: sources };
      }
      throw new Error(`Unexpected SQL in lookup pool: ${normalized.slice(0, 120)}`);
    }
  };
}

// Full mock for get_ioc_context: getApiIoc (SELECT * by id/public_id) + the
// effective-classification, catalog-tag, source-evidence and enrichment reads.
function makeContextPool({ row = null, classifications = [], tags = [], sources = [], evidence = [], enrichment = [], rdap = null, abuseipdb = null, ipinfo = null } = {}) {
  const queries = [];
  return {
    queries,
    connect: async () => ({ query: async () => ({ rows: [] }), release() {} }),
    query: async (sql, params = []) => {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      queries.push({ sql: normalized, params: [...params] });
      // getApiIoc row load (by public_id or id) and mcpLookupIoc exact match.
      if (normalized.includes('FROM ioc_items') && normalized.includes('WHERE public_id = $1::uuid')) {
        return { rows: row ? [row] : [] };
      }
      if (normalized.includes('FROM ioc_items')
        && normalized.includes('observable_type = $1 AND observable = $2')
        && normalized.includes('ORDER BY created_at ASC')) {
        return { rows: row ? [row] : [] };
      }
      if (normalized.includes('SELECT * FROM ioc_items WHERE id = $1')) {
        return { rows: row ? [row] : [] };
      }
      if (normalized.includes('SELECT threat_classification FROM ioc_items')
        && normalized.includes('WHERE id = $1 AND observable_type = $2')) {
        return { rows: row ? [{ threat_classification: row.threat_classification ?? null }] : [] };
      }
      if (normalized.includes('FROM ioc_threat_classifications')) {
        return {
          rows: classifications.map((slug) => ({
            ioc_id: row?.id,
            ioc_observable_type: row?.observable_type,
            classification_slug: slug
          }))
        };
      }
      if (normalized.includes('FROM ioc_tags it')) {
        return {
          rows: tags.map((t) => ({
            name: t.name,
            type: t.type ?? null,
            origins: t.origins ?? (t.origin ? [t.origin] : ['manual']),
            source_name: t.source_name ?? null
          }))
        };
      }
      if (normalized.includes('FROM ioc_items i') && normalized.includes('LEFT JOIN ioc_sources')) {
        return { rows: sources };
      }
      if (normalized.includes('FROM ioc_feed_source_evidence')) {
        return { rows: evidence };
      }
      if (normalized.includes('FROM ioc_enrichments')) {
        return { rows: enrichment };
      }
      if (normalized.includes('FROM ioc_domain_enrichment')) {
        return { rows: rdap ? [rdap] : [] };
      }
      if (normalized.includes('FROM ioc_abuseipdb_enrichment')) {
        return { rows: abuseipdb ? [abuseipdb] : [] };
      }
      if (normalized.includes('FROM ioc_ip_enrichment')) {
        return { rows: ipinfo ? [ipinfo] : [] };
      }
      throw new Error(`Unexpected SQL in context pool: ${normalized.slice(0, 120)}`);
    }
  };
}

test('mcpLookupIoc returns not found', async () => {
  const pool = makeLookupPool({ existing: null });
  const out = await mcpLookupIoc(pool, { value: '9.9.9.9' }, { config: TEST_CONFIG });
  assert.equal(out.status, 200);
  assert.equal(out.body.found, false);
  assert.equal(out.body.type, 'ip');
  assert.equal(out.body.value, '9.9.9.9');
});

test('mcpLookupIoc returns found hit', async () => {
  const existing = {
    id: 55,
    public_id: '11111111-1111-4111-8111-111111111111',
    observable: 'evil.example',
    observable_type: 'domain',
    status: 'active',
    confidence: 'high',
    threat_classification: 'phishing',
    note: null,
    created_at: '2026-01-01T00:00:00.000Z',
    last_seen_at: '2026-01-02T00:00:00.000Z'
  };
  const pool = makeLookupPool({
    existing,
    classifications: ['phishing'],
    tags: [{ id: 1, name: 'watched', type: null }],
    sources: [{
      id: 55,
      ioc_source_id: 3,
      source_name: 'Threat-Hunting',
      catalog_source_name: 'Threat-Hunting',
      status: 'active',
      created_at: existing.created_at
    }]
  });
  const out = await mcpLookupIoc(pool, { value: 'evil.example' }, { config: TEST_CONFIG });
  assert.equal(out.status, 200);
  assert.equal(out.body.found, true);
  assert.equal(out.body.id, 55);
  assert.equal(out.body.type, 'domain');
  assert.deepEqual(out.body.classifications, ['phishing']);
  assert.deepEqual(out.body.tags, ['watched']);
  assert.equal(out.body.sources.length, 1);
});

// junctionRows: rows of { ioc_id, ioc_observable_type, classification_slug } for
// the batched ioc_threat_classifications read (parity with the single-IOC loader).
function makeBulkPool(foundRows, junctionRows = []) {
  const queries = [];
  return {
    queries,
    query: async (sql, params = []) => {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      queries.push({ sql: normalized, params: [...params] });
      if (/FROM ioc_threat_classifications/i.test(normalized)) {
        return { rows: junctionRows };
      }
      assert.match(normalized, /unnest/i);
      return { rows: foundRows };
    }
  };
}

test('mcpBulkLookupIocs mixed found/missing/invalid/duplicates and over-limit', async () => {
  const over = await mcpBulkLookupIocs(
    { query: async () => ({ rows: [] }) },
    { iocs: ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5', '6.6.6.6'] },
    { config: TEST_CONFIG }
  );
  assert.equal(over.status, 400);
  assert.match(over.error.message, /maximum 5/i);

  const foundRows = [{
    id: 1,
    public_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
    observable: '1.1.1.1',
    observable_type: 'ip',
    status: 'active',
    confidence: 'medium',
    threat_classification: null,
    note: null,
    created_at: '2026-01-01T00:00:00.000Z',
    last_seen_at: null
  }];
  const pool = makeBulkPool(foundRows);
  const out = await mcpBulkLookupIocs(
    pool,
    {
      iocs: [
        '1.1.1.1',
        '2.2.2.2',
        'not-an-ioc!!!',
        '1.1.1.1'
      ]
    },
    { config: TEST_CONFIG }
  );
  assert.equal(out.status, 200);
  assert.equal(out.body.submitted, 4);
  assert.equal(out.body.counts.existing, 1);
  assert.equal(out.body.counts.missing, 1);
  assert.equal(out.body.counts.invalid, 1);
  assert.equal(out.body.counts.duplicate_in_request, 1);
  assert.ok(pool.queries.some((q) => /unnest/i.test(q.sql)));
});

// --- bulk_lookup_iocs classification parity (effective, batched) -----------

function bulkRow(id, observable, observable_type, threat_classification = null) {
  return {
    id,
    public_id: `00000000-0000-4000-8000-${String(id).padStart(12, '0')}`,
    observable,
    observable_type,
    status: 'active',
    confidence: 'medium',
    threat_classification,
    note: null,
    created_at: '2026-01-01T00:00:00.000Z',
    last_seen_at: null
  };
}
function jrow(id, observable_type, classification_slug) {
  return { ioc_id: id, ioc_observable_type: observable_type, classification_slug };
}
function bulkClassOf(out, value) {
  return out.body.existing.find((e) => e.value === value)?.classifications;
}

// Test 1 — junction-only classification (legacy column is 'unknown').
test('bulk_lookup_iocs: junction classification used when legacy column is unknown', async () => {
  const rows = [bulkRow(10, 'evil.test', 'domain', 'unknown')];
  const pool = makeBulkPool(rows, [jrow(10, 'domain', 'command_and_control')]);
  const out = await mcpBulkLookupIocs(pool, { iocs: [{ value: 'evil.test', type: 'domain' }] }, { config: TEST_CONFIG });
  assert.deepEqual(bulkClassOf(out, 'evil.test'), ['command_and_control']);
});

// Test 2 — legacy-only classification (no junction rows).
test('bulk_lookup_iocs: legacy classification preserved when no junction rows', async () => {
  const md5 = 'd41d8cd98f00b204e9800998ecf8427e';
  const rows = [bulkRow(11, md5, 'md5', 'dropper_downloader')];
  const pool = makeBulkPool(rows, []);
  const out = await mcpBulkLookupIocs(pool, { iocs: [{ value: md5, type: 'hash' }] }, { config: TEST_CONFIG });
  assert.deepEqual(bulkClassOf(out, md5), ['dropper_downloader']);
});

// Test 3 — junction + legacy both present: junction wins (canonical semantics).
test('bulk_lookup_iocs: junction wins over legacy when both present', async () => {
  const rows = [bulkRow(12, 'both.test', 'domain', 'phishing')];
  const pool = makeBulkPool(rows, [jrow(12, 'domain', 'command_and_control')]);
  const out = await mcpBulkLookupIocs(pool, { iocs: [{ value: 'both.test', type: 'domain' }] }, { config: TEST_CONFIG });
  assert.deepEqual(bulkClassOf(out, 'both.test'), ['command_and_control']);
});

// Test 4 — no duplicate slugs across multi-slug junction.
test('bulk_lookup_iocs: multi-slug junction returns deduped, ordered slugs', async () => {
  const rows = [bulkRow(13, 'multi.test', 'domain', 'unknown')];
  const pool = makeBulkPool(rows, [
    jrow(13, 'domain', 'command_and_control'),
    jrow(13, 'domain', 'phishing')
  ]);
  const out = await mcpBulkLookupIocs(pool, { iocs: [{ value: 'multi.test', type: 'domain' }] }, { config: TEST_CONFIG });
  assert.deepEqual(bulkClassOf(out, 'multi.test'), ['command_and_control', 'phishing']);
});

// Test 5 — no classification anywhere: [] (not ['unknown']), parity with lookup_ioc.
test('bulk_lookup_iocs: unclassified IOC returns [] not [unknown]', async () => {
  const rows = [bulkRow(14, '9.9.9.9', 'ip', 'unknown')];
  const pool = makeBulkPool(rows, []);
  const out = await mcpBulkLookupIocs(pool, { iocs: ['9.9.9.9'] }, { config: TEST_CONFIG });
  assert.deepEqual(bulkClassOf(out, '9.9.9.9'), []);
});

// Test 6 — multi-IOC batch maps each id to its own classifications.
test('bulk_lookup_iocs: batch maps each IOC to its own classifications', async () => {
  const rows = [
    bulkRow(20, 'a.test', 'domain', 'unknown'),
    bulkRow(21, 'b.test', 'domain', 'ransomware'),
    bulkRow(22, 'c.test', 'domain', 'unknown')
  ];
  const junction = [jrow(20, 'domain', 'command_and_control')]; // only IOC 20 has junction
  const pool = makeBulkPool(rows, junction);
  const out = await mcpBulkLookupIocs(pool, {
    iocs: [{ value: 'a.test', type: 'domain' }, { value: 'b.test', type: 'domain' }, { value: 'c.test', type: 'domain' }]
  }, { config: TEST_CONFIG });
  assert.deepEqual(bulkClassOf(out, 'a.test'), ['command_and_control']); // junction
  assert.deepEqual(bulkClassOf(out, 'b.test'), ['ransomware']);          // legacy
  assert.deepEqual(bulkClassOf(out, 'c.test'), []);                      // neither
});

// Test 7 — N+1 guard: exactly ONE junction query regardless of IOC count.
test('bulk_lookup_iocs: classification retrieval is a single batched query (no N+1)', async () => {
  const rows = [
    bulkRow(30, 'x1.test', 'domain', 'unknown'),
    bulkRow(31, 'x2.test', 'domain', 'unknown'),
    bulkRow(32, 'x3.test', 'domain', 'unknown')
  ];
  const pool = makeBulkPool(rows, [jrow(30, 'domain', 'phishing'), jrow(32, 'domain', 'ransomware')]);
  await mcpBulkLookupIocs(pool, {
    iocs: [{ value: 'x1.test', type: 'domain' }, { value: 'x2.test', type: 'domain' }, { value: 'x3.test', type: 'domain' }]
  }, { config: TEST_CONFIG });
  const classQueries = pool.queries.filter((q) => /FROM ioc_threat_classifications/i.test(q.sql));
  assert.equal(classQueries.length, 1, 'exactly one batched classification query');
  // And no per-IOC legacy re-read of ioc_items for classification.
  assert.equal(pool.queries.filter((q) => /SELECT threat_classification FROM ioc_items/i.test(q.sql)).length, 0);
});

// Test 8 — parity: bulk classifications equal the effective single-IOC loader.
test('bulk_lookup_iocs: parity with loadEffectiveIocClassificationSlugs', async () => {
  const rows = [bulkRow(40, 'parity.test', 'domain', 'unknown')];
  const junction = [jrow(40, 'domain', 'command_and_control')];
  const bulkPool = makeBulkPool(rows, junction);
  const out = await mcpBulkLookupIocs(bulkPool, { iocs: [{ value: 'parity.test', type: 'domain' }] }, { config: TEST_CONFIG });

  // Single-IOC effective loader over the same junction + legacy fixture.
  const singlePool = {
    query: async (sql) => {
      const n = String(sql).replace(/\s+/g, ' ');
      if (/FROM ioc_threat_classifications/i.test(n)) return { rows: junction };
      if (/SELECT threat_classification FROM ioc_items/i.test(n)) return { rows: [{ threat_classification: 'unknown' }] };
      return { rows: [] };
    }
  };
  const single = await loadEffectiveIocClassificationSlugs(singlePool, 40, 'domain');
  assert.deepEqual(bulkClassOf(out, 'parity.test'), single);
});

// --- search_iocs DSL construction (Findings #1 and #2) ---------------------
// Every generated query must be valid IOC Search DSL (parses without throwing).

function assertParses(query) {
  assert.doesNotThrow(() => parseSearchQuery(query), `should be valid DSL: ${query}`);
}

test('buildMcpSearchDsl: structured type filter emits valid DSL (not colon syntax)', () => {
  const domain = buildMcpSearchDsl({ type: 'domain' }, TEST_CONFIG);
  assert.equal(domain.ok, true);
  assert.equal(domain.query, 'type equals "domain"');
  assert.doesNotMatch(domain.query, /:/, 'must not use invalid colon syntax');
  assertParses(domain.query);

  const hash = buildMcpSearchDsl({ type: 'hash' }, TEST_CONFIG);
  assert.equal(hash.query, 'type in ("md5", "sha1", "sha256")');
  assertParses(hash.query);

  const ip = buildMcpSearchDsl({ type: 'ip' }, TEST_CONFIG);
  assert.equal(ip.query, 'type in ("ip", "ipv6")');
  assertParses(ip.query);
});

test('buildMcpSearchDsl: classification and source filters emit valid DSL', () => {
  const cls = buildMcpSearchDsl({ classification: 'malware' }, TEST_CONFIG);
  assert.equal(cls.query, 'classification equals "malware"');
  assertParses(cls.query);

  const src = buildMcpSearchDsl({ source: 'Threat-Hunting' }, TEST_CONFIG);
  assert.equal(src.query, 'source equals "Threat-Hunting"');
  assertParses(src.query);

  // A source name with a quote is safely escaped and still parses.
  const tricky = buildMcpSearchDsl({ source: 'a"b' }, TEST_CONFIG);
  assert.equal(tricky.query, 'source equals "a\\"b"');
  assertParses(tricky.query);
});

test('buildMcpSearchDsl: combined structured filters AND together, valid DSL', () => {
  const combined = buildMcpSearchDsl({ type: 'domain', source: 'Threat-Hunting' }, TEST_CONFIG);
  assert.equal(combined.query, '(type equals "domain") AND (source equals "Threat-Hunting")');
  assertParses(combined.query);
});

test('buildMcpSearchDsl: plain-text query becomes a bounded ioc value search', () => {
  const plain = buildMcpSearchDsl({ query: 'com' }, TEST_CONFIG);
  assert.equal(plain.ok, true);
  assert.equal(plain.query, 'ioc contains "com"');
  assertParses(plain.query);

  const bareIoc = buildMcpSearchDsl({ query: 'evil.example.com' }, TEST_CONFIG);
  assert.equal(bareIoc.query, 'ioc contains "evil.example.com"');
  assertParses(bareIoc.query);
});

test('buildMcpSearchDsl: valid DSL query is passed through unchanged', () => {
  const dsl = buildMcpSearchDsl({ query: 'value contains "com"' }, TEST_CONFIG);
  assert.equal(dsl.query, 'value contains "com"');
  assertParses(dsl.query);
});

test('buildMcpSearchDsl: plain-text query + structured filter combine as valid DSL', () => {
  const mixed = buildMcpSearchDsl({ query: 'evil.com', type: 'domain' }, TEST_CONFIG);
  assert.equal(mixed.query, '(ioc contains "evil.com") AND (type equals "domain")');
  assertParses(mixed.query);
});

test('buildMcpSearchDsl: broken DSL attempt surfaces a validation error (not silent plaintext)', () => {
  // known field + operator word but bad/unquoted value => intended DSL, so error.
  const broken = buildMcpSearchDsl({ query: 'type equals domain' }, TEST_CONFIG);
  assert.equal(broken.ok, false);
  assert.equal(broken.error.code, 'VALIDATION_ERROR');
});

test('buildMcpSearchDsl: invalid type value rejected', () => {
  const bad = buildMcpSearchDsl({ type: 'wat' }, TEST_CONFIG);
  assert.equal(bad.ok, false);
});

test('buildMcpSearchDsl: no query and no filters is rejected', () => {
  const empty = buildMcpSearchDsl({}, TEST_CONFIG);
  assert.equal(empty.ok, false);
  assert.match(empty.error.message, /at least one filter/i);
});

test('buildMcpSearchDsl: over-long query rejected', () => {
  const huge = 'a'.repeat(TEST_CONFIG.valueMaxChars + 1);
  const out = buildMcpSearchDsl({ query: huge }, TEST_CONFIG);
  assert.equal(out.ok, false);
  assert.match(out.error.message, /too long/i);
});

test('mcpListIocSources filters inactive and API system source', async () => {
  const pool = {
    query: async () => ({
      rows: [
        {
          id: 1,
          name: 'Threat-Hunting',
          description: 'manual',
          active: true,
          archived_at: null,
          source_type: 'manual',
          default_confidence: 'high',
          ioc_count: 3
        },
        {
          id: 2,
          name: 'Disabled Source',
          description: null,
          active: false,
          archived_at: null,
          source_type: 'manual',
          default_confidence: null,
          ioc_count: 0
        },
        {
          id: 3,
          name: API_SYSTEM_SOURCE_NAME,
          description: 'system',
          active: true,
          archived_at: null,
          source_type: 'system',
          default_confidence: null,
          ioc_count: 9
        },
        {
          id: 4,
          name: 'Archived',
          description: null,
          active: true,
          archived_at: '2026-01-01T00:00:00.000Z',
          source_type: 'manual',
          default_confidence: null,
          ioc_count: 1
        }
      ]
    })
  };
  const out = await mcpListIocSources(pool);
  assert.equal(out.status, 200);
  assert.equal(out.body.count, 1);
  assert.equal(out.body.sources[0].name, 'Threat-Hunting');
});

function makeImportPool({ source, membership = null, existing = null, createCalls }) {
  return {
    query: async (sql, params = []) => {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      if (normalized.includes('FROM ioc_sources WHERE id = $1')) {
        return { rows: source ? [source] : [] };
      }
      if (normalized.includes('ioc_source_id = $3')) {
        return { rows: membership ? [membership] : [] };
      }
      if (normalized.includes('FROM ioc_items')
        && normalized.includes('observable_type = $1 AND observable = $2')
        && !normalized.includes('ioc_source_id')) {
        return { rows: existing ? [existing] : [] };
      }
      if (normalized.includes('INSERT INTO')) {
        createCalls.push({ sql: normalized, params });
      }
      return { rows: [] };
    }
  };
}

test('mcpImportIocs dry_run does not create; unauthorized source rejected', async () => {
  const createCalls = [];
  const activeSource = {
    id: 7,
    name: 'Threat-Hunting',
    description: null,
    default_confidence: 'high',
    default_threat_classification: 'unknown',
    default_expire_policy: 'never',
    default_expire_days: null,
    active: true,
    archived_at: null,
    source_type: 'manual'
  };

  const dryPool = makeImportPool({ source: activeSource, createCalls });
  const dry = await mcpImportIocs(
    dryPool,
    { source_id: 7, iocs: ['8.8.4.4'], dry_run: true },
    { config: TEST_CONFIG }
  );
  assert.equal(dry.status, 200);
  assert.equal(dry.body.dry_run, true);
  assert.equal(dry.body.would_create, 1);
  assert.equal(createCalls.length, 0);

  const apiPool = makeImportPool({
    source: { ...activeSource, id: 99, name: API_SYSTEM_SOURCE_NAME },
    createCalls
  });
  const denied = await mcpImportIocs(
    apiPool,
    { source_id: 99, iocs: ['1.2.3.4'], dry_run: true },
    { config: TEST_CONFIG }
  );
  assert.equal(denied.status, 400);
  assert.match(denied.error.message, /not accessible/i);
  assert.equal(createCalls.length, 0);
});

// --- Regression: feed-imported classifications/tags must not read as empty ----
// Reproduces production IOC d38d8db3-... (SHA-256, ThreatFox): classification
// lives only in the legacy ioc_items.threat_classification column and every tag
// has origin='integration'. Before the fix, lookup_ioc/get_ioc_context reported
// classifications:[] and tags:[] while the IOC Details UI showed them.

const FEED_SHA256 = 'c5763c9ad5885c5fb7e83b38c373efa7eeb9cc146e524180ab5cce8157e1abd8';

function threatFoxRow(overrides = {}) {
  return {
    id: 3394624,
    public_id: 'd38d8db3-526d-4989-b8c8-e95ae85389d3',
    observable: FEED_SHA256,
    observable_type: 'sha256',
    status: 'active',
    confidence: 'high',
    threat_classification: 'dropper_downloader',
    threat_actor_id: null,
    note: 'Auto-imported from ThreatFox API | malware=Coruna | tags=Coruna,encrypted,exploit-package,ios',
    created_at: '2026-09-05T14:32:01.476Z',
    last_seen_at: '2026-09-05T14:32:01.476Z',
    ...overrides
  };
}

const INTEGRATION_TAGS = [
  { name: 'coruna', origins: ['integration'], source_name: 'ThreatFox:abuse.ch' },
  { name: 'encrypted', origins: ['integration'], source_name: 'ThreatFox:abuse.ch' },
  { name: 'exploit-package', origins: ['integration'], source_name: 'ThreatFox:abuse.ch' },
  { name: 'ios', origins: ['integration'], source_name: 'ThreatFox:abuse.ch' }
];

test('mcpLookupIoc: classification falls back to legacy column when junction empty', async () => {
  const existing = threatFoxRow();
  const pool = makeLookupPool({
    existing,
    classifications: [],
    tags: INTEGRATION_TAGS,
    sources: [{
      id: existing.id, ioc_source_id: null, source_name: 'ThreatFox:abuse.ch',
      catalog_source_name: 'ThreatFox:abuse.ch', status: 'active', created_at: existing.created_at
    }]
  });
  const out = await mcpLookupIoc(pool, { value: FEED_SHA256, type: 'hash' }, { config: TEST_CONFIG });
  assert.equal(out.status, 200);
  assert.equal(out.body.found, true);
  assert.equal(out.body.type, 'sha256');
  assert.deepEqual(out.body.classifications, ['dropper_downloader']);
  assert.deepEqual(out.body.tags, ['coruna', 'encrypted', 'exploit-package', 'ios']);
});

test('mcpLookupIoc: junction classifications win over the legacy column', async () => {
  const existing = threatFoxRow({ threat_classification: 'dropper_downloader' });
  const pool = makeLookupPool({
    existing,
    classifications: ['ransomware', 'trojan'],
    tags: INTEGRATION_TAGS
  });
  const out = await mcpLookupIoc(pool, { value: FEED_SHA256, type: 'hash' }, { config: TEST_CONFIG });
  assert.deepEqual(out.body.classifications, ['ransomware', 'trojan']);
  assert.ok(!pool.queries.some((q) => q.sql.includes('SELECT threat_classification FROM ioc_items')));
});

test('mcpLookupIoc: unclassified/untagged IOC yields correct empty arrays', async () => {
  const existing = threatFoxRow({ threat_classification: 'unknown', note: null });
  const pool = makeLookupPool({ existing, classifications: [], tags: [] });
  const out = await mcpLookupIoc(pool, { value: FEED_SHA256, type: 'hash' }, { config: TEST_CONFIG });
  assert.equal(out.body.found, true);
  assert.deepEqual(out.body.classifications, []);
  assert.deepEqual(out.body.tags, []);
});

test('mcpLookupIoc: multiple manual + integration tags merge with names deduped', async () => {
  const existing = threatFoxRow();
  const pool = makeLookupPool({
    existing,
    classifications: [],
    tags: [
      { name: 'apt-tracked', origins: ['manual'], source_name: null },
      ...INTEGRATION_TAGS
    ]
  });
  const out = await mcpLookupIoc(pool, { value: FEED_SHA256, type: 'hash' }, { config: TEST_CONFIG });
  assert.deepEqual(out.body.tags, ['apt-tracked', 'coruna', 'encrypted', 'exploit-package', 'ios']);
});

test('mcpGetIocContext: native classifications/tags + separated source_intelligence', async () => {
  const row = threatFoxRow();
  const pool = makeContextPool({
    row,
    classifications: [],
    tags: INTEGRATION_TAGS,
    sources: [{
      id: row.id, ioc_source_id: null, source_name: 'ThreatFox:abuse.ch',
      catalog_source_name: 'ThreatFox:abuse.ch', status: 'active', created_at: row.created_at
    }],
    evidence: [{
      id: 1, ioc_item_id: row.id, ioc_observable_type: 'sha256',
      feed_id: 10, source_name: 'ThreatFox:abuse.ch', category: 'payload',
      note: 'Auto-imported from ThreatFox API | malware=Coruna | threat_type=payload | tags=Coruna,encrypted,exploit-package,ios',
      feed_key: 'threatfox'
    }],
    enrichment: []
  });
  const out = await mcpGetIocContext(pool, { value: FEED_SHA256, type: 'hash' }, {
    config: TEST_CONFIG,
    mcpAuth: { scopes: [API_SCOPE.MCP_IOC_READ], ownerRole: 'analyst' }
  });
  assert.equal(out.status, 200);
  assert.deepEqual(out.body.classifications, ['dropper_downloader']);
  assert.deepEqual(out.body.tags, ['coruna', 'encrypted', 'exploit-package', 'ios']);
  assert.equal(out.body.tags_detail[0].origin, 'integration');
  assert.equal(out.body.tags_detail[0].source_name, 'ThreatFox:abuse.ch');
  assert.ok(Array.isArray(out.body.source_intelligence.feed_tags));
  assert.ok(out.body.source_intelligence.feed_tags.some((t) => t.normalized === 'coruna'));
  assert.ok(out.body.source_intelligence.labels.some((l) => l.malware === 'Coruna'));
  assert.equal(out.body.enrichment_included, false);
  assert.equal(out.body.enrichment, undefined);
});

test('mcpGetIocContext: by public_id, enrichment included when scope + role allow', async () => {
  const row = threatFoxRow();
  const pool = makeContextPool({
    row,
    classifications: [],
    tags: INTEGRATION_TAGS,
    evidence: [],
    enrichment: [{
      provider: 'virustotal', status: 'ok', normalized_summary: '3/70',
      fetched_at: '2026-09-05T15:00:00.000Z', expires_at: null, error_message: null
    }]
  });
  const out = await mcpGetIocContext(pool, { id: row.public_id }, {
    config: TEST_CONFIG,
    mcpAuth: { scopes: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_ENRICHMENT_READ], ownerRole: 'analyst' }
  });
  assert.equal(out.status, 200);
  assert.deepEqual(out.body.classifications, ['dropper_downloader']);
  assert.equal(out.body.public_id, row.public_id);
  assert.equal(out.body.enrichment_included, true);
  assert.equal(out.body.enrichment.length, 1);
  assert.equal(out.body.enrichment[0].provider, 'virustotal');
});

// --- Multi-provider enrichment aggregation (RDAP/AbuseIPDB/IPinfo) ---

function domainRow(overrides = {}) {
  return {
    id: 3394712,
    public_id: 'b1c82f85-342d-4901-8dd9-fc6670e42b3a',
    observable: 'juangcuan.com',
    observable_type: 'domain',
    status: 'active',
    confidence: 'medium',
    threat_classification: null,
    threat_actor_id: null,
    note: 'Auto-imported from CERT.PL Dangerous Websites',
    created_at: '2026-09-05T16:08:01.221Z',
    last_seen_at: '2026-09-05T16:08:01.221Z',
    ...overrides
  };
}

function ipRow(overrides = {}) {
  return {
    id: 900001,
    public_id: 'aaaaaaaa-0000-4000-8000-000000000001',
    observable: '203.0.113.7',
    observable_type: 'ip',
    status: 'active',
    confidence: 'medium',
    threat_classification: null,
    threat_actor_id: null,
    note: null,
    created_at: '2026-09-05T10:00:00.000Z',
    last_seen_at: '2026-09-05T10:00:00.000Z',
    ...overrides
  };
}

const RDAP_ROW = {
  root_domain: 'juangcuan.com',
  observable_value: 'juangcuan.com',
  ioc_type: 'domain',
  rdap_status: 'success',
  registrar: 'Dynadot Inc',
  registration_date: '2022-04-07T10:23:01.000Z',
  expiration_date: '2027-04-07T10:23:01.000Z',
  last_changed_date: '2026-05-17T10:25:47.000Z',
  domain_age_days: 1600,
  nameservers: ['ns1.dynadot.com'],
  statuses: ['client transfer prohibited'],
  derived_signals: { young_domain: false },
  last_success_at: '2026-09-05T16:21:18.617Z',
  last_enriched_at: '2026-09-05T16:21:18.617Z',
  error_message: null,
  last_error: null
};

const ENRICH_AUTH = { scopes: [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_ENRICHMENT_READ], ownerRole: 'analyst' };

// Test 1 — domain with both VirusTotal and RDAP stored: both surface.
test('mcpGetIocContext: domain returns VirusTotal AND RDAP enrichment', async () => {
  const row = domainRow();
  const pool = makeContextPool({
    row,
    enrichment: [{
      provider: 'virustotal', status: 'success', normalized_summary: { stats: { malicious: 5 } },
      fetched_at: '2026-09-05T16:21:17.714Z', expires_at: '2026-09-06T16:21:17.714Z', error_message: null
    }],
    rdap: RDAP_ROW
  });
  const out = await mcpGetIocContext(pool, { id: row.public_id }, { config: TEST_CONFIG, mcpAuth: ENRICH_AUTH });
  assert.equal(out.status, 200);
  const providers = out.body.enrichment.map((e) => e.provider);
  assert.deepEqual(providers, ['rdap', 'virustotal']); // provider-sorted
  const rdap = out.body.enrichment.find((e) => e.provider === 'rdap');
  assert.equal(rdap.status, 'success');
  assert.equal(rdap.summary.registrar, 'Dynadot Inc');
  assert.equal(rdap.summary.registration_date, '2022-04-07T10:23:01.000Z');
  assert.equal(rdap.summary.expiration_date, '2027-04-07T10:23:01.000Z');
  assert.equal(rdap.summary.last_changed_date, '2026-05-17T10:25:47.000Z');
  assert.equal(rdap.fetched_at, '2026-09-05T16:21:18.617Z');
});

// Test 2 — RDAP present, VirusTotal absent: RDAP still surfaces (collection is
// not coupled to VirusTotal).
test('mcpGetIocContext: domain with RDAP but no VirusTotal still returns RDAP', async () => {
  const row = domainRow();
  const pool = makeContextPool({ row, enrichment: [], rdap: RDAP_ROW });
  const out = await mcpGetIocContext(pool, { id: row.public_id }, { config: TEST_CONFIG, mcpAuth: ENRICH_AUTH });
  assert.equal(out.status, 200);
  assert.deepEqual(out.body.enrichment.map((e) => e.provider), ['rdap']);
});

// Test 3 — RDAP does not leak onto an IOC type it does not support (hash),
// even if a stale domain row would match had it been queried.
test('mcpGetIocContext: hash IOC never surfaces RDAP (type-gated)', async () => {
  const row = threatFoxRow();
  const pool = makeContextPool({
    row,
    tags: INTEGRATION_TAGS,
    enrichment: [{ provider: 'virustotal', status: 'success', normalized_summary: null, fetched_at: null, expires_at: null, error_message: null }],
    rdap: RDAP_ROW
  });
  const out = await mcpGetIocContext(pool, { id: row.public_id }, { config: TEST_CONFIG, mcpAuth: ENRICH_AUTH });
  assert.equal(out.status, 200);
  assert.deepEqual(out.body.enrichment.map((e) => e.provider), ['virustotal']);
  // The RDAP table must not even be queried for a hash IOC.
  assert.ok(!pool.queries.some((q) => q.sql.includes('FROM ioc_domain_enrichment')));
});

// Test 4 — no enrichment anywhere: empty array, no crash.
test('mcpGetIocContext: domain with no enrichment returns empty array', async () => {
  const row = domainRow();
  const pool = makeContextPool({ row, enrichment: [] });
  const out = await mcpGetIocContext(pool, { id: row.public_id }, { config: TEST_CONFIG, mcpAuth: ENRICH_AUTH });
  assert.equal(out.status, 200);
  assert.equal(out.body.enrichment_included, true);
  assert.deepEqual(out.body.enrichment, []);
});

// Test 5 — IP IOC surfaces the IP-only providers (AbuseIPDB + IPinfo), and RDAP
// is not queried for an IP.
test('mcpGetIocContext: IP returns AbuseIPDB and IPinfo, not RDAP', async () => {
  const row = ipRow();
  const pool = makeContextPool({
    row,
    enrichment: [],
    abuseipdb: {
      ip: '203.0.113.7', provider_status: 'success',
      normalized_summary: { abuse_confidence_score: 42 },
      last_enriched_at: '2026-09-05T12:00:00.000Z', error_message: null
    },
    ipinfo: {
      ip: '203.0.113.7', normalized_ip: '203.0.113.7', provider_status: 'success',
      asn: 'AS64500', as_name: 'Example', as_domain: 'example.net',
      country_code: 'US', country: 'United States', continent_code: 'NA', continent: 'North America',
      derived_signals: {}, last_enriched_at: '2026-09-05T12:05:00.000Z', error_message: null
    }
  });
  const out = await mcpGetIocContext(pool, { id: row.public_id }, { config: TEST_CONFIG, mcpAuth: ENRICH_AUTH });
  assert.equal(out.status, 200);
  assert.deepEqual(out.body.enrichment.map((e) => e.provider), ['abuseipdb', 'ipinfo_lite']);
  assert.equal(out.body.enrichment.find((e) => e.provider === 'abuseipdb').summary.abuse_confidence_score, 42);
  assert.equal(out.body.enrichment.find((e) => e.provider === 'ipinfo_lite').summary.asn, 'AS64500');
  assert.ok(!pool.queries.some((q) => q.sql.includes('FROM ioc_domain_enrichment')));
});

test('mcpGetIocContext: readonly owner without enrichment scope omits enrichment', async () => {
  const row = threatFoxRow();
  const pool = makeContextPool({ row, classifications: [], tags: [], evidence: [] });
  const out = await mcpGetIocContext(pool, { value: FEED_SHA256, type: 'hash' }, {
    config: TEST_CONFIG,
    mcpAuth: { scopes: [API_SCOPE.MCP_IOC_READ], ownerRole: 'readonly' }
  });
  assert.equal(out.status, 200);
  assert.equal(out.body.enrichment_included, false);
  assert.equal(out.body.enrichment, undefined);
});

test('mcpLookupIoc: hash-storage fix preserved (abstract hash resolves to sha256)', async () => {
  const existing = threatFoxRow();
  const pool = makeLookupPool({ existing, classifications: [], tags: INTEGRATION_TAGS });
  await mcpLookupIoc(pool, { value: FEED_SHA256, type: 'hash' }, { config: TEST_CONFIG });
  const exact = pool.queries.find((q) =>
    q.sql.includes('observable_type = $1 AND observable = $2') && q.sql.includes('ORDER BY created_at ASC'));
  assert.deepEqual(exact.params, ['sha256', FEED_SHA256]);
});
