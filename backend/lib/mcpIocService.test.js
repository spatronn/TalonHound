import test from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveMcpIocInput,
  mcpLookupIoc,
  mcpBulkLookupIocs,
  mcpListIocSources,
  mcpImportIocs
} from './mcpIocService.js';
import { API_SYSTEM_SOURCE_NAME } from './apiSystemSource.js';
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
        return { rows: tags };
      }
      if (normalized.includes('FROM ioc_items i') && normalized.includes('LEFT JOIN ioc_sources')) {
        return { rows: sources };
      }
      throw new Error(`Unexpected SQL in lookup pool: ${normalized.slice(0, 120)}`);
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

function makeBulkPool(foundRows) {
  const queries = [];
  return {
    queries,
    query: async (sql, params = []) => {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      queries.push({ sql: normalized, params: [...params] });
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
