import test from 'node:test';
import assert from 'node:assert/strict';
import { loadIocThreatContext, serializeIocThreatContext } from './iocThreatContext.js';

function fakePool({ claims = [], relationships = [] } = {}) {
  const queries = [];
  return {
    queries,
    query: async (sql, params = []) => {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      queries.push({ sql: normalized, params: [...params] });
      if (normalized.includes('FROM threat_report_candidates c')) return { rows: claims };
      if (normalized.includes('FROM threat_relationships tr')) return { rows: relationships };
      throw new Error(`Unexpected SQL: ${normalized.slice(0, 80)}`);
    }
  };
}

const CLAIM = {
  id: 1, report_id: 9, matched_ioc_id: 42, role: 'malicious_infrastructure', assessment: 'malicious',
  confidence: '0.900', evidence_text: 'ev', section: 'Indicators', page_number: 2, block_id: 'b1',
  report_public_id: 'rp', report_title: 'T', published_at: '2026-09-10T00:00:00.000Z', tlp: 'amber_strict',
  source_name: 'www.infoblox.com', source_url: 'https://www.infoblox.com/r', source_type: 'url'
};

test('loadIocThreatContext: one claims query + one relationships query keyed by ioc id', async () => {
  const pool = fakePool({ claims: [CLAIM] });
  const out = await loadIocThreatContext(pool, 42);
  assert.equal(pool.queries.length, 2);
  assert.deepEqual(pool.queries[0].params, [42]);
  assert.deepEqual(pool.queries[1].params, [42]);
  // Canonical filters stay in the shared SQL path: soft-deleted and unready reports excluded.
  assert.match(pool.queries[0].sql, /r\.deleted_at IS NULL/);
  assert.match(pool.queries[0].sql, /import_status IN \('ready','imported','review_required'\)/);
  assert.match(pool.queries[1].sql, /r\.deleted_at IS NULL/);
  assert.equal(out.claims.length, 1);
  assert.deepEqual(out.relationships, []);
});

test('serializeIocThreatContext: claim shape is the HTTP threat-context shape (tlp_display derived)', () => {
  const out = serializeIocThreatContext({ claims: [CLAIM], relationships: [] });
  assert.deepEqual(out.claims[0], {
    role: 'malicious_infrastructure',
    assessment: 'malicious',
    confidence: '0.900',
    evidence_text: 'ev',
    section: 'Indicators',
    page_number: 2,
    report: {
      id: 'rp',
      title: 'T',
      published_at: '2026-09-10T00:00:00.000Z',
      tlp: 'amber_strict',
      tlp_display: 'TLP:AMBER+STRICT',
      source_name: 'www.infoblox.com',
      source_type: 'url'
    }
  });
});

test('serializeIocThreatContext: tolerates empty/missing input', () => {
  assert.deepEqual(serializeIocThreatContext(null), { claims: [], relationships: [] });
  assert.deepEqual(serializeIocThreatContext({}), { claims: [], relationships: [] });
});

test('loadIocThreatContext: store failure propagates (never an empty context)', async () => {
  const pool = { query: async () => { throw new Error('connection terminated'); } };
  await assert.rejects(() => loadIocThreatContext(pool, 42), /connection terminated/);
});
