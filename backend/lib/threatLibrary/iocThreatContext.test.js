import test from 'node:test';
import assert from 'node:assert/strict';
import {
  loadIocThreatContext,
  serializeIocThreatContext,
  THREAT_CONTEXT_MAX_ENTITIES,
  THREAT_CONTEXT_MAX_OCCURRENCES,
  THREAT_CONTEXT_MAX_SUMMARY_CHARS,
  THREAT_CONTEXT_MAX_TEXT_CHARS
} from './iocThreatContext.js';

function fakePool({ claims = [], relationships = [], entities = [] } = {}) {
  const queries = [];
  return {
    queries,
    query: async (sql, params = []) => {
      const normalized = String(sql).replace(/\s+/g, ' ').trim();
      queries.push({ sql: normalized, params: [...params] });
      if (normalized.includes('FROM threat_report_candidates c')) return { rows: claims };
      if (normalized.includes('FROM threat_relationships tr')) return { rows: relationships };
      if (normalized.includes('FROM threat_report_entities re')) {
        const wanted = new Set((params[0] || []).map(String));
        return { rows: entities.filter((e) => wanted.has(String(e.report_id))) };
      }
      throw new Error(`Unexpected SQL: ${normalized.slice(0, 80)}`);
    }
  };
}

const CLAIM = {
  id: 1, report_id: 9, matched_ioc_id: 42, role: 'malicious_infrastructure', assessment: 'malicious',
  confidence: '0.900', evidence_text: 'ev', section: 'Indicators', page_number: 2, block_id: 'b1',
  evidence: {
    source_assertion: 'explicit_ioc', occurrence_count: 2,
    occurrences: [
      { block_id: 'b1', zone: 'report_body', section_heading: 'Why casinos', page: null, form: 'standalone', surrounding_text: 'Figure 1 … zzyud[.]com', source_relation: 'subject' },
      { block_id: 'b2', zone: 'explicit_ioc_section', section_heading: 'Indicators', page: 3, form: 'list_row', surrounding_text: 'zzyud[.]com', asserted: true }
    ]
  },
  report_public_id: 'rp', report_title: 'T', published_at: '2026-09-10T00:00:00.000Z', tlp: 'amber_strict',
  source_name: 'www.infoblox.com', source_url: 'https://www.infoblox.com/r', source_type: 'url',
  report_summary: 'Report summary text.'
};

const ENTITIES = [
  { report_id: 9, public_id: 'e1', entity_type: 'campaign', name: 'PeckBirdy', description: 'desc', link_confidence: '0.8', id: 100 },
  { report_id: 9, public_id: 'e2', entity_type: 'threat_actor', name: 'Sable Squirrel', description: null, link_confidence: null, id: 101 },
  { report_id: 8, public_id: 'e3', entity_type: 'malware', name: 'Elsewhere', description: null, link_confidence: null, id: 102 }
];

test('loadIocThreatContext: claims + relationships + one batched entities query, all keyed by ioc / report ids', async () => {
  const pool = fakePool({ claims: [CLAIM], entities: ENTITIES });
  const out = await loadIocThreatContext(pool, 42);
  assert.equal(pool.queries.length, 3);
  assert.deepEqual(pool.queries[0].params, [42]);
  assert.deepEqual(pool.queries[1].params, [42]);
  assert.deepEqual(pool.queries[2].params, [[9]]);
  // Canonical filters stay in the shared SQL path: soft-deleted and unready reports excluded.
  assert.match(pool.queries[0].sql, /r\.deleted_at IS NULL/);
  assert.match(pool.queries[0].sql, /import_status IN \('ready','imported','review_required'\)/);
  assert.match(pool.queries[0].sql, /r\.summary AS report_summary/);
  assert.match(pool.queries[1].sql, /r\.deleted_at IS NULL/);
  assert.match(pool.queries[2].sql, /re\.report_id = ANY\(\$1::bigint\[\]\)/);
  assert.equal(out.claims.length, 1);
  assert.deepEqual(out.relationships, []);
  assert.deepEqual(out.claims[0].report.entities.map((e) => e.name), ['PeckBirdy', 'Sable Squirrel']);
});

test('loadIocThreatContext: no claims => entities query skipped (2 queries)', async () => {
  const pool = fakePool({ entities: ENTITIES });
  const out = await loadIocThreatContext(pool, 42);
  assert.equal(pool.queries.length, 2);
  assert.deepEqual(out, { claims: [], relationships: [] });
});

test('serializeIocThreatContext: claim shape = HTTP threat-context shape + occurrences + report summary/entities', () => {
  const out = serializeIocThreatContext({ claims: [CLAIM], relationships: [], entities: ENTITIES });
  assert.deepEqual(out.claims[0], {
    role: 'malicious_infrastructure',
    assessment: 'malicious',
    confidence: '0.900',
    evidence_text: 'ev',
    section: 'Indicators',
    page_number: 2,
    occurrence_count: 2,
    occurrences: [
      { zone: 'report_body', section_heading: 'Why casinos', page: null, form: 'standalone', surrounding_text: 'Figure 1 … zzyud[.]com' },
      { zone: 'explicit_ioc_section', section_heading: 'Indicators', page: 3, form: 'list_row', surrounding_text: 'zzyud[.]com' }
    ],
    report: {
      id: 'rp',
      title: 'T',
      published_at: '2026-09-10T00:00:00.000Z',
      tlp: 'amber_strict',
      tlp_display: 'TLP:AMBER+STRICT',
      source_name: 'www.infoblox.com',
      source_type: 'url',
      summary: 'Report summary text.',
      entities: [
        { id: 'e1', entity_type: 'campaign', name: 'PeckBirdy', description: 'desc' },
        { id: 'e2', entity_type: 'threat_actor', name: 'Sable Squirrel', description: null }
      ]
    }
  });
});

test('serializeIocThreatContext: bounds are deterministic (occurrences, entities, text, summary)', () => {
  const occ = Array.from({ length: 40 }, (_, i) => ({ zone: 'z', section_heading: `H${i}`, surrounding_text: 'x'.repeat(1000) }));
  const ents = Array.from({ length: 30 }, (_, i) => ({ report_id: 9, public_id: `e${i}`, entity_type: 'malware', name: `M${i}`, description: 'd'.repeat(1000) }));
  const out = serializeIocThreatContext({
    claims: [{ ...CLAIM, report_summary: 's'.repeat(10000), evidence: { occurrence_count: 40, occurrences: occ } }],
    relationships: [],
    entities: ents
  });
  const c = out.claims[0];
  assert.equal(c.occurrences.length, THREAT_CONTEXT_MAX_OCCURRENCES);
  assert.deepEqual(c.occurrences.map((o) => o.section_heading), ['H0', 'H1', 'H2', 'H3', 'H4']);
  assert.equal(c.occurrence_count, 40);
  assert.equal(c.occurrences[0].surrounding_text.length, THREAT_CONTEXT_MAX_TEXT_CHARS);
  assert.equal(c.report.summary.length, THREAT_CONTEXT_MAX_SUMMARY_CHARS);
  assert.equal(c.report.entities.length, THREAT_CONTEXT_MAX_ENTITIES);
  assert.equal(c.report.entities[0].name, 'M0');
  assert.equal(c.report.entities[0].description.length, THREAT_CONTEXT_MAX_TEXT_CHARS);
});

test('serializeIocThreatContext: missing summary/evidence/entities are stable nulls and empty arrays', () => {
  const out = serializeIocThreatContext({ claims: [{ ...CLAIM, report_summary: null, evidence: null }], relationships: [] });
  const c = out.claims[0];
  assert.equal(c.report.summary, null);
  assert.equal(c.occurrence_count, 0);
  assert.deepEqual(c.occurrences, []);
  assert.deepEqual(c.report.entities, []);
});

test('serializeIocThreatContext: tolerates empty/missing input', () => {
  assert.deepEqual(serializeIocThreatContext(null), { claims: [], relationships: [] });
  assert.deepEqual(serializeIocThreatContext({}), { claims: [], relationships: [] });
});

test('loadIocThreatContext: store failure propagates (never an empty context)', async () => {
  const pool = { query: async () => { throw new Error('connection terminated'); } };
  await assert.rejects(() => loadIocThreatContext(pool, 42), /connection terminated/);
});
