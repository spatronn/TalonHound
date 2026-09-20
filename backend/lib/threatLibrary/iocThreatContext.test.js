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
      // Artifact alias lookup (optional; flag-off short-circuits before this).
      if (normalized.includes('file_artifact')) return { rows: [], rowCount: 0 };
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
  const threatQueries = pool.queries.filter((q) => q.sql.includes('threat_'));
  assert.equal(threatQueries.length, 3);
  assert.deepEqual(threatQueries[0].params, [[42], 42]);
  assert.deepEqual(threatQueries[1].params, [[42]]);
  assert.deepEqual(threatQueries[2].params, [[9]]);
  // Canonical filters stay in the shared SQL path: soft-deleted and unready reports excluded.
  assert.match(threatQueries[0].sql, /r\.deleted_at IS NULL/);
  assert.match(threatQueries[0].sql, /import_status IN \('ready','imported','review_required'\)/);
  assert.match(threatQueries[0].sql, /r\.summary AS report_summary/);
  assert.match(threatQueries[0].sql, /matched_ioc_id = ANY\(\$1::bigint\[\]\)/);
  assert.match(threatQueries[0].sql, /DISTINCT ON \(c\.report_id\)/);
  assert.match(threatQueries[1].sql, /r\.deleted_at IS NULL/);
  assert.match(threatQueries[2].sql, /re\.report_id = ANY\(\$1::bigint\[\]\)/);
  assert.equal(out.claims.length, 1);
  assert.deepEqual(out.relationships, []);
  assert.deepEqual(out.claims[0].report.entities.map((e) => e.name), ['PeckBirdy', 'Sable Squirrel']);
});

test('loadIocThreatContext: no claims => entities query skipped (2 threat queries)', async () => {
  const pool = fakePool({ entities: ENTITIES });
  const out = await loadIocThreatContext(pool, 42);
  const threatQueries = pool.queries.filter((q) => q.sql.includes('threat_'));
  assert.equal(threatQueries.length, 2);
  assert.deepEqual(out, { claims: [], relationships: [] });
});

test('loadIocThreatContext: expands to proven file-artifact hash aliases and dedupes one claim per report', async () => {
  const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
  process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
  try {
    const md5Claim = {
      ...CLAIM,
      id: 11,
      matched_ioc_id: 3472708,
      candidate_type: 'md5',
      report_id: 16,
      report_public_id: 'rep-dtrack',
      report_title: 'Dtrack expands its operations to Europe and Latin America'
    };
    const sha1ClaimSameReport = {
      ...CLAIM,
      id: 12,
      matched_ioc_id: 999,
      candidate_type: 'sha1',
      report_id: 16,
      report_public_id: 'rep-dtrack',
      report_title: 'Dtrack expands its operations to Europe and Latin America'
    };
    const otherArtifactClaim = {
      ...CLAIM,
      id: 13,
      matched_ioc_id: 777,
      candidate_type: 'md5',
      report_id: 99,
      report_public_id: 'rep-other',
      report_title: 'Unrelated report'
    };

    const pool = {
      queries: [],
      query: async (sql, params = []) => {
        const normalized = String(sql).replace(/\s+/g, ' ').trim();
        pool.queries.push({ sql: normalized, params: [...params] });
        if (normalized.includes('file_artifact_ioc_links l') && normalized.includes('JOIN file_artifacts a')) {
          return { rows: [{ artifact_id: 'art-canon', status: 'active', merged_into_artifact_id: null }], rowCount: 1 };
        }
        if (normalized.includes('DISTINCT ON (ioc_item_id)')) {
          return {
            rows: [
              { ioc_item_id: 1139687, ioc_public_id: 'sha256-pid' },
              { ioc_item_id: 3472708, ioc_public_id: 'md5-pid' }
            ],
            rowCount: 2
          };
        }
        if (normalized.includes('FROM threat_report_candidates c')) {
          // Emulate DISTINCT ON preference: requested SHA256 first, then hash strength.
          const wanted = new Set((params[0] || []).map(Number));
          const preferred = Number(params[1]);
          const rows = [md5Claim, sha1ClaimSameReport, otherArtifactClaim]
            .filter((c) => wanted.has(Number(c.matched_ioc_id)));
          const byReport = new Map();
          for (const c of rows.sort((a, b) => {
            const aPref = Number(a.matched_ioc_id) === preferred ? 0 : 1;
            const bPref = Number(b.matched_ioc_id) === preferred ? 0 : 1;
            if (aPref !== bPref) return aPref - bPref;
            const rank = (t) => ({ sha256: 0, sha1: 1, md5: 2 }[String(t).toLowerCase()] ?? 9);
            return rank(a.candidate_type) - rank(b.candidate_type) || a.id - b.id;
          })) {
            if (!byReport.has(c.report_id)) byReport.set(c.report_id, c);
          }
          return { rows: [...byReport.values()] };
        }
        if (normalized.includes('FROM threat_relationships tr')) return { rows: [] };
        if (normalized.includes('FROM threat_report_entities re')) return { rows: [] };
        throw new Error(`Unexpected SQL: ${normalized.slice(0, 100)}`);
      }
    };

    const out = await loadIocThreatContext(pool, 1139687);
    assert.equal(out.claims.length, 1, 'same report via MD5+SHA1 aliases appears once');
    assert.equal(out.claims[0].report.title, 'Dtrack expands its operations to Europe and Latin America');
    assert.ok(!out.claims.some((c) => c.report.title === 'Unrelated report'));
    const claimQuery = pool.queries.find((q) => q.sql.includes('FROM threat_report_candidates c'));
    assert.deepEqual(claimQuery.params[0].sort((a, b) => a - b), [1139687, 3472708]);
    assert.equal(claimQuery.params[1], 1139687);
  } finally {
    if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
  }
});

test('loadIocThreatContext: unrelated file artifacts do not inherit each other\'s Threat Context', async () => {
  const prev = process.env.FILE_ARTIFACTS_READ_ENABLED;
  process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
  try {
    const pool = {
      queries: [],
      query: async (sql, params = []) => {
        const normalized = String(sql).replace(/\s+/g, ' ').trim();
        pool.queries.push({ sql: normalized, params: [...params] });
        if (normalized.includes('file_artifact_ioc_links l') && normalized.includes('JOIN file_artifacts a')) {
          return { rows: [{ artifact_id: 'art-a', status: 'active', merged_into_artifact_id: null }], rowCount: 1 };
        }
        if (normalized.includes('DISTINCT ON (ioc_item_id)')) {
          return { rows: [{ ioc_item_id: 100, ioc_public_id: 'a' }, { ioc_item_id: 101, ioc_public_id: 'b' }], rowCount: 2 };
        }
        if (normalized.includes('FROM threat_report_candidates c')) {
          const wanted = new Set((params[0] || []).map(Number));
          assert.ok(!wanted.has(999), 'foreign artifact IOC id must not be queried');
          return { rows: [] };
        }
        if (normalized.includes('FROM threat_relationships tr')) return { rows: [] };
        return { rows: [] };
      }
    };
    const out = await loadIocThreatContext(pool, 100);
    assert.deepEqual(out, { claims: [], relationships: [] });
  } finally {
    if (prev === undefined) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prev;
  }
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
      published_date: '2026-09-10',
      published_at_precision: null,
      published_at_source: null,
      created_at: null,
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
