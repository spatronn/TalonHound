import test from 'node:test';
import assert from 'node:assert/strict';
import {
  clampIndicatorPage,
  isThreatReportId,
  loadThreatReportForMcp,
  serializeThreatReport,
  THREAT_REPORT_INDICATOR_LIMIT_DEFAULT,
  THREAT_REPORT_INDICATOR_LIMIT_MAX,
  THREAT_REPORT_MAX_ENTITIES,
  THREAT_REPORT_MAX_RELATIONSHIPS
} from './mcpThreatReport.js';

const REPORT_ID = '173ef4c4-860b-4c44-aad1-1d65af5a61c8';

function reportRow(overrides = {}) {
  return {
    id: 15, public_id: REPORT_ID, title: 'Illegal Gambling Sites Reveal Three Types of Cybercrime',
    source_type: 'url', source_name: 'www.infoblox.com', source_url: 'https://www.infoblox.com/blog/x',
    source_file_name: null, source_sha256: null, published_at: null, language: 'en-us',
    tlp: 'clear', tlp_source: 'default', confidence: null, report_type: null,
    summary: 'Three types of illegal gambling sites; PeckBirdy C2 decoys are type 3.',
    import_status: 'ready', analysis_status: 'ready', failure_stage: null, failure_reason: 'secret diag', failure_code: null,
    failure_details: { stack: 'internal' }, analysis_progress: { chunk: 9 }, candidate_summary: { new: 25 },
    canonical_document: { blocks: [{ text: 'FULL BODY' }] },
    created_at: '2026-09-16T00:30:21.000Z', updated_at: '2026-09-17T23:39:16.000Z', finalized_at: '2026-09-17T23:39:16.000Z',
    deleted_at: null, ...overrides
  };
}

function candidate(i, overrides = {}) {
  return {
    id: 500 + i, public_id: `c-${i}`, report_id: 15, candidate_type: 'domain',
    original_value: `d${i}[.]com`, normalized_value: `d${i}.com`, assessment: 'malicious', role: 'command_and_control',
    confidence: '1.000', evidence_text: `d${i}[.]com`, section: 'explicit_ioc_section', block_id: `b${i}`, page_number: null,
    review_status: 'created_ioc', match_state: 'existing', matched_ioc_id: 3451500 + i, matched_ioc_observable_type: 'domain',
    promotion_outcome: 'already_existing', promotion_detail: { x: 1 }, promoted_at: 'x', is_ioc: true, source_assertion: 'explicit_ioc',
    evidence: { occurrence_count: 4, occurrences: [{ block_id: 'b', surrounding_text: 'secret window' }], policy_decision: 'explicit_report_assertion' },
    ...overrides
  };
}

const ENTITIES = [
  { id: 167, public_id: 'e-peck', portable_id: 'entity--1', entity_type: 'campaign', name: 'PeckBirdy', normalized_name: 'peckbirdy', description: 'C2 framework', created_at: 'x', updated_at: 'x', link_confidence: '0.8', link_evidence: 'ev' },
  { id: 172, public_id: 'e-sable', portable_id: 'entity--2', entity_type: 'threat_actor', name: 'Sable Squirrel', normalized_name: 'sable squirrel', description: null, created_at: 'x', updated_at: 'x', link_confidence: null, link_evidence: null }
];

const RELATIONSHIPS = [
  { id: 49, public_id: 'rel-1', portable_id: 'relationship--1', report_id: 15, subject_kind: 'entity', subject_entity_id: 172, subject_candidate_id: null,
    subject_ioc_id: null, subject_portable_ref: 'entity--2', relationship_type: 'uses', object_kind: 'entity', object_entity_id: 167,
    object_candidate_id: null, object_ioc_id: null, object_portable_ref: 'entity--1', role: null, confidence: null, evidence_text: null,
    section: null, page_number: null, block_id: null, created_at: '2026-09-16T00:39:05.000Z' }
];

function snapshot({ report = reportRow(), candidates = [candidate(1), candidate(2, { assessment: 'context_only', role: 'reference', is_ioc: false, matched_ioc_id: null, matched_ioc_observable_type: null, review_status: 'pending' })], entities = ENTITIES, relationships = RELATIONSHIPS } = {}) {
  return { report, candidates, entities, relationships, artifacts: [{ id: 1, sha256: 'abc' }], jobs: [{ id: 1, status: 'done' }] };
}

function fakePool({ report = reportRow(), snap = snapshot() } = {}) {
  const queries = [];
  return {
    queries,
    query: async (sql, params = []) => {
      const n = String(sql).replace(/\s+/g, ' ').trim();
      queries.push({ sql: n, params: [...params] });
      if (n.includes('FROM threat_reports WHERE public_id = $1::uuid AND deleted_at IS NULL')) return { rows: report ? [report] : [] };
      if (n.includes('FROM threat_reports WHERE id = $1 AND deleted_at IS NULL')) return { rows: report ? [report] : [] };
      if (n.includes('FROM threat_report_candidates WHERE report_id = $1')) return { rows: snap.candidates };
      if (n.includes('FROM threat_report_entities re')) return { rows: snap.entities };
      if (n.includes('FROM threat_relationships WHERE report_id = $1')) return { rows: snap.relationships };
      if (n.includes('FROM threat_report_artifacts')) return { rows: snap.artifacts };
      if (n.includes('FROM threat_library_jobs')) return { rows: snap.jobs };
      throw new Error(`Unexpected SQL: ${n.slice(0, 90)}`);
    }
  };
}

test('isThreatReportId / clampIndicatorPage', () => {
  assert.equal(isThreatReportId(REPORT_ID), true);
  assert.equal(isThreatReportId('15'), false);
  assert.equal(isThreatReportId(''), false);
  assert.deepEqual(clampIndicatorPage({}), { limit: THREAT_REPORT_INDICATOR_LIMIT_DEFAULT, offset: 0 });
  assert.deepEqual(clampIndicatorPage({ limit: 5000, offset: -3 }), { limit: THREAT_REPORT_INDICATOR_LIMIT_MAX, offset: 0 });
  assert.deepEqual(clampIndicatorPage({ limit: 7, offset: 3 }), { limit: 7, offset: 3 });
});

test('serializeThreatReport: allow-listed metadata + summary, no body/diagnostics/artifacts/jobs', () => {
  const out = serializeThreatReport(snapshot());
  assert.equal(out.id, REPORT_ID);
  assert.equal(out.title, 'Illegal Gambling Sites Reveal Three Types of Cybercrime');
  assert.equal(out.source_name, 'www.infoblox.com');
  assert.equal(out.source_url, 'https://www.infoblox.com/blog/x');
  assert.equal(out.tlp_display, 'TLP:CLEAR');
  assert.equal(out.tlp_source, 'default');
  assert.equal(out.summary, 'Three types of illegal gambling sites; PeckBirdy C2 decoys are type 3.');
  assert.equal(out.review_phase, 'finalized');
  assert.deepEqual(out.counts, { indicators: 2, entities: 2, relationships: 1 });
  for (const k of ['canonical_document', 'failure_reason', 'failure_details', 'analysis_progress', 'candidate_summary', 'artifacts', 'jobs', 'source_sha256']) {
    assert.equal(k in out, false, `${k} must not be exposed`);
  }
  assert.equal(JSON.stringify(out).includes('FULL BODY'), false);
  assert.equal(JSON.stringify(out).includes('secret'), false);
});

test('serializeThreatReport: indicators carry their own role/assessment, allow-listed, no evidence internals', () => {
  const out = serializeThreatReport(snapshot());
  assert.deepEqual(out.indicators.items[0], {
    id: 'c-1', value: 'd1.com', original_value: 'd1[.]com', type: 'domain', is_ioc: true,
    assessment: 'malicious', role: 'command_and_control', confidence: '1.000', section: 'explicit_ioc_section',
    page_number: null, evidence_text: 'd1[.]com', occurrence_count: 4, review_status: 'approved', match_state: 'existing',
    ioc_id: 3451501, ioc_type: 'domain'
  });
  const ctx = out.indicators.items[1];
  assert.equal(ctx.assessment, 'context_only');
  assert.equal(ctx.role, 'reference');
  assert.equal(ctx.is_ioc, false);
  assert.equal(ctx.ioc_id, null);
  assert.equal(ctx.review_status, 'pending');
  for (const k of ['evidence', 'block_id', 'promotion_detail', 'source_assertion', 'report_id', 'promotion_outcome', 'occurrences']) {
    assert.equal(k in out.indicators.items[0], false, `${k} must not be exposed`);
  }
});

test('serializeThreatReport: indicator paging is deterministic (persisted order) with has_more', () => {
  const cands = Array.from({ length: 12 }, (_, i) => candidate(i));
  const p1 = serializeThreatReport(snapshot({ candidates: cands }), { limit: 5, offset: 0 });
  assert.deepEqual(p1.indicators.items.map((x) => x.value), ['d0.com', 'd1.com', 'd2.com', 'd3.com', 'd4.com']);
  assert.equal(p1.indicators.total, 12);
  assert.equal(p1.indicators.has_more, true);
  const p3 = serializeThreatReport(snapshot({ candidates: cands }), { limit: 5, offset: 10 });
  assert.deepEqual(p3.indicators.items.map((x) => x.value), ['d10.com', 'd11.com']);
  assert.equal(p3.indicators.returned, 2);
  assert.equal(p3.indicators.has_more, false);
  const past = serializeThreatReport(snapshot({ candidates: cands }), { limit: 5, offset: 50 });
  assert.deepEqual(past.indicators.items, []);
  assert.equal(past.indicators.has_more, false);
});

test('serializeThreatReport: entities are report-level co-mentions (allow-listed, bounded), relationships explicit + named', () => {
  const out = serializeThreatReport(snapshot());
  assert.deepEqual(out.entities, [
    { id: 'e-peck', entity_type: 'campaign', name: 'PeckBirdy', description: 'C2 framework' },
    { id: 'e-sable', entity_type: 'threat_actor', name: 'Sable Squirrel', description: null }
  ]);
  assert.equal(out.relationships.length, 1);
  const rel = out.relationships[0];
  assert.equal(rel.id, 'rel-1');
  assert.equal(rel.relationship_type, 'uses');
  assert.equal(rel.subject_entity_name, 'Sable Squirrel');
  assert.equal(rel.subject_entity_type, 'threat_actor');
  assert.equal(rel.object_entity_name, 'PeckBirdy');
  assert.equal(rel.report.id, REPORT_ID);
  assert.equal(rel.report.tlp_display, 'TLP:CLEAR');
  for (const k of ['report_id', 'subject_entity_id', 'object_entity_id', 'block_id', 'portable_id']) {
    assert.equal(k in rel, false, `${k} must not be exposed`);
  }
  // No indicator was turned into a relationship just because entities co-occur.
  assert.equal(out.relationships.some((r) => r.subject_ioc_id != null || r.object_ioc_id != null), false);
});

test('serializeThreatReport: entity and relationship bounds', () => {
  const ents = Array.from({ length: 80 }, (_, i) => ({ ...ENTITIES[0], id: 1000 + i, public_id: `e${i}`, name: `E${i}` }));
  const rels = Array.from({ length: 150 }, (_, i) => ({ ...RELATIONSHIPS[0], id: 2000 + i, public_id: `r${i}` }));
  const out = serializeThreatReport(snapshot({ entities: ents, relationships: rels }));
  assert.equal(out.entities.length, THREAT_REPORT_MAX_ENTITIES);
  assert.equal(out.entities[0].name, 'E0');
  assert.equal(out.relationships.length, THREAT_REPORT_MAX_RELATIONSHIPS);
  assert.deepEqual(out.counts, { indicators: 2, entities: 80, relationships: 150 });
});

test('loadThreatReportForMcp: fixed query count (report + snapshot), no per-indicator or per-entity reads', async () => {
  const cands = Array.from({ length: 300 }, (_, i) => candidate(i));
  const pool = fakePool({ snap: snapshot({ candidates: cands }) });
  const out = await loadThreatReportForMcp(pool, { id: REPORT_ID, indicator_limit: 500 });
  assert.equal(out.status, 200);
  assert.equal(out.body.indicators.returned, 300);
  // getReportByPublicId + loadReportSnapshot(getReportById, candidates, entities, relationships, artifacts, jobs)
  assert.equal(pool.queries.length, 7);
  assert.equal(pool.queries.some((q) => /^(INSERT|UPDATE|DELETE)/i.test(q.sql)), false);
});

test('loadThreatReportForMcp: invalid id, not found, not ready, deleted', async () => {
  const bad = await loadThreatReportForMcp(fakePool(), { id: '15' });
  assert.equal(bad.status, 400);
  assert.equal(bad.error.code, 'VALIDATION_ERROR');

  const missing = await loadThreatReportForMcp(fakePool({ report: null }), { id: REPORT_ID });
  assert.equal(missing.status, 404);
  assert.equal(missing.error.code, 'REPORT_NOT_FOUND');

  const importing = await loadThreatReportForMcp(fakePool({ report: reportRow({ import_status: 'importing' }) }), { id: REPORT_ID });
  assert.equal(importing.status, 409);
  assert.equal(importing.error.code, 'REPORT_NOT_READY');

  // Custom error-code table is honoured (MCP passes API_ERROR_CODE).
  const custom = await loadThreatReportForMcp(fakePool({ report: null }), { id: REPORT_ID }, { errorCodes: { REPORT_NOT_FOUND: 'X_NF' } });
  assert.equal(custom.error.code, 'X_NF');
});

test('loadThreatReportForMcp: store failure propagates (never an empty report)', async () => {
  const pool = { query: async () => { throw new Error('connection terminated'); } };
  await assert.rejects(() => loadThreatReportForMcp(pool, { id: REPORT_ID }), /connection terminated/);
});
