import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sanitizeAiTag,
  mergeReportTags,
  mergeMitreProposals,
  mergeReportIntelligence,
  validateMitreMappings,
  persistAiReportTags,
  persistAiReportMitre,
  persistReportIntelligence,
  serializeMitreMappingRow,
  MITRE_ACCEPT_MIN_CONFIDENCE
} from './reportIntelligence.js';
import { loadMitreReference, invalidateMitreReferenceCache } from '../threatClassifications/mitreReference.js';
import { validateAiAnalysis, processAiResponseText } from './ai/schema.js';
import { mergeAnalyses } from './ai/analyze.js';
import { normalizeAiAnalysisInput } from './ai/normalize.js';

const PHISH_EVIDENCE = 'The report states that victims received phishing emails with malicious links.';

function mitreItem(id, extra = {}) {
  return { technique_id: id, evidence: PHISH_EVIDENCE, confidence: 0.9, ...extra };
}

test('sanitizeAiTag reuses space form and rejects filler / IOC-like / empty', () => {
  assert.deepEqual(sanitizeAiTag('Credential-Theft'), { ok: true, name: 'credential theft' });
  assert.deepEqual(sanitizeAiTag('  Phishing  '), { ok: true, name: 'phishing' });
  assert.equal(sanitizeAiTag('security').ok, false);
  assert.equal(sanitizeAiTag('malware').reason, 'filler');
  assert.equal(sanitizeAiTag('').reason, 'empty');
  assert.equal(sanitizeAiTag('   ').reason, 'empty');
  assert.equal(sanitizeAiTag(null).reason, 'empty');
  assert.equal(sanitizeAiTag(12).reason, 'malformed');
  assert.equal(sanitizeAiTag('CVE-2024-1234').reason, 'ioc_like');
  assert.equal(sanitizeAiTag('https://evil.example').reason, 'ioc_like');
  assert.equal(sanitizeAiTag('a'.repeat(50)).reason, 'too_long');
});

test('mergeReportTags collapses case/hyphen duplicates and caps at 5', () => {
  const merged = mergeReportTags([
    ['Phishing', 'credential-theft', 'finance'],
    ['phishing', 'PowerShell', 'Windows', 'cloud']
  ]);
  assert.deepEqual(merged.tags, ['phishing', 'credential theft', 'finance', 'powershell', 'windows']);
  assert.equal(merged.tags.includes('cloud'), false);
});

test('mergeReportTags rejects filler and empty without inventing replacements', () => {
  const merged = mergeReportTags([['security', '', 'phishing', 'research']]);
  assert.deepEqual(merged.tags, ['phishing']);
  assert.ok(merged.rejected.some((r) => r.reason === 'filler'));
});

test('mergeMitreProposals keeps one row per technique and strongest evidence', () => {
  const { byId } = mergeMitreProposals([
    [mitreItem('T1566.002', { confidence: 0.8, evidence: 'short' })],
    [mitreItem('T1566.002', { confidence: 0.96, evidence: 'The report states victims clicked credential-harvesting links.' })]
  ]);
  const one = byId.get('T1566.002');
  assert.equal(one.confidence, 0.96);
  assert.match(one.evidence, /credential-harvesting/);
});

test('validateMitreMappings accepts catalog techniques and rejects unknown / malformed / low confidence / no evidence', async () => {
  invalidateMitreReferenceCache();
  const reference = await loadMitreReference();
  const merged = mergeMitreProposals([[
    mitreItem('T1566'),
    mitreItem('T1566.002'),
    mitreItem('T9999'),
    { technique_id: 'not-an-id', evidence: PHISH_EVIDENCE, confidence: 0.9 },
    mitreItem('T1059.001', { confidence: 0.2 }),
    { technique_id: 'T1105', evidence: '', confidence: 0.99 }
  ]]);
  const { accepted, rejected } = validateMitreMappings(merged, reference);
  const ids = accepted.map((m) => m.technique_id);
  assert.ok(ids.includes('T1566.002'));
  assert.equal(ids.includes('T1566'), false, 'parent dropped when sub-technique is accepted');
  assert.ok(rejected.some((r) => r.technique_id === 'T9999' && r.reason === 'unknown_id'));
  assert.ok(merged.rejected.some((r) => r.reason === 'malformed_id'));
  assert.ok(rejected.some((r) => r.technique_id === 'T1059.001' && r.reason === 'low_confidence'));
  assert.ok(rejected.some((r) => r.technique_id === 'T1105' && r.reason === 'missing_evidence'));
  const spear = accepted.find((m) => m.technique_id === 'T1566.002');
  assert.equal(spear.technique_name, 'Spearphishing Link');
  assert.ok(spear.tactics.some((t) => t.id === 'TA0001' && t.name === 'Initial Access'));
});

test('canonical name/tactic come from catalog, not the model', async () => {
  invalidateMitreReferenceCache();
  const reference = await loadMitreReference();
  const { accepted } = validateMitreMappings(
    mergeMitreProposals([[{
      technique_id: 'T1566',
      evidence: PHISH_EVIDENCE,
      confidence: 0.9,
      technique_name: 'Wrong Name',
      tactic: 'Impact'
    }]]),
    reference
  );
  assert.equal(accepted[0].technique_name, 'Phishing');
  assert.ok(accepted[0].tactics.some((t) => t.name === 'Initial Access'));
  assert.equal(accepted[0].tactics.some((t) => t.name === 'Impact'), false);
});

test('confidence floor is the shared MITRE accept threshold', () => {
  assert.equal(MITRE_ACCEPT_MIN_CONFIDENCE, 0.75);
});

test('old analysis JSON without enrichment still validates', () => {
  const r = validateAiAnalysis({
    summary: 'legacy',
    entities: [],
    candidate_updates: [],
    relationships: []
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.report_tags, []);
  assert.deepEqual(r.value.mitre_attack, []);
});

test('malformed optional enrichment is stripped; IOC extraction still succeeds', () => {
  const r = processAiResponseText(JSON.stringify({
    summary: 'ok',
    entities: [{ entity_type: 'malware', name: 'Lynx' }],
    candidate_updates: [],
    relationships: [],
    report_tags: { not: 'an array' },
    mitre_attack: 'T1566'
  }));
  assert.equal(r.ok, true);
  assert.equal(r.value.entities[0].name, 'Lynx');
  assert.deepEqual(r.value.report_tags, []);
  assert.deepEqual(r.value.mitre_attack, []);
});

test('valid tags + MITRE pass the AI schema', () => {
  const r = validateAiAnalysis({
    summary: 'ok',
    entities: [],
    candidate_updates: [],
    relationships: [],
    report_tags: ['phishing', 'finance'],
    mitre_attack: [mitreItem('T1566.002')]
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.report_tags, ['phishing', 'finance']);
  assert.equal(r.value.mitre_attack[0].technique_id, 'T1566.002');
});

test('chunk merge collapses duplicate tags and MITRE ids', () => {
  const merged = mergeAnalyses([
    { summary: 'a', entities: [], candidate_updates: [], relationships: [], report_tags: ['Phishing'], mitre_attack: [mitreItem('T1566.002', { confidence: 0.8 })] },
    { summary: 'b', entities: [], candidate_updates: [], relationships: [], report_tags: ['phishing', 'finance'], mitre_attack: [mitreItem('T1566.002', { confidence: 0.95 })] }
  ]);
  assert.equal(merged.ok, true);
  assert.deepEqual(merged.value.report_tags, ['phishing', 'finance']);
  assert.equal(merged.value.mitre_attack.length, 1);
  assert.equal(merged.value.mitre_attack[0].confidence, 0.95);
});

test('empty tags and missing MITRE are valid', () => {
  const n = normalizeAiAnalysisInput({ summary: 'only summary', confidence: 0.5 });
  assert.deepEqual(n.value.report_tags, []);
  assert.deepEqual(n.value.mitre_attack, []);
  const intel = mergeReportIntelligence([{ summary: 'x', report_tags: [], mitre_attack: [] }]);
  assert.deepEqual(intel.report_tags, []);
  assert.equal(intel.mitre_proposals.size, 0);
});

function mockDb(state) {
  return {
    query: async (sql, params) => {
      const s = String(sql);
      if (/FROM tags WHERE name = \$1 OR slug = \$2/.test(s)) {
        const hit = state.tags.find((t) => t.name === params[0] || t.slug === params[1]);
        return { rows: hit ? [hit] : [] };
      }
      if (/FROM tags WHERE name = \$1 LIMIT 1/.test(s)) {
        const hit = state.tags.find((t) => t.name === params[0]);
        return { rows: hit ? [hit] : [] };
      }
      if (/INSERT INTO tags /.test(s)) {
        if (state.tags.some((t) => t.name === params[0])) {
          const err = new Error('duplicate');
          err.code = '23505';
          throw err;
        }
        const row = {
          id: state.nextId++,
          name: params[0],
          slug: params[1],
          type: params[2],
          category: params[3],
          enabled: true,
          created_origin: params[7]
        };
        state.tags.push(row);
        return { rows: [row] };
      }
      if (/INSERT INTO threat_report_tags/.test(s)) {
        const key = `${params[0]}:${params[1]}`;
        if (state.links.has(key)) return { rowCount: 0 };
        state.links.add(key);
        return { rowCount: 1 };
      }
      if (/INSERT INTO threat_report_mitre_mappings/.test(s)) {
        const key = `${params[0]}:${params[1]}`;
        const prev = state.mitre.get(key);
        state.mitre.set(key, { report_id: params[0], attack_id: params[1], confidence: params[2], evidence_text: params[3] });
        return { rowCount: prev ? 1 : 1 };
      }
      if (/FROM threat_report_mitre_mappings/.test(s)) {
        const rows = [...state.mitre.values()].filter((r) => Number(r.report_id) === Number(params[0]?.[0] || params[0]));
        return { rows };
      }
      return { rows: [], rowCount: 0 };
    }
  };
}

test('AI tags create and link three new catalog tags', async () => {
  const state = { tags: [], links: new Set(), mitre: new Map(), nextId: 10 };
  const stats = await persistAiReportTags(mockDb(state), 1, ['phishing', 'credential theft', 'finance']);
  assert.equal(stats.created, 3);
  assert.equal(stats.linked, 3);
  assert.equal(state.tags.length, 3);
});

test('existing tag with different casing is reused', async () => {
  const state = {
    tags: [{ id: 3, name: 'phishing', slug: 'phishing', type: 'context', enabled: true }],
    links: new Set(),
    mitre: new Map(),
    nextId: 10
  };
  const stats = await persistAiReportTags(mockDb(state), 1, ['Phishing']);
  assert.equal(stats.reused, 1);
  assert.equal(stats.created, 0);
  assert.equal(state.tags.length, 1);
});

test('duplicate AI tags create one link', async () => {
  const state = { tags: [], links: new Set(), mitre: new Map(), nextId: 10 };
  const stats = await persistAiReportTags(mockDb(state), 1, ['phishing', 'Phishing', 'phishing']);
  assert.equal(stats.accepted, 3);
  assert.equal(state.links.size, 1);
});

test('re-analysis does not duplicate report-tag links', async () => {
  const state = { tags: [], links: new Set(), mitre: new Map(), nextId: 10 };
  const db = mockDb(state);
  await persistAiReportTags(db, 1, ['phishing']);
  const again = await persistAiReportTags(db, 1, ['phishing']);
  assert.equal(state.links.size, 1);
  assert.equal(again.already_linked, 1);
});

test('manually existing report tag survives AI analysis', async () => {
  const state = {
    tags: [
      { id: 1, name: 'microsoft 365', slug: 'microsoft-365', type: 'context', enabled: true },
      { id: 2, name: 'phishing', slug: 'phishing', type: 'context', enabled: true }
    ],
    links: new Set(['1:1']),
    mitre: new Map(),
    nextId: 10
  };
  await persistAiReportTags(mockDb(state), 1, ['phishing']);
  assert.ok(state.links.has('1:1'));
  assert.ok(state.links.has('1:2'));
});

test('concurrent tag create race reuses the winner', async () => {
  const state = { tags: [], links: new Set(), mitre: new Map(), nextId: 10 };
  const db = mockDb(state);
  const first = db.query.bind(db);
  let inserts = 0;
  db.query = async (sql, params) => {
    if (/INSERT INTO tags /.test(String(sql))) {
      inserts += 1;
      if (inserts === 1) {
        state.tags.push({
          id: 99, name: params[0], slug: params[1], type: 'context', enabled: true
        });
        const err = new Error('duplicate');
        err.code = '23505';
        throw err;
      }
    }
    return first(sql, params);
  };
  const stats = await persistAiReportTags(db, 1, ['phishing']);
  assert.equal(stats.created, 0);
  assert.equal(stats.reused, 1);
  assert.equal(state.tags.filter((t) => t.name === 'phishing').length, 1);
});

test('valid MITRE rows persist; re-analysis upserts without a second identity', async () => {
  const state = { tags: [], links: new Set(), mitre: new Map(), nextId: 10 };
  const db = mockDb(state);
  await persistAiReportMitre(db, 7, [
    { technique_id: 'T1566', confidence: 0.8, evidence: PHISH_EVIDENCE }
  ]);
  await persistAiReportMitre(db, 7, [
    { technique_id: 'T1566', confidence: 0.92, evidence: 'Updated short evidence from the report.' }
  ]);
  assert.equal(state.mitre.size, 1);
  assert.equal(state.mitre.get('7:T1566').confidence, 0.92);
});

test('persistReportIntelligence keeps IOC-side success when MITRE catalog lookup is empty', async () => {
  const state = { tags: [], links: new Set(), mitre: new Map(), nextId: 10 };
  const logs = [];
  const diag = await persistReportIntelligence(
    mockDb(state),
    4,
    { report_tags: ['phishing'], mitre_attack: [mitreItem('T1566')] },
    { log: { info: () => {}, warn: (m) => logs.push(m) }, reference: new Map() }
  );
  assert.equal(diag.tags_accepted, 1);
  assert.equal(diag.mitre_accepted, 0);
  assert.ok(diag.mitre_rejected.some((r) => r.reason === 'unknown_id' || r.reason === 'catalog_unavailable' || r.technique_id === 'T1566'));
});

test('serializeMitreMappingRow uses catalog metadata', async () => {
  invalidateMitreReferenceCache();
  const reference = await loadMitreReference();
  const row = serializeMitreMappingRow({
    attack_id: 'T1566.002',
    confidence: 0.91,
    evidence_text: PHISH_EVIDENCE
  }, reference);
  assert.equal(row.technique_id, 'T1566.002');
  assert.equal(row.technique_name, 'Spearphishing Link');
  assert.ok(row.tactics.some((t) => t.id === 'TA0001'));
  assert.equal(row.confidence, 0.91);
  assert.equal(row.evidence, PHISH_EVIDENCE);
});
