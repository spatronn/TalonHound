import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sanitizeAiTag,
  mergeReportTags,
  persistAiReportTags,
  persistReportIntelligence
} from './reportIntelligence.js';
import { validateAiAnalysis, processAiResponseText } from './ai/schema.js';
import { mergeAnalyses } from './ai/analyze.js';
import { normalizeAiAnalysisInput } from './ai/normalize.js';

const LEGACY_EVIDENCE = 'The report states that victims received phishing emails with malicious links.';

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

test('old analysis JSON without enrichment still validates', () => {
  const r = validateAiAnalysis({
    summary: 'legacy',
    entities: [],
    candidate_updates: [],
    relationships: []
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.report_tags, []);
  assert.equal('mitre_attack' in r.value, false);
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
  assert.equal('mitre_attack' in r.value, false);
});

test('valid tags pass the AI schema; a legacy v7 mitre_attack payload is ignored, not rejected', () => {
  const r = validateAiAnalysis({
    summary: 'ok',
    entities: [],
    candidate_updates: [],
    relationships: [],
    report_tags: ['phishing', 'finance'],
    mitre_attack: [{ technique_id: 'T1566.002', evidence: LEGACY_EVIDENCE, confidence: 0.9 }]
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.report_tags, ['phishing', 'finance']);
  assert.equal('mitre_attack' in r.value, false);
  assert.ok(r.normalization_notes.includes('ignored_legacy_mitre_attack'));
});

test('chunk merge collapses duplicate tags and drops legacy MITRE proposals', () => {
  const legacy = [{ technique_id: 'T1566.002', evidence: LEGACY_EVIDENCE, confidence: 0.95 }];
  const merged = mergeAnalyses([
    { summary: 'a', entities: [], candidate_updates: [], relationships: [], report_tags: ['Phishing'], mitre_attack: legacy },
    { summary: 'b', entities: [], candidate_updates: [], relationships: [], report_tags: ['phishing', 'finance'], mitre_attack: legacy }
  ]);
  assert.equal(merged.ok, true);
  assert.deepEqual(merged.value.report_tags, ['phishing', 'finance']);
  assert.equal('mitre_attack' in merged.value, false);
});

test('empty tags are valid and no mitre_attack field is defaulted', () => {
  const n = normalizeAiAnalysisInput({ summary: 'only summary', confidence: 0.5 });
  assert.deepEqual(n.value.report_tags, []);
  assert.equal('mitre_attack' in n.value, false);
});

function mockDb(state) {
  return {
    query: async (sql, params) => {
      const s = String(sql);
      state.sql?.push(s);
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
      return { rows: [], rowCount: 0 };
    }
  };
}

test('AI tags create and link three new catalog tags', async () => {
  const state = { tags: [], links: new Set(), nextId: 10 };
  const stats = await persistAiReportTags(mockDb(state), 1, ['phishing', 'credential theft', 'finance']);
  assert.equal(stats.created, 3);
  assert.equal(stats.linked, 3);
  assert.equal(state.tags.length, 3);
});

test('existing tag with different casing is reused', async () => {
  const state = {
    tags: [{ id: 3, name: 'phishing', slug: 'phishing', type: 'context', enabled: true }],
    links: new Set(),
    nextId: 10
  };
  const stats = await persistAiReportTags(mockDb(state), 1, ['Phishing']);
  assert.equal(stats.reused, 1);
  assert.equal(stats.created, 0);
  assert.equal(state.tags.length, 1);
});

test('duplicate AI tags create one link', async () => {
  const state = { tags: [], links: new Set(), nextId: 10 };
  const stats = await persistAiReportTags(mockDb(state), 1, ['phishing', 'Phishing', 'phishing']);
  assert.equal(stats.accepted, 3);
  assert.equal(state.links.size, 1);
});

test('re-analysis does not duplicate report-tag links', async () => {
  const state = { tags: [], links: new Set(), nextId: 10 };
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
    nextId: 10
  };
  await persistAiReportTags(mockDb(state), 1, ['phishing']);
  assert.ok(state.links.has('1:1'));
  assert.ok(state.links.has('1:2'));
});

test('concurrent tag create race reuses the winner', async () => {
  const state = { tags: [], links: new Set(), nextId: 10 };
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

test('report intelligence persist never touches threat_report_mitre_mappings, even for a legacy payload', async () => {
  const state = { tags: [], links: new Set(), nextId: 10, sql: [] };
  const diag = await persistReportIntelligence(
    mockDb(state),
    4,
    { report_tags: ['phishing'], mitre_attack: [{ technique_id: 'T1566', evidence: LEGACY_EVIDENCE, confidence: 0.99 }] },
    { log: { info: () => {}, warn: () => {} } }
  );
  assert.equal(diag.tags_accepted, 1);
  assert.equal(state.links.size, 1);
  assert.equal(state.sql.some((q) => /mitre/i.test(q)), false);
  assert.equal(Object.keys(diag).some((k) => /mitre/i.test(k)), false);
});
