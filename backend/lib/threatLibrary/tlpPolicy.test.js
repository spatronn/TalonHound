/**
 * TLP derivation: explicit marking > safe default, manual override always
 * wins, and the model's hint never becomes the effective value.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  TLP_RANK,
  TLP_SOURCES,
  defaultTlpForSource,
  detectExplicitTlp,
  isTlpDowngrade,
  isValidTlp,
  isValidTlpSource,
  resolveEffectiveTlp
} from './tlpPolicy.js';
import { planTlpRepair } from '../../scripts/repair-threat-library-tlp.js';
import { buildChunkPrompt, buildSynthesisPrompt, TLP_LINE } from './ai/prompts.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const pipelineSrc = readFileSync(path.join(here, 'pipeline.js'), 'utf8');
const routeSrc = readFileSync(path.join(here, '../../routes/threatLibrary.js'), 'utf8');

function doc(texts, title = 'Iranian cyber targeting of dissidents, activists and journalists') {
  return { title, blocks: texts.map((text, i) => ({ id: `b${i + 1}`, type: 'paragraph', text })) };
}

const sensitivePublicDoc = doc([
  'Iranian state cyber actors are targeting dissidents, activists and journalists with spear-phishing.',
  'The malware CHOSEN BRICK exfiltrates data through Telegram bots; espionage tradecraft is described below.',
  'Mitigations: user awareness and technical controls.'
]);

test('public URL + no explicit marking -> TLP:CLEAR (default), regardless of the AI hint', () => {
  const r = resolveEffectiveTlp({
    report: { tlp: 'clear', tlp_source: 'default', source_type: 'url' },
    document: sensitivePublicDoc,
    aiHint: 'AMBER'
  });
  assert.equal(r.tlp, 'clear');
  assert.equal(r.tlp_source, 'default');
  assert.equal(r.detection, null);
  assert.equal(r.ai_hint, 'amber', 'hint is recorded, not applied');
});

test('sensitive subject matter alone never becomes AMBER: the model hint is ignored even when the row was already AMBER', () => {
  // A report previously persisted with the model-invented value is corrected on re-analysis.
  const r = resolveEffectiveTlp({
    report: { tlp: 'amber', tlp_source: 'default', source_type: 'url' },
    document: sensitivePublicDoc,
    aiHint: 'TLP:AMBER'
  });
  assert.equal(r.tlp, 'clear');
  assert.equal(r.changed, true);
});

test('public URL + explicit TLP:AMBER marking -> AMBER (explicit)', () => {
  const r = resolveEffectiveTlp({
    report: { tlp: 'clear', tlp_source: 'default', source_type: 'url' },
    document: doc(['TLP:AMBER', 'Advisory body text.'])
  });
  assert.equal(r.tlp, 'amber');
  assert.equal(r.tlp_source, 'explicit');
  assert.deepEqual(r.detection.distinct, ['amber']);
});

test('public URL + explicit TLP:RED marking -> RED (explicit); AMBER+STRICT and WHITE normalise', () => {
  assert.equal(resolveEffectiveTlp({ report: { source_type: 'url' }, document: doc(['Marking: TLP:RED']) }).tlp, 'red');
  assert.equal(detectExplicitTlp(doc(['TLP:AMBER+STRICT'])).tlp, 'amber_strict');
  assert.equal(detectExplicitTlp(doc(['TLP AMBER STRICT'])).tlp, 'amber_strict');
  assert.equal(detectExplicitTlp(doc(['TLP:WHITE'])).tlp, 'clear');
  assert.equal(detectExplicitTlp(doc(['TLP: GREEN'])).tlp, 'green');
});

test('explicit marking takes precedence over the public-source fallback and over the AI hint', () => {
  const r = resolveEffectiveTlp({
    report: { tlp: 'clear', tlp_source: 'default', source_type: 'url' },
    document: doc(['This document is TLP:GREEN.']),
    aiHint: 'RED'
  });
  assert.equal(r.tlp, 'green');
  assert.equal(r.tlp_source, 'explicit');
});

test('several distinct markings resolve to the most restrictive (never loosen)', () => {
  const d = detectExplicitTlp(doc(['Footer: TLP:CLEAR', 'Annex marked TLP:AMBER', 'TLP:CLEAR']));
  assert.equal(d.tlp, 'amber');
  assert.deepEqual(d.distinct.sort(), ['amber', 'clear']);
});

test('prose, lowercase and file names are not markings', () => {
  assert.equal(detectExplicitTlp(doc(['Uploaded as tlp_clear_01.pdf'])), null);
  assert.equal(detectExplicitTlp(doc(['the traffic light protocol (tlp) defines amber'])), null);
  assert.equal(detectExplicitTlp(doc(['TLPAMBER'])), null);
  assert.equal(detectExplicitTlp(doc(['Use TLP amber for partners'])), null, 'lowercase level is prose');
  assert.equal(detectExplicitTlp(null), null);
  assert.equal(detectExplicitTlp({ title: 'TLP:AMBER advisory', blocks: [] })?.tlp, 'amber', 'title counts');
});

test('manual override wins over explicit markings and defaults, and reports no change', () => {
  const r = resolveEffectiveTlp({
    report: { tlp: 'green', tlp_source: 'manual', source_type: 'url' },
    document: doc(['TLP:RED']),
    aiHint: 'AMBER'
  });
  assert.equal(r.tlp, 'green');
  assert.equal(r.tlp_source, 'manual');
  assert.equal(r.changed, false);
  assert.equal(r.detection.tlp, 'red', 'detection still recorded for diagnostics');
});

test('private / uploaded sources keep the project default (clear) instead of an invented restriction', () => {
  assert.equal(defaultTlpForSource('pdf'), 'clear');
  assert.equal(defaultTlpForSource('thib'), 'clear');
  const r = resolveEffectiveTlp({ report: { tlp: 'amber', tlp_source: 'default', source_type: 'pdf' }, document: sensitivePublicDoc, aiHint: 'AMBER' });
  assert.equal(r.tlp, 'clear');
});

test('rank, validity and downgrade helpers', () => {
  assert.deepEqual(TLP_SOURCES, ['explicit', 'default', 'manual']);
  assert.ok(TLP_RANK.red > TLP_RANK.amber_strict && TLP_RANK.amber_strict > TLP_RANK.amber && TLP_RANK.amber > TLP_RANK.green && TLP_RANK.green > TLP_RANK.clear);
  assert.equal(isTlpDowngrade('amber', 'clear'), true);
  assert.equal(isTlpDowngrade('clear', 'amber'), false);
  assert.equal(isTlpDowngrade('amber', 'amber'), false);
  assert.equal(isTlpDowngrade('amber_strict', 'amber'), true);
  assert.equal(isValidTlp('amber_strict'), true);
  assert.equal(isValidTlp('purple'), false);
  assert.equal(isValidTlpSource('manual'), true);
  assert.equal(isValidTlpSource('ai'), false);
});

test('pipeline persists the resolved TLP + provenance, never the raw model value', () => {
  assert.doesNotMatch(pipelineSrc, /tlp: normalizeTlp\(aiValue\.tlp/);
  assert.match(pipelineSrc, /const latestReport = \(await getReportById\(pool, report\.id\)\) \|\| report;/, 'manual edits made during analysis are honoured');
  assert.match(pipelineSrc, /resolveEffectiveTlp\(\{ report: latestReport, document, aiHint: aiValue\.tlp \|\| null \}\)/);
  assert.match(pipelineSrc, /tlp: tlpResolution\.tlp,\s*tlp_source: tlpResolution\.tlp_source,/);
  assert.match(pipelineSrc, /ai_result: \{\s*tlp: \{\s*effective: tlpResolution\.tlp,/);
});

test('prompts tell the model to echo only literal markings', () => {
  assert.match(TLP_LINE, /ONLY the exact TLP marking/);
  assert.match(TLP_LINE, /Never infer a TLP/);
  const chunk = buildChunkPrompt({ documentTitle: 't', language: 'en', chunkIndex: 0, chunkTotal: 1, blocksText: 'x', blockIds: ['b1'], toClassify: [], resolved: [] });
  assert.ok(chunk.includes(TLP_LINE));
  assert.ok(buildSynthesisPrompt({ documentTitle: 't', partialsText: '{}' }).includes(TLP_LINE));
});

test('imports record provenance: request-supplied TLP is manual, otherwise default', () => {
  assert.match(routeSrc, /import\/url[\s\S]*?tlp_source: req\.body\?\.tlp \? 'manual' : 'default'/);
  assert.match(routeSrc, /import\/pdf[\s\S]*?tlp_source: req\.body\?\.tlp \? 'manual' : 'default'/);
  assert.match(routeSrc, /tlp_source: row\.tlp_source \|\| 'default'/, 'API exposes provenance');
});

test('repair plan: manual untouched, explicit re-asserted, model-invented corrected, ambiguous left alone', () => {
  const base = { source_type: 'url', canonical_document: sensitivePublicDoc };
  assert.equal(planTlpRepair({ ...base, tlp: 'amber', tlp_source: 'manual' }, ['AMBER']).decision, 'skip_manual');
  const explicit = planTlpRepair({ ...base, tlp: 'clear', tlp_source: 'default', canonical_document: doc(['TLP:AMBER']) }, []);
  assert.deepEqual([explicit.decision, explicit.tlp, explicit.tlp_source, explicit.change], ['explicit', 'amber', 'explicit', true]);
  const ncsc = planTlpRepair({ ...base, tlp: 'amber', tlp_source: 'default' }, ['AMBER']);
  assert.deepEqual([ncsc.decision, ncsc.tlp, ncsc.tlp_source, ncsc.change], ['model_invented', 'clear', 'default', true]);
  const ambiguous = planTlpRepair({ ...base, tlp: 'amber', tlp_source: 'default' }, []);
  assert.deepEqual([ambiguous.decision, ambiguous.tlp, ambiguous.change], ['ambiguous', 'amber', false]);
  const already = planTlpRepair({ ...base, tlp: 'clear', tlp_source: 'default' }, ['AMBER']);
  assert.deepEqual([already.decision, already.change], ['default', false]);
  // Idempotent: running the plan on its own output changes nothing.
  const again = planTlpRepair({ ...base, tlp: ncsc.tlp, tlp_source: ncsc.tlp_source }, ['AMBER']);
  assert.equal(again.change, false);
});
