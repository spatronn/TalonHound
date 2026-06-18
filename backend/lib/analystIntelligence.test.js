import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAnalystIntelligenceSummary,
  diffAnalystIntelligenceFields,
  normalizeTlp,
  validateAnalystIntelligencePayload
} from './analystIntelligence.js';
import { mergeAnalystIntelligenceItem } from '../routes/analystIntelligence.js';

test('normalizeTlp maps white to clear', () => {
  assert.equal(normalizeTlp('WHITE'), 'clear');
  assert.equal(normalizeTlp('clear'), 'clear');
});

test('validateAnalystIntelligencePayload requires title', () => {
  const result = validateAnalystIntelligencePayload({});
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes('title')));
});

test('validateAnalystIntelligencePayload rejects invalid URL', () => {
  const result = validateAnalystIntelligencePayload({
    title: 'Test ref',
    url: 'not-a-url'
  });
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.includes('url')));
});

test('validateAnalystIntelligencePayload accepts valid payload', () => {
  const result = validateAnalystIntelligencePayload({
    title: 'abc.com Free TI lookup',
    url: 'https://abc.com/lookup',
    source_name: 'abc.com',
    reference_type: 'free_ti',
    tlp: 'clear',
    confidence: 'medium',
    assessment_impact: 'supports_malicious',
    note: 'Found malicious classification'
  });
  assert.equal(result.ok, true);
  assert.equal(result.value.reference_type, 'free_ti');
  assert.equal(result.value.tlp, 'clear');
});

test('validateAnalystIntelligencePayload rejects invalid enum', () => {
  const result = validateAnalystIntelligencePayload({
    title: 'Bad enum',
    assessment_impact: 'totally_bad'
  });
  assert.equal(result.ok, false);
});

test('buildAnalystIntelligenceSummary counts impacts', () => {
  const summary = buildAnalystIntelligenceSummary([
    { assessment_impact: 'supports_malicious' },
    { assessment_impact: 'supports_malicious' },
    { assessment_impact: 'needs_review' },
    { assessment_impact: 'context_only' }
  ]);
  assert.equal(summary.total_count, 4);
  assert.equal(summary.supports_malicious_count, 2);
  assert.equal(summary.needs_review_count, 1);
  assert.equal(summary.context_only_count, 1);
});

test('mergeAnalystIntelligenceItem defaults counts to zero', () => {
  const merged = mergeAnalystIntelligenceItem({ id: 1, observable_type: 'ip', observable: '1.2.3.4' }, new Map());
  assert.equal(merged.analyst_intelligence_count, 0);
  assert.equal(merged.supports_malicious_count, 0);
  assert.equal(merged.needs_review_count, 0);
});

test('mergeAnalystIntelligenceItem applies count map', () => {
  const map = new Map([['1|ip', { analyst_intelligence_count: 2, supports_malicious_count: 1, needs_review_count: 0 }]]);
  const merged = mergeAnalystIntelligenceItem({ id: 1, observable_type: 'ip' }, map);
  assert.equal(merged.analyst_intelligence_count, 2);
  assert.equal(merged.supports_malicious_count, 1);
});

test('diffAnalystIntelligenceFields detects changed fields', () => {
  const changed = diffAnalystIntelligenceFields(
    { title: 'A', confidence: 'low' },
    { title: 'B', confidence: 'low' }
  );
  assert.deepEqual(changed, ['title']);
});
