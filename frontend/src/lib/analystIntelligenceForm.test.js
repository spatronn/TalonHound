import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAnalystReferencePayload,
  toAnalystReferenceForm
} from './analystIntelligenceForm.js';

test('toAnalystReferenceForm maps backend enums for edit', () => {
  const form = toAnalystReferenceForm({
    title: 'Ref',
    url: 'https://example.com',
    reference_type: 'internal_note',
    tlp: 'clear',
    confidence: 'unknown',
    assessment_impact: 'context_only',
    note: 'line one'
  });
  assert.equal(form.reference_type, 'internal_note');
  assert.equal(form.confidence, 'unknown');
  assert.equal(form.assessment_impact, 'context_only');
  assert.equal(form.note, 'line one');
  assert.equal('source_name' in form, false);
});

test('buildAnalystReferencePayload sends enum values and omits source_name', () => {
  const payload = buildAnalystReferencePayload({
    title: '  Ref title  ',
    url: '',
    reference_type: 'free_ti',
    tlp: 'green',
    confidence: 'high',
    assessment_impact: 'supports_malicious',
    note: 'updated note\nsecond line'
  });
  assert.deepEqual(payload, {
    title: 'Ref title',
    url: null,
    reference_type: 'free_ti',
    tlp: 'green',
    confidence: 'high',
    assessment_impact: 'supports_malicious',
    note: 'updated note\nsecond line'
  });
  assert.equal('source_name' in payload, false);
});

test('buildAnalystReferencePayload trims note and url', () => {
  const payload = buildAnalystReferencePayload({
    title: 'T',
    url: 'https://x.com',
    reference_type: 'other',
    tlp: 'clear',
    confidence: 'low',
    assessment_impact: 'needs_review',
    note: '  '
  });
  assert.equal(payload.url, 'https://x.com');
  assert.equal(payload.note, null);
});
