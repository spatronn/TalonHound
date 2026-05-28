import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildIocInheritedConfidenceSummary,
  computeInheritedEffectiveConfidence,
  normalizeConfidence,
  resolveImportConfidenceFields,
  resolveParsedSourceConfidence,
  validateConfidenceInput
} from './iocConfidence.js';

test('normalizeConfidence maps legacy and invalid values', () => {
  assert.equal(normalizeConfidence('High'), 'high');
  assert.equal(normalizeConfidence('critical'), 'high');
  assert.equal(normalizeConfidence('unknown'), null);
});

test('computeInheritedEffectiveConfidence priority: manual > explicit > feed default', () => {
  const manual = computeInheritedEffectiveConfidence({
    manualOverride: 'low',
    memberships: [{ status: 'active', explicit_confidence: 'high', feed_default_confidence: 'high' }]
  });
  assert.equal(manual.effective, 'low');
  assert.equal(manual.confidence_source, 'manual');

  const explicit = computeInheritedEffectiveConfidence({
    memberships: [{ status: 'active', explicit_confidence: 'high', feed_default_confidence: 'medium' }]
  });
  assert.equal(explicit.effective, 'high');
  assert.equal(explicit.confidence_source, 'feed_entry');

  const inherited = computeInheritedEffectiveConfidence({
    memberships: [{ status: 'active', feed_default_confidence: 'medium', feed_name: 'USOM TR-CERT' }]
  });
  assert.equal(inherited.effective, 'medium');
  assert.equal(inherited.confidence_source, 'feed_default');
  assert.equal(inherited.confidence_inherited_from_feed, true);
  assert.equal(inherited.confidence_feed_name, 'USOM TR-CERT');
});

test('multi-feed aggregation picks highest feed default', () => {
  const result = computeInheritedEffectiveConfidence({
    memberships: [
      { status: 'active', feed_default_confidence: 'medium', feed_name: 'Feed A' },
      { status: 'active', feed_default_confidence: 'high', feed_name: 'Feed B' }
    ]
  });
  assert.equal(result.effective, 'high');
  assert.equal(result.confidence_feed_name, 'Feed B');
});

test('resolveParsedSourceConfidence honors explicit null entry confidence', () => {
  assert.equal(resolveParsedSourceConfidence(null, 'high'), null);
  assert.equal(resolveParsedSourceConfidence(undefined, 'high'), 'high');
});

test('resolveImportConfidenceFields does not copy feed default to ioc row', () => {
  const fields = resolveImportConfidenceFields({ parsedSourceConfidence: null });
  assert.equal(fields.source_confidence, null);
  assert.equal(fields.feed_default_confidence, null);
  assert.equal(fields.confidence, null);
});

test('buildIocInheritedConfidenceSummary uses membership inheritance', () => {
  const summary = buildIocInheritedConfidenceSummary({
    seedRow: { id: 1, public_id: '11111111-1111-1111-1111-111111111111', analyst_confidence_override: null },
    membershipRows: [{
      status: 'active',
      explicit_confidence: null,
      feed_default_confidence: 'high',
      feed_name: 'USOM TR-CERT',
      feed_key: 'usom-trcert'
    }],
    iocRows: []
  });
  assert.equal(summary.effective, 'high');
  assert.equal(summary.confidence_source, 'feed_default');
  assert.equal(summary.confidence_inherited_from_feed, true);
});

test('validateConfidenceInput rejects invalid values', () => {
  assert.equal(validateConfidenceInput('very_high').ok, false);
  assert.equal(validateConfidenceInput('high').ok, true);
});
