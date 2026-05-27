import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildIocConfidenceSummary,
  computeEffectiveConfidence,
  normalizeConfidence,
  resolveConfidenceSourceKind,
  resolveImportConfidenceFields,
  validateConfidenceInput
} from './iocConfidence.js';

test('normalizeConfidence maps legacy and invalid values', () => {
  assert.equal(normalizeConfidence('High'), 'high');
  assert.equal(normalizeConfidence('critical'), 'high');
  assert.equal(normalizeConfidence('unknown'), null);
  assert.equal(normalizeConfidence('very_high'), null);
});

test('computeEffectiveConfidence priority: analyst > source > feed default > fallback', () => {
  assert.equal(
    computeEffectiveConfidence({
      sourceConfidence: 'low',
      feedDefaultConfidence: 'medium',
      analystOverride: 'high'
    }),
    'high'
  );
  assert.equal(
    computeEffectiveConfidence({
      sourceConfidence: 'high',
      feedDefaultConfidence: 'medium'
    }),
    'high'
  );
  assert.equal(
    computeEffectiveConfidence({
      sourceConfidence: null,
      feedDefaultConfidence: 'high'
    }),
    'high'
  );
  assert.equal(
    computeEffectiveConfidence({ sourceConfidence: null, feedDefaultConfidence: null }),
    'medium'
  );
});

test('resolveConfidenceSourceKind', () => {
  assert.equal(
    resolveConfidenceSourceKind({ analystOverride: 'high', sourceConfidence: 'low' }),
    'analyst_override'
  );
  assert.equal(
    resolveConfidenceSourceKind({ sourceConfidence: 'medium', feedDefaultConfidence: 'high' }),
    'feed_provided'
  );
  assert.equal(
    resolveConfidenceSourceKind({ feedDefaultConfidence: 'high' }),
    'feed_default'
  );
  assert.equal(resolveConfidenceSourceKind({}), 'system_fallback');
});

test('buildIocConfidenceSummary with feed default and no override', () => {
  const rows = [{
    public_id: '11111111-1111-1111-1111-111111111111',
    source_name: 'MalwareBazaar:abuse.ch',
    source_confidence: null,
    feed_default_confidence: 'high',
    confidence: 'high',
    analyst_confidence_override: null
  }];
  const summary = buildIocConfidenceSummary({
    rows,
    seedPublicId: '11111111-1111-1111-1111-111111111111',
    feedNamesByKey: { 'malwarebazaar-abusech': 'MalwareBazaar abuse.ch' }
  });
  assert.equal(summary.effective, 'high');
  assert.equal(summary.source, 'feed_default');
  assert.equal(summary.feed_name, 'MalwareBazaar abuse.ch');
  assert.equal(summary.analyst_override, null);
});

test('buildIocConfidenceSummary with analyst override', () => {
  const rows = [{
    public_id: '11111111-1111-1111-1111-111111111111',
    source_name: 'MalwareBazaar:abuse.ch',
    source_confidence: 'medium',
    feed_default_confidence: 'medium',
    confidence: 'high',
    analyst_confidence_override: 'high',
    analyst_confidence_override_reason: 'Verified sample',
    analyst_confidence_overridden_at: '2026-05-27T16:55:00.000Z',
    overridden_by_email: 'safa@safa.com'
  }];
  const summary = buildIocConfidenceSummary({
    rows,
    seedPublicId: '11111111-1111-1111-1111-111111111111',
    feedNamesByKey: { 'malwarebazaar-abusech': 'MalwareBazaar abuse.ch' }
  });
  assert.equal(summary.effective, 'high');
  assert.equal(summary.source, 'analyst_override');
  assert.equal(summary.baseline_effective, 'medium');
  assert.equal(summary.override_reason, 'Verified sample');
});

test('resolveImportConfidenceFields preserves analyst override on re-import', () => {
  const fields = resolveImportConfidenceFields({
    parsedSourceConfidence: 'medium',
    feedDefaultConfidence: 'high',
    existingRow: { analyst_confidence_override: 'high' }
  });
  assert.equal(fields.analyst_confidence_override, 'high');
  assert.equal(fields.confidence, 'high');
  assert.equal(fields.source_confidence, 'medium');
});

test('validateConfidenceInput rejects invalid values', () => {
  assert.equal(validateConfidenceInput('very_high').ok, false);
  assert.equal(validateConfidenceInput('high').ok, true);
});
