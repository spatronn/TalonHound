import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildIocInheritedConfidenceSummary,
  buildConfidenceProvenance,
  computeInheritedEffectiveConfidence,
  computeItemStoredConfidence,
  normalizeConfidence,
  resolveImportConfidenceFields,
  resolveParsedSourceConfidence,
  resolveIocConfidenceFromMemberships,
  validateConfidenceInput
} from './iocConfidence.js';
import { resolveManualIocConfidenceProvenance } from './manualIocCreate.js';

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

test('buildIocInheritedConfidenceSummary resolves historical feed default for expired IOC', () => {
  const summary = buildIocInheritedConfidenceSummary({
    seedRow: { id: 1, public_id: '11111111-1111-1111-1111-111111111111', analyst_confidence_override: null, status: 'expired' },
    membershipRows: [{
      status: 'expired',
      purged_at: null,
      explicit_confidence: null,
      feed_default_confidence: 'high',
      feed_name: 'URLHaus abuse.ch',
      feed_key: 'urlhaus-abusech'
    }],
    iocRows: [{ status: 'expired', source_name: 'URLHaus abuse.ch' }]
  });
  assert.equal(summary.effective, 'high');
  assert.equal(summary.confidence_source, 'feed_default');
  assert.equal(summary.confidence_source_scope, 'historical');
  assert.match(summary.source_description, /URLHaus abuse\.ch \(historical\)/);
  assert.equal(summary.has_active_source, false);
});

test('buildIocInheritedConfidenceSummary expired IOC uses explicit historical feed entry confidence', () => {
  const summary = buildIocInheritedConfidenceSummary({
    seedRow: { id: 1, status: 'expired', analyst_confidence_override: null },
    membershipRows: [{
      status: 'expired',
      explicit_confidence: 'high',
      feed_default_confidence: 'low',
      feed_name: 'URLHaus abuse.ch',
      feed_key: 'urlhaus-abusech'
    }],
    iocRows: [{ status: 'expired' }]
  });
  assert.equal(summary.effective, 'high');
  assert.equal(summary.confidence_source, 'feed_entry');
  assert.equal(summary.confidence_source_scope, 'historical');
});

test('buildIocInheritedConfidenceSummary expired IOC keeps analyst override', () => {
  const summary = buildIocInheritedConfidenceSummary({
    seedRow: {
      id: 1,
      status: 'expired',
      analyst_confidence_override: 'high',
      overridden_by_email: 'analyst@demo.local'
    },
    membershipRows: [{
      status: 'expired',
      feed_default_confidence: 'low',
      feed_name: 'URLHaus abuse.ch'
    }],
    iocRows: [{ status: 'expired' }]
  });
  assert.equal(summary.effective, 'high');
  assert.equal(summary.confidence_source, 'analyst_override');
  assert.equal(summary.analyst_override, 'high');
});

test('buildIocInheritedConfidenceSummary reactivated IOC uses active membership confidence', () => {
  const summary = buildIocInheritedConfidenceSummary({
    seedRow: { id: 1, status: 'active', analyst_confidence_override: null },
    membershipRows: [
      {
        status: 'expired',
        feed_default_confidence: 'low',
        feed_name: 'Old Feed'
      },
      {
        status: 'active',
        feed_default_confidence: 'high',
        feed_name: 'URLHaus abuse.ch'
      }
    ],
    iocRows: [{ status: 'active' }]
  });
  assert.equal(summary.effective, 'high');
  assert.equal(summary.confidence_source_scope, 'active');
  assert.equal(summary.confidence_feed_name, 'URLHaus abuse.ch');
});

test('buildIocInheritedConfidenceSummary expired IOC without source evidence stays unknown', () => {
  const summary = buildIocInheritedConfidenceSummary({
    seedRow: { id: 1, status: 'expired', analyst_confidence_override: null, confidence: null },
    membershipRows: [],
    iocRows: [{ status: 'expired' }]
  });
  assert.equal(summary.effective, null);
  assert.equal(summary.confidence_source, 'unknown');
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

test('buildIocInheritedConfidenceSummary manual IOC source default', () => {
  const summary = buildIocInheritedConfidenceSummary({
    seedRow: {
      id: 42,
      public_id: '22222222-2222-2222-2222-222222222222',
      confidence: 'high',
      confidence_source: 'ioc_source_default',
      confidence_source_name: 'Threat-Hunting',
      ioc_source_id: 7,
      source_name: 'Threat-Hunting'
    },
    membershipRows: [],
    iocRows: []
  });
  assert.equal(summary.effective, 'high');
  assert.equal(summary.confidence_source, 'ioc_source_default');
  assert.match(summary.source_description, /Threat-Hunting/);
  assert.equal(summary.confidence_provenance.type, 'ioc_source_default');
  assert.match(summary.confidence_provenance.label, /Threat-Hunting/);
});

test('computeItemStoredConfidence infers IOC source when provenance column missing', () => {
  const stored = computeItemStoredConfidence({
    confidence: 'high',
    ioc_source_id: 3,
    source_name: 'Threat-Hunting'
  });
  assert.equal(stored.confidence_source, 'ioc_source_default');
  assert.equal(stored.effective, 'high');
});

test('resolveManualIocConfidenceProvenance distinguishes source default vs manual entry', () => {
  const sourceRow = { name: 'Threat-Hunting', default_confidence: 'high' };
  assert.equal(
    resolveManualIocConfidenceProvenance({ confidence: 'high' }, sourceRow, 'high').confidence_source,
    'ioc_source_default'
  );
  assert.equal(
    resolveManualIocConfidenceProvenance({ confidence: 'medium' }, sourceRow, 'medium').confidence_source,
    'manual_entry'
  );
});

test('validateConfidenceInput rejects invalid values', () => {
  assert.equal(validateConfidenceInput('very_high').ok, false);
  assert.equal(validateConfidenceInput('high').ok, true);
});
