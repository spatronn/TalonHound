import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getIocConfidencePresentation,
  confidenceLabel,
  formatConfidenceAuditMetadata
} from './iocConfidenceCard.js';

test('getIocConfidencePresentation feed default', () => {
  const p = getIocConfidencePresentation({
    effective: 'high',
    source: 'feed_default',
    feed_name: 'MalwareBazaar abuse.ch'
  });
  assert.equal(p.effectiveLabel, 'High');
  assert.equal(p.hasOverride, false);
  assert.match(p.sourceLine, /MalwareBazaar abuse\.ch/);
});

test('getIocConfidencePresentation manual override', () => {
  const p = getIocConfidencePresentation({
    effective: 'high',
    analyst_override: 'high',
    source: 'analyst_override',
    baseline_effective: 'medium',
    overridden_by: 'safa@safa.com',
    overridden_at: '2026-05-27T16:55:00.000Z',
    override_reason: 'Confirmed malicious sample'
  });
  assert.equal(p.hasOverride, true);
  assert.match(p.overrideLine, /safa@safa\.com/);
  assert.equal(p.reasonLine, 'Reason: Confirmed malicious sample');
});

test('getIocConfidencePresentation IOC source default', () => {
  const p = getIocConfidencePresentation({
    effective: 'high',
    source: 'ioc_source_default',
    confidence_source_name: 'Threat-Hunting',
    confidence_provenance: {
      type: 'ioc_source_default',
      source_name: 'Threat-Hunting',
      label: 'IOC source default from Threat-Hunting'
    }
  });
  assert.equal(p.hasOverride, false);
  assert.match(p.sourceLine, /Threat-Hunting/);
  assert.doesNotMatch(p.sourceLine, /Unknown/);
});

test('formatConfidenceAuditMetadata', () => {
  const text = formatConfidenceAuditMetadata({
    old_effective_confidence: 'medium',
    new_effective_confidence: 'high',
    reason: 'Verified',
    user: 'safa@safa.com'
  });
  assert.match(text, /medium → high/);
  assert.match(text, /Verified/);
});

test('confidenceLabel', () => {
  assert.equal(confidenceLabel('high'), 'High');
});
