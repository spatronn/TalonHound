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
    baseline_effective: 'medium',
    overridden_by: 'safa@safa.com',
    overridden_at: '2026-05-27T16:55:00.000Z',
    override_reason: 'Confirmed malicious sample'
  });
  assert.equal(p.hasOverride, true);
  assert.match(p.overrideLine, /safa@safa\.com/);
  assert.equal(p.reasonLine, 'Reason: Confirmed malicious sample');
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
