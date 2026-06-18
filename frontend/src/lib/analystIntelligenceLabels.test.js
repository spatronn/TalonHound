import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assessmentImpactLabel,
  normalizeTlpLabel,
  referenceTypeLabel,
  tlpLabel
} from './analystIntelligenceLabels.js';
import {
  computeAnalystRefsSummary,
  computeOverallSignal,
  computeProviderCoverage,
  computeReputationSummary
} from './intelligenceSummary.js';

test('assessment impact label mapping', () => {
  assert.equal(assessmentImpactLabel('supports_malicious'), 'Supports malicious');
  assert.equal(assessmentImpactLabel('context_only'), 'Context only');
});

test('TLP label mapping normalizes white to clear', () => {
  assert.equal(normalizeTlpLabel('WHITE'), 'clear');
  assert.equal(tlpLabel('clear'), 'TLP:CLEAR');
});

test('reference type label mapping', () => {
  assert.equal(referenceTypeLabel('free_ti'), 'Free TI platform');
  assert.equal(referenceTypeLabel('social'), 'Social / X');
});

test('computeOverallSignal returns suspicious when VT detections exist', () => {
  const signal = computeOverallSignal({
    vt: { status: 'success', malicious: 2, suspicious: 0, detected: 2 },
    abuseipdb: null
  });
  assert.equal(signal.label, 'Suspicious');
});

test('computeAnalystRefsSummary includes malicious count', () => {
  assert.equal(
    computeAnalystRefsSummary({ total_count: 2, supports_malicious_count: 1 }),
    '2 refs / 1 supports malicious'
  );
});

test('provider coverage maps api_key_missing to not configured', () => {
  const coverage = computeProviderCoverage({ virustotal: { status: 'api_key_missing' } });
  assert.equal(coverage.find((p) => p.key === 'virustotal')?.state, 'not_configured');
});

test('computeReputationSummary shows VT ratio', () => {
  const rep = computeReputationSummary({
    vt: { status: 'success', detected: 13, total: 92 },
    abuseipdb: null
  });
  assert.deepEqual(rep, [{ label: 'VT', value: '13 / 92' }]);
});
