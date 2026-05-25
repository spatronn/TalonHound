import test from 'node:test';
import assert from 'node:assert/strict';
import { computeIncidentRiskScore } from './incidentRiskScore.js';

test('computeIncidentRiskScore uses event_count when total_hits missing', () => {
  const score = computeIncidentRiskScore({
    ioc_type: 'domain',
    verdict: 'Unreviewed',
    event_count: 2,
    asset_count: 1,
    has_dns_evidence: true,
    has_proxy_evidence: true,
    accepted_connections: 0,
    blocked_connections: 0,
    confidence: 'medium'
  });
  assert.ok(score > 0, `expected positive risk, got ${score}`);
});

test('false positive verdict yields zero risk score', () => {
  const score = computeIncidentRiskScore({
    verdict: 'FP',
    event_count: 10,
    total_hits: 10
  });
  assert.equal(score, 0);
});
