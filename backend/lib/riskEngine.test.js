import test from 'node:test';
import assert from 'node:assert/strict';
import {
  calculateIncidentRisk,
  calculateInstitutionRisk,
  normalizeVerdict,
  inferEvidenceTier
} from './riskEngine.js';
import { computeEffectiveAiDelta, computeFinalRiskWithLlm } from '../risk/llmRiskAdvisor.js';

function baseIncident(overrides = {}) {
  return {
    ioc_type: 'domain',
    ioc_value: 'evil.example.com',
    total_hits: 10,
    asset_count: 1,
    verdict: 'Unreviewed',
    confidence: 'medium',
    status: 'open',
    first_seen: new Date(Date.now() - 3600000).toISOString(),
    last_seen: new Date().toISOString(),
    ...overrides
  };
}

test('false_positive verdict variants score 0', () => {
  for (const verdict of ['fp', 'FP', 'false_positive', 'false positive', 'False Positive']) {
    const { risk_score } = calculateIncidentRisk(baseIncident({ verdict, total_hits: 5000 }));
    assert.equal(risk_score, 0, `expected 0 for verdict=${verdict}`);
    assert.equal(normalizeVerdict(verdict), 'FP');
  }
});

test('DNS-only 10k hits stays <= 25', () => {
  const { risk_score, risk_breakdown } = calculateIncidentRisk(baseIncident({
    total_hits: 10000,
    has_dns_evidence: true,
    has_proxy_evidence: false,
    has_firewall_evidence: false,
    accepted_connections: 0,
    blocked_connections: 0,
    dominant_source_type: 'dns'
  }));
  assert.equal(inferEvidenceTier(baseIncident({
    has_dns_evidence: true,
    accepted_connections: 0,
    blocked_connections: 0,
    dominant_source_type: 'dns'
  })), 'dns_only');
  assert.ok(risk_score <= 25, `dns-only score ${risk_score} should be <= 25`);
  assert.equal(risk_breakdown.dns_only_dampening, true);
});

test('blocked-only 50k hits stays <= 25', () => {
  const row = baseIncident({
    ioc_type: 'ip',
    ioc_value: '203.0.113.10',
    total_hits: 50000,
    accepted_connections: 0,
    blocked_connections: 1200,
    has_firewall_evidence: true,
    dominant_source_type: 'firewall'
  });
  const { risk_score, risk_breakdown } = calculateIncidentRisk(row);
  assert.equal(inferEvidenceTier(row), 'blocked_only');
  assert.ok(risk_score <= 25, `blocked-only score ${risk_score} should be <= 25`);
  assert.equal(risk_breakdown.blocked_only_dampening, true);
});

test('allowed proxy scores higher than DNS-only for comparable hits', () => {
  const dns = calculateIncidentRisk(baseIncident({
    total_hits: 200,
    has_dns_evidence: true,
    has_proxy_evidence: false,
    accepted_connections: 0,
    blocked_connections: 0,
    dominant_source_type: 'dns'
  }));
  const proxy = calculateIncidentRisk(baseIncident({
    ioc_type: 'url',
    ioc_value: 'http://evil.example.com/malware',
    total_hits: 200,
    has_proxy_evidence: true,
    has_dns_evidence: false,
    accepted_connections: 12,
    blocked_connections: 0,
    dominant_source_type: 'proxy'
  }));
  assert.ok(proxy.risk_score > dns.risk_score, `proxy ${proxy.risk_score} should exceed dns ${dns.risk_score}`);
});

test('multiple hosts increase score more than repeated single-host hits', () => {
  const singleHost = calculateIncidentRisk(baseIncident({
    ioc_type: 'url',
    total_hits: 100,
    asset_count: 1,
    has_proxy_evidence: true,
    accepted_connections: 5,
    blocked_connections: 0,
    dominant_source_type: 'proxy'
  }));
  const multiHost = calculateIncidentRisk(baseIncident({
    ioc_type: 'url',
    total_hits: 100,
    asset_count: 10,
    has_proxy_evidence: true,
    accepted_connections: 5,
    blocked_connections: 0,
    dominant_source_type: 'proxy'
  }));
  assert.ok(
    multiHost.risk_breakdown.components.observed_hosts_signal
      > singleHost.risk_breakdown.components.observed_hosts_signal,
    'multi-host spread signal should exceed single-host spread signal'
  );
  assert.ok(
    multiHost.risk_score >= singleHost.risk_score,
    `multi-host score ${multiHost.risk_score} should be >= single-host ${singleHost.risk_score}`
  );
});

test('low evidence tier caps positive AI delta at +5', () => {
  const incident = baseIncident({
    has_dns_evidence: true,
    accepted_connections: 0,
    blocked_connections: 0
  });
  const tier = inferEvidenceTier(incident);
  const delta = computeEffectiveAiDelta(20, 1, tier, 1);
  assert.ok(delta <= 5, `effective delta ${delta} should be <= 5 for ${tier}`);
});

test('FP with AI adjustment still final score 0', () => {
  const incident = baseIncident({ verdict: 'false positive', total_hits: 1000 });
  const final = computeFinalRiskWithLlm(40, 20, 1, incident, 1);
  assert.equal(final, 0);
});

test('institution with 40 low-quality incidents stays below 80', () => {
  const incidents = Array.from({ length: 40 }, (_, i) => {
    const row = baseIncident({
      id: `id-${i}`,
      incident_id: i + 1,
      ioc_value: `dns-only-${i}.example.com`,
      total_hits: 500,
      asset_count: 1,
      accepted_connections: 0,
      blocked_connections: 0,
      has_dns_evidence: true,
      has_proxy_evidence: false,
      dominant_source_type: 'dns',
      status: i % 3 === 0 ? 'closed' : 'open',
      updated_at: new Date(Date.now() - (i * 86400000)).toISOString()
    });
    const risk = calculateIncidentRisk(row);
    return { ...row, ...risk };
  });

  const overview = calculateInstitutionRisk(incidents);
  assert.ok(
    overview.institution_risk_score < 80,
    `institution score ${overview.institution_risk_score} should stay < 80 for 40 dns-only incidents`
  );
});

test('list-style aggregate fields produce same base score as detail-style row', () => {
  const shared = {
    ioc_type: 'ip',
    ioc_value: '198.51.100.9',
    total_hits: 120,
    asset_count: 3,
    verdict: 'Unreviewed',
    confidence: 'high',
    accepted_connections: 0,
    blocked_connections: 40,
    has_firewall_evidence: true,
    has_dns_evidence: false,
    has_proxy_evidence: false,
    dominant_source_type: 'firewall',
    dominant_parser_source: 'fortigate',
    detection_type: 'realtime'
  };

  const listRow = { ...shared };
  const detailRow = { ...shared, event_count: 120 };

  const listScore = calculateIncidentRisk(listRow).risk_score;
  const detailScore = calculateIncidentRisk(detailRow).risk_score;

  assert.equal(listScore, detailScore);
});

test('low AI confidence yields zero effective delta', () => {
  const delta = computeEffectiveAiDelta(20, 0.2, 'multi_source_network', 1);
  assert.equal(delta, 0);
});
