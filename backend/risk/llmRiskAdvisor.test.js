import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAdvisorOutput } from './llmRiskAdvisor.js';

function buildEnrichedDomainIncident() {
  return {
    ioc: 'malicious-domain.com',
    ioc_type: 'domain',
    activity_type: 'dns',
    stats: {
      total_hits: 2500,
      observed_hosts: 6,
      duration_minutes: 60 * 36
    },
    related_iocs: [
      {
        relationship: 'dns_response_ip',
        source_ioc: 'malicious-domain.com',
        related_ioc: '5.6.7.8',
        related_ioc_in_ioc_list: true,
        chain_type: 'environment_level_related_activity',
        traffic: { accepted_count: 4, services: ['tcp'], ports: [8080] }
      }
    ]
  };
}

test('normalizer sets +10 floor for strong related IOC evidence', () => {
  const enrichedContext = buildEnrichedDomainIncident();
  const out = normalizeAdvisorOutput({ risk_adjustment: 5, confidence: 0.9, reason: 'high dns volume' }, 'ok', enrichedContext);

  assert.equal(out.hasAcceptedOrSuccessfulTraffic, true);
  assert.equal(out.hasStrongMaliciousContext, true);
  assert.equal(out.adjustment, 10);
  assert.match(out.reason, /malicious-domain\.com/i);
  assert.match(out.reason, /5\.6\.7\.8/);
  assert.match(out.reason, /ioc list/i);
  assert.match(out.reason, /accepted traffic/i);
  assert.match(out.reason, /tcp\/8080/i);
  assert.match(out.reason, /environment-level/i);
  assert.doesNotMatch(out.reason, /confirmed compromise/i);
});

test('worker/manual equivalent enriched context yields same signals and adjustment', () => {
  const workerContext = buildEnrichedDomainIncident();
  const manualContext = JSON.parse(JSON.stringify(workerContext));

  const workerOut = normalizeAdvisorOutput({ risk_adjustment: 0, confidence: 0.6, reason: 'dns activity' }, 'ok', workerContext);
  const manualOut = normalizeAdvisorOutput({ risk_adjustment: 0, confidence: 0.6, reason: 'dns activity' }, 'ok', manualContext);

  assert.equal(workerOut.hasAcceptedOrSuccessfulTraffic, manualOut.hasAcceptedOrSuccessfulTraffic);
  assert.equal(workerOut.hasStrongMaliciousContext, manualOut.hasStrongMaliciousContext);
  assert.equal(workerOut.adjustment, manualOut.adjustment);
});

test('domain invalid_reason path uses tiered fallback, not URL hardcoded string', () => {
  const out = normalizeAdvisorOutput(
    { risk_adjustment: 5, confidence: 0.2, reason: 'this increases the risk of breach' },
    'ok',
    { ioc_type: 'domain', activity_type: 'dns', stats: { observed_hosts: 1, duration_minutes: 2 } }
  );
  assert.equal(out.normalization_reason, 'invalid_reason_persistence_contradiction');
  assert.equal(out.adjustment, 0);
  assert.ok(out.confidence >= 0.45 && out.confidence <= 0.65);
  assert.ok(!out.reason.includes('Repeated proxy URL access attempts'));
  assert.ok(out.reason.includes('normalized detection events supported by'));
});

test('domain model DNS-heavy reason is rewritten when proxy signals exist in payload evidence', () => {
  const payload = {
    ioc: 'kapindakimutlulukhemenal.com',
    ioc_type: 'domain',
    activity_type: 'dns',
    incident: { detection_event_count: 2, evidence_log_count: 5 },
    evidence_log_count: 5,
    stats: { observed_hosts: 1, duration_minutes: 3, event_count: 2 },
    event_summary: { source_types: { dns: 1, proxy: 1 } },
    playbook_coverage: { proxy_evidence: true },
    evidence_summary: { samples: ['TCP_TUNNEL/200 CONNECT kapindakimutlulukhemenal.com'] },
    sample_events: []
  };
  const out = normalizeAdvisorOutput(
    { risk_adjustment: 0, confidence: 0.6, reason: 'Moderate DNS query volume with no persistence or a single observed host, and short duration.' },
    'ok',
    payload
  );
  assert.match(out.reason, /proxy|CONNECT|network-level/i);
  assert.ok(!/^moderate dns query volume/i.test(out.reason.trim()));
  assert.equal(out.adjustment, 5);
  assert.equal(out.normalization_reason, 'domain_dns_proxy_tunnel_adjustment');
});

test('URL playbook incomplete still uses URL-specific fallback', () => {
  const out = normalizeAdvisorOutput(
    { risk_adjustment: 10, confidence: 0.8, reason: 'nothing useful here' },
    'ok',
    { ioc_type: 'url', stats: { observed_hosts: 1, duration_minutes: 5 } }
  );
  assert.equal(out.normalization_reason, 'invalid_reason_persistence_contradiction');
  assert.ok(out.reason.includes('proxy URL') || out.reason.includes('observed network activity'));
});
