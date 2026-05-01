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
