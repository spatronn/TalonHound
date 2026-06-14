import test from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveExplanationEvidenceTier,
  deriveExplanationActionOutcome,
  buildRiskExplanation,
  formatEvidenceTierLabel,
  formatActionOutcomeLabel
} from './riskExplanation.js';
import {
  inferEventFamilyFromRow,
  isProxyFailedEvent,
  isSubstantiveDnsEvent
} from './eventEvidenceSignals.js';

const INCIDENT_900_PROXY_RAW = '<182>Jun 14 21:55:21 ollama squid-access: 1781474121.853     92 192.168.1.8 TCP_TUNNEL/503 0 CONNECT aasdaonz.mechanickhodakarami.shop:443 -';

test('incident #900 pattern: proxy CONNECT 503 is proxy evidence not DNS only', () => {
  const context = {
    ioc_type: 'domain',
    has_dns_evidence: true,
    has_proxy_evidence: false,
    event_summary: { source_types: { proxy: 1 } },
    explanation_events: [
      {
        source_type: 'generic',
        parser_source: 'unknown',
        raw_log_snapshot: INCIDENT_900_PROXY_RAW
      },
      {
        source_type: 'dns',
        parser_source: 'syslog_observables',
        raw_log_snapshot: ''
      }
    ]
  };

  const evidence = deriveExplanationEvidenceTier(context, { evidence_tier: 'dns_only' });
  const action = deriveExplanationActionOutcome(context, { action_outcome: 'unknown' });

  assert.equal(evidence.tier, 'proxy_only');
  assert.equal(evidence.label, 'Proxy Evidence');
  assert.equal(action.outcome, 'proxy_failed');
  assert.equal(action.label, 'Proxy Failed');
});

test('dns + proxy incident shows DNS + Proxy Evidence not proxy_only', () => {
  const context = {
    event_summary: { source_types: { dns: 1, proxy: 1 } },
    has_dns_evidence: true,
    has_proxy_evidence: true,
    accepted_connections: 0,
    blocked_connections: 0,
    explanation_events: [
      { source_type: 'dns', raw_log_snapshot: 'client 10.0.0.5#52341: query: evil.example.com IN A' },
      { source_type: 'proxy', raw_log_snapshot: '10.0.0.5 TCP_MISS/200 512 CONNECT evil.example.com:443' }
    ]
  };
  const evidence = deriveExplanationEvidenceTier(context, { evidence_tier: 'proxy_only' });
  assert.equal(evidence.tier, 'dns_proxy');
  assert.equal(evidence.label, 'DNS + Proxy Evidence');
});

test('proxy access in raw log maps to Observed Access outcome', () => {
  const context = {
    event_summary: { source_types: { dns: 1, proxy: 1 } },
    has_dns_evidence: true,
    has_proxy_evidence: true,
    accepted_connections: 0,
    blocked_connections: 0,
    explanation_events: [
      { source_type: 'dns', raw_log_snapshot: 'client 10.0.0.5#52341: query: evil.example.com IN A' },
      { source_type: 'proxy', raw_log_snapshot: '10.0.0.5 TCP_MISS/200 512 CONNECT evil.example.com:443' }
    ]
  };
  const action = deriveExplanationActionOutcome(context, { action_outcome: 'unknown' });
  assert.equal(action.outcome, 'observed_access');
  assert.equal(action.label, 'Observed Access');
});

test('dns-only incident stays DNS Only / DNS Observed', () => {
  const context = {
    event_summary: { source_types: { dns: 3 } },
    has_dns_evidence: true,
    has_proxy_evidence: false,
    accepted_connections: 0,
    blocked_connections: 0,
    explanation_events: [
      { source_type: 'dns', raw_log_snapshot: 'client 10.0.0.5#52341: query: evil.example.com IN A' }
    ]
  };
  const evidence = deriveExplanationEvidenceTier(context, {});
  const action = deriveExplanationActionOutcome(context, {});
  assert.equal(evidence.tier, 'dns_only');
  assert.equal(evidence.label, 'DNS Only');
  assert.equal(action.outcome, 'dns_observed');
  assert.equal(action.label, 'DNS Observed');
});

test('proxy-only incident stays Proxy Evidence', () => {
  const context = {
    event_summary: { source_types: { proxy: 2 } },
    has_proxy_evidence: true,
    has_dns_evidence: false,
    explanation_events: [
      { source_type: 'proxy', raw_log_snapshot: '192.168.1.8 TCP_TUNNEL/503 0 CONNECT evil.example.com:443' }
    ]
  };
  const evidence = deriveExplanationEvidenceTier(context, {});
  assert.equal(evidence.tier, 'proxy_only');
  assert.equal(evidence.label, 'Proxy Evidence');
});

test('label formatters map raw enums to analyst-friendly text', () => {
  assert.equal(formatEvidenceTierLabel('proxy_only'), 'Proxy Evidence');
  assert.equal(formatActionOutcomeLabel('proxy_failed'), 'Proxy Failed');
  assert.equal(formatActionOutcomeLabel('unknown'), 'Unknown Outcome');
});

test('buildRiskExplanation exposes label fields', () => {
  const out = buildRiskExplanation(
    { risk_score: 20, risk_breakdown: { verdict: 'Unreviewed', components: {}, accepted_connections: 0, blocked_connections: 0 } },
    { final_risk_score: 20 },
    {
      event_summary: { source_types: { dns: 1, proxy: 1 } },
      has_dns_evidence: true,
      has_proxy_evidence: true,
      explanation_events: [
        { source_type: 'dns', raw_log_snapshot: 'client 10.0.0.5 query: evil.example.com IN A' },
        { source_type: 'proxy', raw_log_snapshot: 'TCP_MISS/200 CONNECT evil.example.com:443' }
      ]
    }
  );
  assert.equal(out.evidence_tier_label, 'DNS + Proxy Evidence');
  assert.equal(out.action_outcome_label, 'Observed Access');
});

test('event evidence helpers classify squid CONNECT and empty dns stub', () => {
  assert.equal(inferEventFamilyFromRow({ raw_log_snapshot: INCIDENT_900_PROXY_RAW }), 'proxy');
  assert.equal(isProxyFailedEvent({ raw_log_snapshot: INCIDENT_900_PROXY_RAW }), true);
  assert.equal(isSubstantiveDnsEvent({ source_type: 'dns', parser_source: 'syslog_observables', raw_log_snapshot: '' }), false);
});
