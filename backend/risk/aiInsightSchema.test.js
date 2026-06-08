import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeStructuredAiInsight } from './aiInsightSchema.js';

test('structured AI insight normalizes controlled values and safe actions', () => {
  const out = normalizeStructuredAiInsight(
    {
      summary: 'Phishing pattern with unknown proxy action.',
      threat_class: 'phishing',
      confidence_score: 88,
      impact_level: 'high',
      evidence_strength: 'strong',
      risk_drivers: ['high-confidence phishing tag'],
      missing_context: ['proxy_action_unknown', 'delete_ioc'],
      recommended_controls: ['email_gateway', 'auto_block'],
      recommended_actions: ['review_related_logs', 'block_ioc_automatically']
    },
    {
      ioc_type: 'domain',
      ioc_metadata: { tags: ['phishing'], primary_threat_classification: 'phishing' },
      threat_intel: { virustotal: { available: true }, rdap: { available: true } },
      environment_impact: { detection_events_count: 3, allowed_count: 0, blocked_count: 0, unknown_count: 3 },
      playbook_coverage: { endpoint_process_evidence: false }
    }
  );

  assert.equal(out.threat_class, 'phishing');
  assert.equal(out.impact_level, 'high');
  assert.equal(out.evidence_strength, 'strong');
  assert.deepEqual(out.recommended_controls, ['email_gateway']);
  assert.deepEqual(out.recommended_actions, ['review_related_logs']);
  assert.ok(out.missing_context.includes('proxy_action_unknown'));
  assert.ok(out.missing_context.includes('no_endpoint_context'));
});

test('malformed structured AI insight falls back safely', () => {
  const out = normalizeStructuredAiInsight('not json', {
    ioc_type: 'ip',
    ioc_metadata: { tags: [], primary_threat_classification: null },
    threat_intel: { virustotal: { available: false }, rdap: { available: false } },
    environment_impact: { detection_events_count: 0, allowed_count: 0, blocked_count: 0, unknown_count: 0 },
    playbook_coverage: {}
  });

  assert.equal(out.threat_class, 'unknown');
  assert.equal(out.impact_level, 'unknown');
  assert.equal(out.evidence_strength, 'weak');
  assert.equal(out.confidence_score, 0);
  assert.ok(out.missing_context.includes('no_tags'));
  assert.ok(out.missing_context.includes('unknown_threat_class'));
  assert.ok(out.missing_context.includes('vt_missing'));
  assert.deepEqual(out.recommended_controls, []);
  assert.deepEqual(out.recommended_actions, []);
});

test('unknown recommended action and control values are filtered out', () => {
  const out = normalizeStructuredAiInsight({
    recommended_controls: ['dns_security', 'unknown_control', { value: 'email_gateway' }],
    recommended_actions: ['review_related_logs', 'delete_ioc', 'block_ioc', { value: 'refresh_rdap' }],
    confidence_score: 150,
    impact_level: 'severe',
    evidence_strength: 'certain',
    risk_drivers: ['valid driver', { nope: true }, null]
  }, {
    ioc_type: 'domain',
    ioc_metadata: { tags: ['dns'], primary_threat_classification: 'scanner' },
    threat_intel: { virustotal: { available: true }, rdap: { available: true } },
    environment_impact: { detection_events_count: 1, allowed_count: 1, blocked_count: 0, unknown_count: 0 },
    playbook_coverage: { endpoint_process_evidence: true }
  });

  assert.deepEqual(out.recommended_controls, ['dns_security']);
  assert.deepEqual(out.recommended_actions, ['review_related_logs']);
  assert.equal(out.confidence_score, 100);
  assert.equal(out.impact_level, 'unknown');
  assert.equal(out.evidence_strength, 'weak');
  assert.deepEqual(out.risk_drivers, ['valid driver']);
});
