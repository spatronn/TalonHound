import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildEnvironmentInsightSummary,
  compactEnvironmentInsightSummary,
  parseEnvironmentInsightRange
} from './environmentInsight.js';

test('environment insight range validation safely defaults invalid values', () => {
  assert.equal(parseEnvironmentInsightRange('7d'), 7);
  assert.equal(parseEnvironmentInsightRange('30'), 30);
  assert.equal(parseEnvironmentInsightRange('90d'), 90);
  assert.equal(parseEnvironmentInsightRange('365d'), 30);
  assert.equal(parseEnvironmentInsightRange('bad'), 30);
  assert.equal(parseEnvironmentInsightRange(''), 30);
});

test('environment insight aggregate handles an empty period', async () => {
  const periodStart = new Date('2026-05-09T00:00:00Z');
  const periodEnd = new Date('2026-06-08T00:00:00Z');
  const pool = {
    async query(sql) {
      if (sql.includes('AS period_start')) return { rows: [{ period_start: periodStart, period_end: periodEnd }] };
      if (sql.includes('COUNT(*)::int AS total_incidents')) {
        return { rows: [{ total_incidents: 0, open_incidents: 0, closed_incidents: 0 }] };
      }
      if (sql.includes('COUNT(*)::int AS detection_events')) {
        return { rows: [{ detection_events: 0, observed_hosts: 0, allowed_count: 0, blocked_count: 0 }] };
      }
      return { rows: [] };
    }
  };

  const summary = await buildEnvironmentInsightSummary({
    pool,
    rangeDays: 30,
    calculateIncidentRisk: () => ({ risk_score: 0 }),
    computeInstitutionRiskOverview: async () => null,
    incidentStatsSelect: 'COUNT(*)::int AS event_count'
  });

  assert.equal(summary.range_days, 30);
  assert.equal(summary.aggregate_package_version, 'environment_insight_v1');
  assert.deepEqual(summary.totals, {
    total_incidents: 0,
    open_incidents: 0,
    closed_incidents: 0,
    detection_events: 0,
    observed_hosts: 0
  });
  assert.deepEqual(summary.allowed_blocked_unknown_ratio, { allowed: 0, blocked: 0, unknown: 0 });
  assert.deepEqual(summary.highest_risk_incidents, []);
  assert.equal(summary.safety_constraints.no_automatic_remediation, true);
});

test('environment insight compact payload respects top N limits', () => {
  const input = {
    range_days: 30,
    totals: { total_incidents: 20 },
    top_tags: Array.from({ length: 12 }, (_, i) => ({ key: `tag-${i}`, count: 20 - i })),
    top_ioc_sources: Array.from({ length: 12 }, (_, i) => ({ key: `source-${i}`, count: 20 - i })),
    recommended_controls_frequency: Array.from({ length: 12 }, (_, i) => ({ key: `control-${i}`, count: 20 - i })),
    missing_context_frequency: Array.from({ length: 12 }, (_, i) => ({ key: `missing-${i}`, count: 20 - i })),
    top_risk_drivers: Array.from({ length: 12 }, (_, i) => ({ key: `driver-${i}`, count: 20 - i })),
    top_risk_reducers: Array.from({ length: 12 }, (_, i) => ({ key: `reducer-${i}`, count: 20 - i })),
    highest_risk_incidents: Array.from({ length: 8 }, (_, i) => ({
      id: `inc-${i}`,
      incident_id: i + 1,
      public_id: `ioc-${i}`,
      ioc_value: `very-sensitive-${i}.example`,
      ioc_type: 'domain',
      risk_score: 90 - i,
      threat_class: 'phishing',
      tags: ['phishing', 'credential', 'extra', 'overflow', 'x', 'y', 'z'],
      source: 'feed',
      observed_hosts_count: i,
      event_count: i + 2,
      reason_summary: 'A '.repeat(200)
    }))
  };

  const compact = compactEnvironmentInsightSummary(input, { topSampleLimit: 5, listLimit: 10 });
  assert.equal(compact.top_tags.length, 10);
  assert.equal(compact.top_ioc_sources.length, 10);
  assert.equal(compact.recommended_controls_frequency.length, 10);
  assert.equal(compact.missing_context_frequency.length, 10);
  assert.equal(compact.top_risk_drivers.length, 10);
  assert.equal(compact.top_risk_reducers.length, 10);
  assert.equal(compact.highest_risk_incidents.length, 5);
  assert.equal(compact.highest_risk_incidents[0].ioc_value, undefined);
  assert.equal(compact.highest_risk_incidents[0].public_id, 'ioc-0');
  assert.ok(compact.highest_risk_incidents[0].reason_summary.length <= 180);
  assert.equal(compact.highest_risk_incidents[0].tags.length, 6);
});
