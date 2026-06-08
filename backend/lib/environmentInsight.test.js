import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildEnvironmentInsightSummary,
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
