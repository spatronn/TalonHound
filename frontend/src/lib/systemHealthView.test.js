import test from 'node:test';
import assert from 'node:assert/strict';
import {
  healthLabel,
  normalizeHealthStatus,
  reasonLabel,
  summaryLabel
} from './systemHealthView.js';

test('canonical health labels preserve Unknown as neutral state', () => {
  assert.equal(normalizeHealthStatus('unknown'), 'unknown');
  assert.equal(healthLabel('unknown'), 'Unknown');
  assert.equal(normalizeHealthStatus('configured'), 'unknown');
});

test('summary copy prioritizes problems then unknown evidence', () => {
  assert.equal(summaryLabel({ total: 3, healthy: 1, degraded: 1, unhealthy: 1 }), '2 need attention');
  assert.equal(summaryLabel({ total: 3, healthy: 2, unknown: 1 }), '1 unknown');
  assert.equal(summaryLabel({ total: 2, healthy: 2 }), '2 healthy');
});

test('stale provider success explains unknown health', () => {
  assert.match(reasonLabel('stale_success'), /outside the freshness window/i);
});

test('active-probe health reasons have explicit, non-usage wording', () => {
  // "never checked" is the ONLY Unknown wording — never "no recent usage".
  assert.match(reasonLabel('never_checked'), /no health check has been performed/i);
  assert.match(reasonLabel('health_check_passed'), /connection test succeeded/i);
  assert.match(reasonLabel('overdue'), /overdue/i);
  assert.doesNotMatch(reasonLabel('never_checked'), /usage|enrichment/i);
});
