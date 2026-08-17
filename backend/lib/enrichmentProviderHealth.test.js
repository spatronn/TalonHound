import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolveProviderHealth } from './enrichmentProviderHealth.js';

const NOW = new Date('2026-08-17T12:00:00.000Z');
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

test('recent successful evidence is healthy', () => {
  const health = resolveProviderHealth({
    configured: true,
    last_success_at: new Date(NOW.getTime() - HOUR).toISOString()
  }, { now: NOW, freshnessMs: DAY });
  assert.equal(health.status, 'healthy');
  assert.equal(health.reason, 'recent_success');
});

for (const days of [15, 59]) {
  test(`${days}-day-old successful evidence is unknown`, () => {
    const health = resolveProviderHealth({
      configured: true,
      last_success_at: new Date(NOW.getTime() - days * DAY).toISOString()
    }, { now: NOW, freshnessMs: DAY });
    assert.equal(health.status, 'unknown');
    assert.equal(health.reason, 'stale_success');
  });
}

test('never tested or used is unknown', () => {
  const health = resolveProviderHealth({ configured: true }, { now: NOW, freshnessMs: DAY });
  assert.equal(health.status, 'unknown');
  assert.equal(health.reason, 'no_recent_evidence');
});

test('recent authoritative failure is unhealthy', () => {
  const health = resolveProviderHealth({
    configured: true,
    last_failure_at: new Date(NOW.getTime() - HOUR).toISOString(),
    failure_authoritative: true
  }, { now: NOW, freshnessMs: DAY });
  assert.equal(health.status, 'unhealthy');
  assert.equal(health.reason, 'recent_failure');
});

test('recent runtime failure with recent success is degraded', () => {
  const health = resolveProviderHealth({
    configured: true,
    last_success_at: new Date(NOW.getTime() - 2 * HOUR).toISOString(),
    last_failure_at: new Date(NOW.getTime() - HOUR).toISOString()
  }, { now: NOW, freshnessMs: DAY });
  assert.equal(health.status, 'degraded');
  assert.equal(health.reason, 'partial_failure');
});

test('recent rate limit is degraded', () => {
  const health = resolveProviderHealth({
    configured: true,
    last_failure_at: new Date(NOW.getTime() - HOUR).toISOString(),
    failure_message: 'Provider rate limit reached'
  }, { now: NOW, freshnessMs: DAY });
  assert.equal(health.status, 'degraded');
  assert.equal(health.reason, 'rate_limited');
});

test('provider admin and system health endpoints share one provider loader', () => {
  const server = readFileSync(
    fileURLToPath(new URL('../server.js', import.meta.url)),
    'utf8'
  );
  const calls = [...server.matchAll(/loadEnrichmentProviderSummaries\(\)/g)];
  assert.ok(calls.length >= 3, 'definition plus both endpoint consumers');
  assert.match(server, /admin\/enrichment-providers[\s\S]*loadEnrichmentProviderSummaries\(\)/);
  assert.match(server, /system\/health[\s\S]*loadEnrichmentProviderSummaries\(\)/);
});
