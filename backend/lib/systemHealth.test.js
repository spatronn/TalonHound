import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveOverallSystemHealth, summarizeHealth } from './systemHealth.js';

test('required core failure makes overall system unhealthy', () => {
  const result = resolveOverallSystemHealth({
    core: [{ status: 'unhealthy', required: true }],
    providers: [{ status: 'healthy' }]
  });
  assert.equal(result.status, 'unhealthy');
});

test('disabled unhealthy provider does not fail or degrade overall health', () => {
  const result = resolveOverallSystemHealth({
    core: [{ status: 'healthy', required: true }],
    providers: [{ status: 'unhealthy', enabled: false }]
  });
  assert.equal(result.status, 'healthy');
});

test('unknown evidence is not treated as unhealthy', () => {
  const result = resolveOverallSystemHealth({
    core: [{ status: 'healthy', required: true }],
    workers: [{ status: 'unknown' }]
  });
  assert.equal(result.status, 'unknown');
});

test('optional known failure degrades an otherwise operational system', () => {
  const result = resolveOverallSystemHealth({
    core: [{ status: 'healthy', required: true }],
    providers: [{ status: 'unhealthy', enabled: true }]
  });
  assert.equal(result.status, 'degraded');
});

test('summaries retain unknown as a separate count', () => {
  assert.deepEqual(
    summarizeHealth([{ status: 'healthy' }, { status: 'unknown' }, { status: 'failed' }]),
    { total: 3, healthy: 1, degraded: 0, unhealthy: 1, unknown: 1 }
  );
});
