import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveProviderStatus } from './providerMeta.js';

test('provider status consumes canonical backend health', () => {
  assert.equal(resolveProviderStatus({ status: 'healthy', health: { status: 'unknown' } }), 'unknown');
  assert.equal(resolveProviderStatus({ health: { status: 'degraded' } }), 'degraded');
  assert.equal(resolveProviderStatus({ health: { status: 'unhealthy' } }), 'unhealthy');
});

test('enabled RDAP is not inferred healthy without evidence', () => {
  assert.equal(resolveProviderStatus({ provider: 'rdap', enabled: true }), 'unknown');
});

test('legacy errors map to canonical unhealthy', () => {
  assert.equal(resolveProviderStatus({ status: 'error' }), 'unhealthy');
});
