import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isCacheFresh,
  acquireRdapSlotForTests,
  releaseRdapSlotForTests,
  resetRdapQueueForTests,
  getRdapQueueStatsForTests
} from './rdapEnrichmentService.js';

test('isCacheFresh treats recent failed lookups as fresh for read cache', () => {
  const row = {
    rdap_status: 'failed',
    last_enriched_at: new Date().toISOString()
  };
  assert.equal(isCacheFresh(row, { force: false }), true);
});

test('refresh should not reuse failed cache (policy: success-only short-circuit)', () => {
  const existing = {
    rdap_status: 'failed',
    last_enriched_at: new Date().toISOString()
  };
  const shouldShortCircuit = existing?.rdap_status === 'success' && isCacheFresh(existing, { force: false });
  assert.equal(shouldShortCircuit, false);
});

test('refresh may reuse fresh successful cache', () => {
  const existing = {
    rdap_status: 'success',
    last_enriched_at: new Date().toISOString()
  };
  const shouldShortCircuit = existing?.rdap_status === 'success' && isCacheFresh(existing, { force: false });
  assert.equal(shouldShortCircuit, true);
});

test('RDAP waiter queue rejects when full', async () => {
  resetRdapQueueForTests();
  const { maxConcurrency, maxWaiters } = getRdapQueueStatsForTests();
  // Saturate concurrency slots.
  for (let i = 0; i < maxConcurrency; i += 1) {
    await acquireRdapSlotForTests();
  }
  // Fill wait queue to capacity.
  const waiting = [];
  for (let i = 0; i < maxWaiters; i += 1) {
    waiting.push(acquireRdapSlotForTests());
  }
  await assert.rejects(
    () => acquireRdapSlotForTests(),
    (err) => err?.code === 'RDAP_QUEUE_FULL'
  );
  // Drain so later tests are unaffected.
  for (let i = 0; i < maxConcurrency + maxWaiters; i += 1) {
    releaseRdapSlotForTests();
  }
  await Promise.allSettled(waiting);
  resetRdapQueueForTests();
  assert.equal(getRdapQueueStatsForTests().waiting, 0);
  assert.equal(getRdapQueueStatsForTests().active, 0);
});
