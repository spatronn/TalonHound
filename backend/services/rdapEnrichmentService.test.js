import test from 'node:test';
import assert from 'node:assert/strict';
import { isCacheFresh } from './rdapEnrichmentService.js';

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
