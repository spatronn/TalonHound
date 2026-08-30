import test from 'node:test';
import assert from 'node:assert/strict';
import { runSpamhausDropSync } from './spamhausDropSync.js';

// Provider was enabled when the job was enqueued but disabled before the worker
// picked it up: the worker-side re-check must complete the job cleanly as skipped
// without any external fetch and without triggering a retry.
test('runSpamhausDropSync skips cleanly when provider is disabled (no external fetch)', async () => {
  const pool = {
    async query() {
      return { rows: [{ enabled: false, timeout_ms: 30000, config: {} }] };
    }
  };

  const originalFetch = globalThis.fetch;
  let fetchCalled = false;
  globalThis.fetch = async () => { fetchCalled = true; throw new Error('disabled provider must not fetch'); };
  try {
    const result = await runSpamhausDropSync(pool, { triggeredBy: 'admin' });
    assert.equal(result.ok, true, 'terminal success — no retry');
    assert.equal(result.skipped, true);
    assert.equal(result.reason, 'Spamhaus DROP provider is disabled');
    assert.deepEqual(result.results, {});
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(fetchCalled, false, 'no external fetch for a disabled provider');
});

test('runSpamhausDropSync does not record per-IOC Enrichment Usage', async () => {
  const calls = [];
  const pool = {
    async query(sql) {
      calls.push(String(sql));
      if (String(sql).includes('threat_intel_provider_configs')) {
        return { rows: [{ enabled: true, timeout_ms: 1000, config: { sync_interval_hours: 24 } }] };
      }
      return { rows: [] };
    }
  };

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('network down'); };
  try {
    await runSpamhausDropSync(pool, { triggeredBy: 'scheduler' });
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(
    calls.some((s) => /enrichment_usage_daily/i.test(s)),
    false,
    'dataset sync/import must not increment per-IOC usage telemetry'
  );
});
