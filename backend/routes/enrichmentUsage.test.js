import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerEnrichmentUsageRoutes } from './enrichmentUsage.js';

// Fake pool that answers the fixed set of grouped analytics queries plus the
// provider-state / quota lookups the route performs.
function createPool({ providerRows = [], seriesRows = [], typeRows = [], startedOn = null, quotaRows = [] } = {}) {
  return {
    async query(sql) {
      const text = String(sql);
      if (text.includes('SELECT CURRENT_DATE')) {
        // Emulate the DB session clock (System Timezone "today").
        return { rows: [{ today: '2026-08-12' }] };
      }
      if (text.includes('SELECT provider, config FROM threat_intel_provider_configs')) {
        return { rows: quotaRows };
      }
      // VirusTotal registry state loader
      if (text.includes('SELECT enabled, api_key FROM threat_intel_provider_configs')) {
        return { rows: [{ enabled: true, api_key: 'k' }] };
      }
      if (text.includes('FROM enrichment_usage_daily')) {
        if (text.includes('MIN(bucket_date)')) return { rows: [{ started_on: startedOn }] };
        if (text.includes('GROUP BY provider_key')) return { rows: providerRows };
        if (text.includes('GROUP BY bucket_date')) return { rows: seriesRows };
        if (text.includes('GROUP BY ioc_type')) return { rows: typeRows };
      }
      return { rows: [] };
    }
  };
}

async function withServer(pool, run) {
  const app = express();
  registerEnrichmentUsageRoutes(app, pool);
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  try {
    const { port } = server.address();
    await run(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

const VT_ROW = {
  provider_key: 'virustotal',
  request_count: '10', external_call_count: '7', cache_hit_count: '3',
  success_count: '9', failure_count: '1', rate_limit_count: '1',
  total_external_response_time_ms: '1400', external_response_count: '7'
};
const IPINFO_ROW = {
  provider_key: 'ipinfo_lite',
  request_count: '5', external_call_count: '1', cache_hit_count: '4',
  success_count: '5', failure_count: '0', rate_limit_count: '0',
  total_external_response_time_ms: '200', external_response_count: '1'
};

test('default range returns 30-day window with summary distinguishing requests vs external calls', async () => {
  const pool = createPool({
    providerRows: [VT_ROW, IPINFO_ROW],
    seriesRows: [{ date: '2026-08-10', request_count: '3', external_call_count: '2', cache_hit_count: '1', success_count: '3', failure_count: '0', rate_limit_count: '0' }],
    typeRows: [{ ioc_type: 'ip', request_count: '5', external_call_count: '1', cache_hit_count: '4', success_count: '5', failure_count: '0', rate_limit_count: '0', total_external_response_time_ms: '200', external_response_count: '1' }],
    startedOn: '2026-08-01'
  });
  await withServer(pool, async (base) => {
    const res = await fetch(`${base}/api/enrichment-usage`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.range.preset, 'last_30_days');
    // Range is anchored to the DB session "today" (System Timezone), not JS/UTC now.
    assert.equal(body.range.to, '2026-08-12');
    assert.equal(body.range.from, '2026-07-14');
    assert.equal(body.summary.request_count, 15);
    assert.equal(body.summary.external_call_count, 8); // the distinct consumption metric
    assert.equal(body.summary.cache_hit_count, 7);
    assert.equal(body.summary.rate_limit_count, 1);
    assert.equal(body.collection_started_on, '2026-08-01');
    // provider breakdown sorted by external calls desc
    assert.equal(body.providers[0].provider_key, 'virustotal');
    assert.equal(body.series.length, 1);
    assert.equal(body.ioc_types[0].ioc_type, 'ip');
  });
});

test('provider filter narrows summary and breakdown to the selected provider', async () => {
  const pool = createPool({ providerRows: [VT_ROW, IPINFO_ROW] });
  await withServer(pool, async (base) => {
    const res = await fetch(`${base}/api/enrichment-usage?provider=ipinfo_lite`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.filters.provider, 'ipinfo_lite');
    assert.equal(body.summary.request_count, 5); // only ipinfo, not VT
    assert.equal(body.summary.cache_hit_count, 4);
    assert.equal(body.providers.length, 1);
    assert.equal(body.providers[0].provider_key, 'ipinfo_lite');
  });
});

test('unknown provider is rejected with 400', async () => {
  await withServer(createPool(), async (base) => {
    const res = await fetch(`${base}/api/enrichment-usage?provider=does_not_exist`);
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.match(body.message, /unknown provider/i);
  });
});

test('invalid custom date range is rejected with 400', async () => {
  await withServer(createPool(), async (base) => {
    const res = await fetch(`${base}/api/enrichment-usage?range=custom&from=2026-08-10&to=2026-08-01`);
    assert.equal(res.status, 400);
  });
});

test('unknown ioc type is rejected with 400', async () => {
  await withServer(createPool(), async (base) => {
    const res = await fetch(`${base}/api/enrichment-usage?iocType=banana`);
    assert.equal(res.status, 400);
  });
});

test('ioc type filter is accepted', async () => {
  await withServer(createPool({ providerRows: [VT_ROW] }), async (base) => {
    const res = await fetch(`${base}/api/enrichment-usage?iocType=domain`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.filters.ioc_type, 'domain');
  });
});

test('empty period returns zeroed summary and known providers with zero usage', async () => {
  await withServer(createPool({ providerRows: [], startedOn: null }), async (base) => {
    const res = await fetch(`${base}/api/enrichment-usage?range=today`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.summary.request_count, 0);
    assert.equal(body.summary.cache_hit_rate, null); // unknown, not a fake zero
    assert.equal(body.collection_started_on, null);
    // registry providers still listed so the table is not empty
    assert.ok(body.providers.some((p) => p.provider_key === 'virustotal'));
    const vt = body.providers.find((p) => p.provider_key === 'virustotal');
    assert.equal(vt.request_count, 0);
    assert.equal(vt.quota, null); // no quota configured => unavailable, never invented
  });
});

test('quota configured in provider config surfaces as structured metadata', async () => {
  const pool = createPool({
    providerRows: [VT_ROW],
    quotaRows: [{ provider: 'virustotal', config: { quota: { limit: 5000, used: 1240, window: 'monthly', source: 'configured' } } }]
  });
  await withServer(pool, async (base) => {
    const res = await fetch(`${base}/api/enrichment-usage`);
    const body = await res.json();
    const vt = body.providers.find((p) => p.provider_key === 'virustotal');
    assert.deepEqual(vt.quota, { limit: 5000, used: 1240, used_pct: 24.8, window: 'monthly', source: 'configured' });
  });
});

test('GET is served without any role gate (readonly-compatible; RBAC is the global policy)', async () => {
  // The route adds no requireRole; a plain GET returns 200, so the global
  // rbacHttpPolicy (GET allowed for every role) governs access.
  await withServer(createPool(), async (base) => {
    const res = await fetch(`${base}/api/enrichment-usage`);
    assert.equal(res.status, 200);
  });
});
