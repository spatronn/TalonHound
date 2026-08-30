import test from 'node:test';
import assert from 'node:assert/strict';
import {
  rowToSpamhausApiPayload,
  persistSpamhausLookupResult
} from './spamhausDropEnrichmentService.js';

test('rowToSpamhausApiPayload returns not_run for missing row', () => {
  const r = rowToSpamhausApiPayload(null);
  assert.equal(r.status, 'not_run');
  assert.equal(r.provider, 'spamhaus_drop');
});

test('rowToSpamhausApiPayload maps listed row', () => {
  const r = rowToSpamhausApiPayload({
    lookup_ip: '1.2.3.4',
    provider_status: 'listed',
    listed: true,
    matched_cidr: '1.2.3.0/24',
    sblid: 'SBL1',
    rir: 'arin',
    list_type: 'drop_v4',
    dataset_status: 'healthy',
    enriched_at: '2026-07-15T12:00:00Z'
  });
  assert.equal(r.status, 'listed');
  assert.equal(r.matched_cidr, '1.2.3.0/24');
  assert.equal(r.last_enriched_at, '2026-07-15T12:00:00Z');
});

test('rowToSpamhausApiPayload maps not_listed row', () => {
  const r = rowToSpamhausApiPayload({
    lookup_ip: '8.8.8.8',
    provider_status: 'not_listed',
    listed: false,
    enriched_at: '2026-07-15T12:00:00Z'
  });
  assert.equal(r.status, 'not_listed');
  assert.equal(r.listed, false);
});

test('persistSpamhausLookupResult upserts listed/not_listed and skips dataset_not_synced', async () => {
  const calls = [];
  const pool = {
    query: async (sql, params) => {
      calls.push({ sql: String(sql), params });
      return { rows: [{ lookup_ip: params[0], provider_status: params[3] }] };
    }
  };

  await persistSpamhausLookupResult(pool, {
    targetIp: '39.80.61.25',
    iocValue: 'http://39.80.61.25:36540/bin.sh',
    iocType: 'url',
    response: { status: 'not_listed', listed: false, target_ip: '39.80.61.25' }
  });
  assert.equal(calls.length, 1);
  assert.match(calls[0].sql, /INSERT INTO ioc_spamhaus_drop_enrichment/i);
  assert.equal(calls[0].params[0], '39.80.61.25');
  assert.equal(calls[0].params[3], 'not_listed');

  calls.length = 0;
  const skipped = await persistSpamhausLookupResult(pool, {
    targetIp: '39.80.61.25',
    iocValue: 'http://39.80.61.25:36540/bin.sh',
    iocType: 'url',
    response: { status: 'dataset_not_synced', listed: null }
  });
  assert.equal(skipped, null);
  assert.equal(calls.length, 0);
});
