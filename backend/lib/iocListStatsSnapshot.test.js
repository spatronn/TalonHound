import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeIocListStatsPayload } from './iocListStatsSnapshot.js';
import { buildIocListPagination } from './iocListPagination.js';

test('normalizeIocListStatsPayload aggregates hash types and top sources', () => {
  const payload = normalizeIocListStatsPayload({
    total: 1600000,
    by_type: [
      { observable_type: 'ip', count: 900000 },
      { observable_type: 'md5', count: 100000 },
      { observable_type: 'sha256', count: 50000 },
      { observable_type: 'domain', count: 200000 }
    ],
    by_source: [
      { source_name: 'URLhaus:abuse.ch', count: 400000 },
      { source_name: 'manual-smoke', count: 1000 }
    ]
  });

  assert.equal(payload.total_records, 1600000);
  assert.equal(payload.by_type.find((x) => x.observable_type === 'ip')?.count, 900000);
  assert.equal(payload.by_type.find((x) => x.observable_type === 'hash')?.count, 150000);
  assert.equal(payload.top_sources.length, 2);
});

test('buildIocListPagination uses browse cap when global total unknown', () => {
  const p = buildIocListPagination({
    mode: 'browse',
    globalTotalUnknown: true,
    page: 1,
    pageSize: 25,
    statusFilter: 'active'
  });
  assert.equal(p.global_total, null);
  assert.equal(p.listed_items, 2000);
  assert.equal(p.is_capped, true);
});

test('buildIocListPagination still uses snapshot global total when provided', () => {
  const p = buildIocListPagination({
    mode: 'browse',
    globalTotal: 1672730,
    page: 2,
    pageSize: 25,
    statusFilter: 'active'
  });
  assert.equal(p.global_total, 1672730);
  assert.equal(p.listed_items, 2000);
  assert.equal(p.is_capped, true);
});
