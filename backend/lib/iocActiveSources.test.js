import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isActiveFeedMembership,
  isHistoricalFeedMembership,
  parseIocListStatusFilter,
  iocStatusSqlClause,
  membershipDisplayStatus,
  formatFeedMembershipSource,
  formatManualIocSource,
  applyActiveListScope,
  activeObservableHasActiveSourceSql,
  enrichItemsWithActiveSourceCounts,
  fetchIocListStats,
  fetchActiveIocListPage,
  activeScopedObservablesSql
} from './iocActiveSources.js';
import {
  buildIocInheritedConfidenceSummary,
  computeInheritedEffectiveConfidence
} from './iocConfidence.js';

test('applyActiveListScope hides items without active sources when status is active', () => {
  const items = [
    { observable: 'a.example', active_source_count: 1, source_names: ['manual-smoke'] },
    { observable: 'b.example', active_source_count: 0, source_names: [] }
  ];
  const out = applyActiveListScope(items, 'active');
  assert.equal(out.length, 1);
  assert.equal(out[0].observable, 'a.example');
});

test('applyActiveListScope keeps all items for historical/all status', () => {
  const items = [{ active_source_count: 0 }, { active_source_count: 1 }];
  assert.equal(applyActiveListScope(items, 'all').length, 2);
  assert.equal(applyActiveListScope(items, 'expired').length, 2);
});

test('activeObservableHasActiveSourceSql requires active membership filters', () => {
  const sql = activeObservableHasActiveSourceSql('i.observable', 'i.observable_type');
  assert.match(sql, /m\.status = 'active'/);
  assert.match(sql, /m\.purged_at IS NULL/);
  assert.match(sql, /f\.archived_at IS NULL/);
  assert.match(sql, /ioc_source_id IS NOT NULL/);
});

test('fetchIocListStats active mode uses membership-indexed scoped observables', async () => {
  const queries = [];
  const pool = {
    connect: async () => ({
      query: async (sql, params) => pool.query(sql, params),
      release: () => {}
    }),
    async query(sql) {
      queries.push(String(sql));
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK' || sql.startsWith('SET LOCAL')) {
        return { rows: [] };
      }
      if (sql.includes('COUNT(*)::bigint AS count FROM scoped_obs')) {
        return { rows: [{ count: '2' }] };
      }
      if (sql.includes('GROUP BY observable_type')) {
        return { rows: [{ observable_type: 'domain', count: '2' }] };
      }
      if (sql.includes('FROM ioc_feed_memberships m')) {
        return { rows: [{ source_name: 'manual-smoke', count: '2' }] };
      }
      return { rows: [] };
    }
  };
  const stats = await fetchIocListStats(pool, 'active');
  assert.equal(stats.total, 2);
  assert.equal(stats.by_source[0].source_name, 'manual-smoke');
  assert.ok(queries.some((q) => q.includes('m.purged_at IS NULL')));
  assert.ok(queries.some((q) => q.includes('ioc_source_id IS NOT NULL')));
  assert.ok(!queries.some((q) => q.includes('COUNT(*)::bigint AS count FROM scoped_obs') && q.includes('EXISTS (')));
});

test('activeScopedObservablesSql uses feed membership union not correlated exists', () => {
  const sql = activeScopedObservablesSql();
  assert.match(sql, /FROM ioc_feed_memberships m/);
  assert.match(sql, /ioc_source_id IS NOT NULL/);
  assert.doesNotMatch(sql, /EXISTS/);
});

test('fetchActiveIocListPage includes feed-based active IOC', async () => {
  const pool = {
    connect: async () => ({
      query: async (sql, params) => pool.query(sql, params),
      release: () => {}
    }),
    async query(sql, params) {
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK' || sql.startsWith('SET LOCAL')) {
        return { rows: [] };
      }
      if (sql.includes('FROM ioc_feed_memberships m')) {
        return { rows: [{ ioc_item_id: 42, ioc_observable_type: 'domain', sort_ts: '2026-01-02T00:00:00Z' }] };
      }
      if (sql.includes('ioc_source_id IS NOT NULL')) {
        return { rows: [] };
      }
      if (sql.includes('FROM ioc_domain') && sql.includes('id = ANY')) {
        return { rows: [{ id: 42, public_id: '11111111-1111-1111-1111-111111111111', observable: 'evil.example', observable_type: 'domain', created_at: '2026-01-01T00:00:00Z' }] };
      }
      if (sql.includes('FROM ioc_ip_geo_cache')) return { rows: [] };
      return { rows: [] };
    }
  };
  const rows = await fetchActiveIocListPage(pool, { limit: 5, offset: 0 });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].observable, 'evil.example');
});

test('fetchActiveIocListPage includes manual active IOC without feed membership', async () => {
  const pool = {
    connect: async () => ({
      query: async (sql, params) => pool.query(sql, params),
      release: () => {}
    }),
    async query(sql, params) {
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK' || sql.startsWith('SET LOCAL')) {
        return { rows: [] };
      }
      if (sql.includes('FROM ioc_feed_memberships m')) {
        return { rows: [] };
      }
      if (sql.includes('ioc_source_id IS NOT NULL')) {
        return { rows: [{ ioc_item_id: 99, ioc_observable_type: 'ip', sort_ts: '2026-07-05T18:35:30Z' }] };
      }
      if (sql.includes('FROM ioc_ip') && sql.includes('id = ANY')) {
        return { rows: [{ id: 99, public_id: '22222222-2222-2222-2222-222222222222', observable: '31.76.32.249', observable_type: 'ip', created_at: '2026-07-05T18:35:30Z' }] };
      }
      if (sql.includes('FROM ioc_ip_geo_cache')) return { rows: [] };
      return { rows: [] };
    }
  };
  const rows = await fetchActiveIocListPage(pool, { limit: 5, offset: 0 });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].observable, '31.76.32.249');
  assert.equal(rows[0].observable_type, 'ip');
});

test('fetchActiveIocListPage interleaves feed and manual IOCs by sort_ts descending', async () => {
  const pool = {
    connect: async () => ({
      query: async (sql, params) => pool.query(sql, params),
      release: () => {}
    }),
    async query(sql, params) {
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK' || sql.startsWith('SET LOCAL')) {
        return { rows: [] };
      }
      if (sql.includes('FROM ioc_feed_memberships m')) {
        return { rows: [{ ioc_item_id: 10, ioc_observable_type: 'ip', sort_ts: '2026-06-01T00:00:00Z' }] };
      }
      if (sql.includes('ioc_source_id IS NOT NULL')) {
        // manual IOC is newer than the feed IOC
        return { rows: [{ ioc_item_id: 20, ioc_observable_type: 'ip', sort_ts: '2026-07-05T18:35:30Z' }] };
      }
      if (sql.includes('FROM ioc_ip') && sql.includes('id = ANY')) {
        const ids = params[0];
        const rows = [];
        if (ids.includes(20)) rows.push({ id: 20, public_id: 'aaaa', observable: '31.76.32.249', observable_type: 'ip', created_at: '2026-07-05T18:35:30Z' });
        if (ids.includes(10)) rows.push({ id: 10, public_id: 'bbbb', observable: '1.1.1.1', observable_type: 'ip', created_at: '2026-06-01T00:00:00Z' });
        return { rows };
      }
      if (sql.includes('FROM ioc_ip_geo_cache')) return { rows: [] };
      return { rows: [] };
    }
  };
  const rows = await fetchActiveIocListPage(pool, { limit: 10, offset: 0 });
  assert.equal(rows.length, 2);
  // Newer manual IOC should appear first
  assert.equal(rows[0].observable, '31.76.32.249');
  assert.equal(rows[1].observable, '1.1.1.1');
});

test('fetchActiveIocListPage excludes inactive manual IOC from default list', async () => {
  const pool = {
    connect: async () => ({
      query: async (sql, params) => pool.query(sql, params),
      release: () => {}
    }),
    async query(sql, params) {
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK' || sql.startsWith('SET LOCAL')) {
        return { rows: [] };
      }
      if (sql.includes('FROM ioc_feed_memberships m')) return { rows: [] };
      if (sql.includes('ioc_source_id IS NOT NULL')) {
        // The SQL WHERE clause filters status='active', so expired IOC won't be returned
        return { rows: [] };
      }
      if (sql.includes('FROM ioc_ip_geo_cache')) return { rows: [] };
      return { rows: [] };
    }
  };
  const rows = await fetchActiveIocListPage(pool, { limit: 5, offset: 0 });
  assert.equal(rows.length, 0);
});

test('fetchActiveIocListPage manual query uses COALESCE status active filter', async () => {
  const queries = [];
  const pool = {
    connect: async () => ({
      query: async (sql, params) => pool.query(sql, params),
      release: () => {}
    }),
    async query(sql, params) {
      queries.push(String(sql));
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK' || sql.startsWith('SET LOCAL')) {
        return { rows: [] };
      }
      return { rows: [] };
    }
  };
  await fetchActiveIocListPage(pool, { limit: 5, offset: 0 });
  const manualQuery = queries.find((q) => q.includes('ioc_source_id IS NOT NULL'));
  assert.ok(manualQuery, 'must query manual IOCs');
  assert.match(manualQuery, /COALESCE\(status, 'active'\) = 'active'/);
  assert.match(manualQuery, /ORDER BY created_at DESC/);
});

test('enrichItemsWithActiveSourceCounts byItemIds path counts manual IOC as active source', async () => {
  const queries = [];
  const pool = {
    async query(sql, params) {
      queries.push(String(sql));
      if (sql.includes('FROM ioc_feed_memberships m')) return { rows: [] };
      if (sql.includes('ioc_source_id IS NOT NULL')) {
        return { rows: [{ ioc_item_id: 3015395, observable_type: 'ip', source_name: 'manual-smoke' }] };
      }
      return { rows: [] };
    }
  };
  const items = [{ id: 3015395, observable: '31.76.32.249', observable_type: 'ip' }];
  const result = await enrichItemsWithActiveSourceCounts(pool, items, { byItemIds: true });
  assert.equal(result.length, 1);
  assert.equal(result[0].active_source_count, 1, 'manual IOC must count as active source');
  assert.deepEqual(result[0].source_names, ['manual-smoke']);
  assert.ok(queries.some((q) => q.includes('ioc_source_id IS NOT NULL')), 'must query manual sources in byItemIds path');
});

test('membershipDisplayStatus distinguishes purged from expired', () => {
  assert.equal(membershipDisplayStatus({ status: 'expired', purged_at: null }), 'expired');
  assert.equal(membershipDisplayStatus({ status: 'purged', purged_at: new Date() }), 'purged');
  assert.equal(membershipDisplayStatus({ status: 'expired', purged_at: new Date() }), 'purged');
});

test('formatFeedMembershipSource marks purged memberships as non-actionable', () => {
  const purged = formatFeedMembershipSource({
    id: 9,
    feed_name: 'USOM TR-CERT',
    feed_key: 'usom',
    status: 'purged',
    purged_at: new Date(),
    purge_reason: 'feed_data_purge'
  });
  assert.equal(purged.status, 'purged');
  assert.equal(purged.actions_enabled, false);

  const active = formatFeedMembershipSource({
    id: 10,
    feed_name: 'Other Feed',
    feed_key: 'other',
    status: 'active',
    purged_at: null
  });
  assert.equal(active.status, 'active');
  assert.equal(active.actions_enabled, true);
});

test('formatManualIocSource exposes manual active source', () => {
  const manual = formatManualIocSource({
    ioc_item_id: 42,
    ioc_source_id: 7,
    source_name: 'manual-smoke',
    created_at: '2026-01-01T00:00:00Z'
  });
  assert.equal(manual.source_type, 'manual');
  assert.equal(manual.name, 'manual-smoke');
  assert.equal(manual.status, 'active');
  assert.equal(manual.actions_enabled, false);
});

test('isActiveFeedMembership excludes purged memberships', () => {
  assert.equal(isActiveFeedMembership({ status: 'active', purged_at: null }), true);
  assert.equal(isActiveFeedMembership({ status: 'active', purged_at: new Date() }), false);
  assert.equal(isActiveFeedMembership({ status: 'purged', purged_at: new Date() }), false);
  assert.equal(isActiveFeedMembership({ status: 'expired' }), false);
});

test('isHistoricalFeedMembership includes purged and expired', () => {
  assert.equal(isHistoricalFeedMembership({ status: 'purged', purged_at: new Date() }), true);
  assert.equal(isHistoricalFeedMembership({ status: 'expired' }), true);
  assert.equal(isHistoricalFeedMembership({ status: 'active', purged_at: null }), false);
});

test('parseIocListStatusFilter defaults to active', () => {
  assert.equal(parseIocListStatusFilter(undefined), 'active');
  assert.equal(parseIocListStatusFilter('expired'), 'expired');
  assert.equal(parseIocListStatusFilter('all'), 'all');
});

test('iocStatusSqlClause builds active filter', () => {
  assert.match(iocStatusSqlClause('active', 'i'), /COALESCE\(i\.status, 'active'\) = 'active'/);
  assert.equal(iocStatusSqlClause('all'), null);
});

test('purged membership is not used for confidence source', () => {
  const result = computeInheritedEffectiveConfidence({
    memberships: [{
      status: 'purged',
      purged_at: new Date(),
      feed_default_confidence: 'high',
      feed_name: 'USOM TR-CERT'
    }]
  });
  assert.equal(result.effective, null);
  assert.equal(result.confidence_source, 'unknown');
});

test('buildIocInheritedConfidenceSummary ignores purged feed default', () => {
  const summary = buildIocInheritedConfidenceSummary({
    seedRow: { id: 1, public_id: '11111111-1111-1111-1111-111111111111', analyst_confidence_override: null, status: 'expired' },
    membershipRows: [{
      status: 'purged',
      purged_at: new Date(),
      explicit_confidence: null,
      feed_default_confidence: 'high',
      feed_name: 'USOM TR-CERT',
      feed_key: 'usom-trcert'
    }],
    iocRows: [{ status: 'expired', source_name: 'USOM TR-CERT' }]
  });
  assert.equal(summary.effective, null);
  assert.equal(summary.confidence_source, 'unknown');
  assert.equal(summary.has_active_source, false);
  assert.equal(summary.historical_memberships.length, 1);
  assert.equal(summary.historical_memberships[0].status, 'purged');
});

test('shared IOC keeps active feed confidence when other feed purged', () => {
  const summary = buildIocInheritedConfidenceSummary({
    seedRow: { id: 1, public_id: '11111111-1111-1111-1111-111111111111', analyst_confidence_override: null, status: 'active' },
    membershipRows: [
      {
        status: 'purged',
        purged_at: new Date(),
        feed_default_confidence: 'high',
        feed_name: 'USOM TR-CERT',
        feed_key: 'usom'
      },
      {
        status: 'active',
        purged_at: null,
        feed_default_confidence: 'medium',
        feed_name: 'Other Feed',
        feed_key: 'other'
      }
    ],
    iocRows: [{ status: 'active', source_name: 'Other Feed' }]
  });
  assert.equal(summary.effective, 'medium');
  assert.equal(summary.confidence_feed_name, 'Other Feed');
  assert.equal(summary.has_active_source, true);
  assert.equal(summary.membership_breakdown.length, 1);
});
