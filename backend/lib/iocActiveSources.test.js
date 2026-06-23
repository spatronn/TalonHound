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

test('fetchActiveIocListPage paginates via membership index path', async () => {
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
      if (sql.includes('FROM ioc_feed_memberships m') && sql.includes('ORDER BY m.last_seen_in_feed')) {
        return {
          rows: [{
            ioc_item_id: 42,
            ioc_observable_type: 'domain',
            sort_ts: '2026-01-02T00:00:00Z'
          }]
        };
      }
      if (sql.includes('ioc_source_id IS NOT NULL')) {
        return { rows: [] };
      }
      if (sql.includes('FROM ioc_domain') && sql.includes('id = ANY')) {
        return {
          rows: [{
            id: 42,
            public_id: '11111111-1111-1111-1111-111111111111',
            observable: 'evil.example',
            observable_type: 'domain',
            created_at: '2026-01-01T00:00:00Z'
          }]
        };
      }
      return { rows: [] };
    }
  };
  const rows = await fetchActiveIocListPage(pool, { limit: 5, offset: 0 });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].observable, 'evil.example');
  assert.ok(queries.some((q) => q.includes('last_seen_in_feed DESC')));
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
