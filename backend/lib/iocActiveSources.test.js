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
  queryActiveIocBrowseWindow,
  activeScopedObservablesSql,
  IOC_LIST_BROWSE_SQL_CONTRACT
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
    async query(sql) {
      if (String(sql).includes('WITH recent AS')) {
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
      if (String(sql).includes('FROM ioc_ip_geo_cache')) return { rows: [] };
      return { rows: [] };
    }
  };
  const rows = await fetchActiveIocListPage(pool, { limit: 5, offset: 0 });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].observable, 'evil.example');
  assert.equal(rows[0].imported_at, '2026-01-01T00:00:00Z');
  assert.equal(rows[0].created_at, '2026-01-01T00:00:00Z');
  assert.equal(rows[0].last_seen_at, rows[0].imported_at);
});

test('fetchActiveIocListPage includes manual active IOC without feed membership', async () => {
  const pool = {
    async query(sql) {
      if (String(sql).includes('WITH recent AS')) {
        return {
          rows: [{
            id: 99,
            public_id: '22222222-2222-2222-2222-222222222222',
            observable: '31.76.32.249',
            observable_type: 'ip',
            created_at: '2026-07-05T18:35:30Z'
          }]
        };
      }
      if (String(sql).includes('FROM ioc_ip_geo_cache')) return { rows: [] };
      return { rows: [] };
    }
  };
  const rows = await fetchActiveIocListPage(pool, { limit: 5, offset: 0 });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].observable, '31.76.32.249');
  assert.equal(rows[0].observable_type, 'ip');
});

test('fetchActiveIocListPage orders by created_at descending (platform import)', async () => {
  const pool = {
    async query(sql) {
      if (String(sql).includes('WITH recent AS')) {
        return {
          rows: [
            { id: 20, public_id: 'aaaa', observable: '31.76.32.249', observable_type: 'ip', created_at: '2026-07-05T18:35:30Z' },
            { id: 10, public_id: 'bbbb', observable: '1.1.1.1', observable_type: 'ip', created_at: '2026-06-01T00:00:00Z' }
          ]
        };
      }
      if (String(sql).includes('FROM ioc_ip_geo_cache')) return { rows: [] };
      return { rows: [] };
    }
  };
  const rows = await fetchActiveIocListPage(pool, { limit: 10, offset: 0 });
  assert.equal(rows.length, 2);
  assert.equal(rows[0].observable, '31.76.32.249');
  assert.equal(rows[1].observable, '1.1.1.1');
});

test('fetchActiveIocListPage excludes inactive rows returned by SQL filter', async () => {
  const pool = {
    async query(sql) {
      if (String(sql).includes('WITH recent AS')) return { rows: [] };
      if (String(sql).includes('FROM ioc_ip_geo_cache')) return { rows: [] };
      return { rows: [] };
    }
  };
  const rows = await fetchActiveIocListPage(pool, { limit: 5, offset: 0 });
  assert.equal(rows.length, 0);
});

test('fetchActiveIocListPage SQL contract: oversample CTE, no NULLS LAST, created_at DESC', async () => {
  const queries = [];
  const pool = {
    async query(sql) {
      queries.push(String(sql));
      return { rows: [] };
    }
  };
  await fetchActiveIocListPage(pool, { limit: 5, offset: 0 });
  const browseSql = queries.find((q) => q.includes('WITH recent AS'));
  assert.ok(browseSql, 'must use oversample CTE');
  assert.match(browseSql, /ORDER BY created_at DESC/);
  assert.match(browseSql, /ORDER BY r\.created_at DESC/);
  assert.equal(browseSql.includes('NULLS LAST'), false);
  assert.match(browseSql, /COALESCE\(r\.status, 'active'\) = 'active'/);
  assert.match(browseSql, /ioc_source_id IS NOT NULL/);
  assert.match(browseSql, /FROM ioc_feed_memberships m/);
});

test('fetchActiveIocListPage page_size slices after window (offset pagination)', async () => {
  const pool = {
    async query(sql, params) {
      if (String(sql).includes('WITH recent AS')) {
        assert.equal(params[1], 10); // need = offset(5)+limit(5)
        const rows = [];
        for (let i = 0; i < 10; i += 1) {
          rows.push({
            id: 100 - i,
            public_id: `p${i}`,
            observable: `o${i}.test`,
            observable_type: 'domain',
            created_at: `2026-07-${String(26 - i).padStart(2, '0')}T00:00:00Z`
          });
        }
        return { rows };
      }
      return { rows: [] };
    }
  };
  const rows = await fetchActiveIocListPage(pool, { limit: 5, offset: 5 });
  assert.equal(rows.length, 5);
  assert.equal(rows[0].observable, 'o5.test');
  assert.equal(rows[4].observable, 'o9.test');
});

test('queryActiveIocBrowseWindow preserves imported_at semantics fields', async () => {
  const pool = {
    async query() {
      return {
        rows: [{
          id: 1,
          public_id: 'x',
          observable: 'a.test',
          observable_type: 'domain',
          created_at: '2026-07-26T10:00:00.000Z'
        }]
      };
    }
  };
  const rows = await queryActiveIocBrowseWindow(pool, { oversample: 50, need: 25 });
  assert.equal(rows[0].created_at, '2026-07-26T10:00:00.000Z');
});

test('IOC_LIST_BROWSE_SQL_CONTRACT documents anti-patterns', () => {
  assert.equal(IOC_LIST_BROWSE_SQL_CONTRACT.forbidsNullsLast, 'NULLS LAST');
  assert.match(IOC_LIST_BROWSE_SQL_CONTRACT.requiresOrderByCreatedAtDesc, /created_at DESC/);
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

test('formatFeedMembershipSource exposes last_changed_at and never derives it from presence', () => {
  const changed = formatFeedMembershipSource({
    id: 11,
    feed_name: 'USOM TR-CERT',
    feed_key: 'usom-trcert',
    status: 'active',
    first_seen_in_feed: '2026-07-19T22:48:00.000Z',
    last_changed_in_source: '2026-07-19T22:48:00.000Z',
    // A later successful poll advanced the technical presence column only.
    last_seen_in_feed: '2026-07-20T19:48:00.000Z'
  });
  assert.equal(changed.first_seen_at, '2026-07-19T22:48:00.000Z');
  assert.equal(
    changed.last_changed_at,
    '2026-07-19T22:48:00.000Z',
    'an unchanged re-import must not advance the analyst-visible timestamp'
  );
  // Deprecated alias is still emitted for backward compatibility, but must not be the
  // value the UI renders.
  assert.equal(changed.last_seen_at, '2026-07-20T19:48:00.000Z');
  assert.notEqual(changed.last_changed_at, changed.last_seen_at);
});

test('formatFeedMembershipSource falls back to first_seen_in_feed before migration 121', () => {
  const legacy = formatFeedMembershipSource({
    id: 12,
    feed_name: 'USOM TR-CERT',
    feed_key: 'usom-trcert',
    status: 'active',
    first_seen_in_feed: '2026-07-19T22:48:00.000Z',
    last_changed_in_source: null,
    last_seen_in_feed: '2026-07-20T19:48:00.000Z'
  });
  assert.equal(
    legacy.last_changed_at,
    '2026-07-19T22:48:00.000Z',
    'NULL must fall back to the documented first_seen baseline, not to last_seen_in_feed'
  );
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
