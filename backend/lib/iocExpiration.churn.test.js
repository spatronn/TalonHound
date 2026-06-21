import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeMembershipFieldPatch,
  membershipComputedFieldsUnchanged,
  upsertMembershipOnImport,
  withImportOptimizationContext
} from './iocExpiration.js';
import {
  pickFeedPolicyFromRows,
  resolveFeedPolicyFromContext,
  isIocSuppressedFromIndex,
  scheduleDeferredIocRecompute
} from './importOptimizationContext.js';
import { buildSuppressionIndex } from './ioc-suppression.js';
import { persistPublishedFeedSnapshot } from './feedPublisherService.js';
import { fingerprintAggregateRows } from '../ioc-match-count-worker.js';

describe('computeMembershipFieldPatch no-op detection', () => {
  it('detects unchanged computed membership fields', () => {
    const m = {
      first_seen_in_feed: '2026-01-01T00:00:00Z',
      last_seen_in_feed: '2026-01-02T00:00:00Z',
      missing_since: null,
      override_enabled: false,
      policy_expires_at: '2026-02-01T00:00:00Z',
      expires_at: '2026-02-01T00:00:00Z',
      status: 'active',
      expired_at: null,
      expiration_reason: null
    };
    const policy = { enabled: true, expiration_mode: 'last_seen_ttl', ttl_days: 30 };
    const patch = computeMembershipFieldPatch(m, policy, new Date('2026-01-02T00:00:00Z'));
    assert.equal(membershipComputedFieldsUnchanged(m, patch), true);
  });
});

describe('pickFeedPolicyFromRows', () => {
  const rows = [
    { feed_id: '11111111-1111-1111-1111-111111111111', observable_type: 'all', expiration_mode: 'never', enabled: true },
    { feed_id: '11111111-1111-1111-1111-111111111111', observable_type: 'domain', expiration_mode: 'last_seen_ttl', ttl_days: 30, enabled: true }
  ];

  it('prefers specific observable_type over all', () => {
    const policy = pickFeedPolicyFromRows(rows, '11111111-1111-1111-1111-111111111111', 'domain');
    assert.equal(policy.expiration_mode, 'last_seen_ttl');
  });

  it('resolveFeedPolicyFromContext caches by feed/type', () => {
    const ctx = { policyRows: rows, _policyByKey: new Map() };
    const a = resolveFeedPolicyFromContext(ctx, '11111111-1111-1111-1111-111111111111', 'domain');
    const b = resolveFeedPolicyFromContext(ctx, '11111111-1111-1111-1111-111111111111', 'domain');
    assert.equal(a, b);
    assert.equal(ctx._policyByKey.size, 1);
  });
});

describe('suppression index', () => {
  it('matches suppressed IOC from preloaded index', () => {
    const index = buildSuppressionIndex([
      { ioc_value: 'evil.test', ioc_type: 'domain', scope: 'global' }
    ]);
    assert.equal(isIocSuppressedFromIndex(index, 'evil.test', 'domain'), true);
    assert.equal(isIocSuppressedFromIndex(index, 'good.test', 'domain'), false);
  });
});

describe('upsertMembershipOnImport conditional updates', () => {
  it('skips membership UPDATE when row already active with same last_seen', async () => {
    const seenAt = new Date('2026-06-01T12:00:00Z');
    const updates = [];
    const membershipRow = {
      id: 10,
      ioc_item_id: 99,
      ioc_observable_type: 'domain',
      feed_id: '11111111-1111-1111-1111-111111111111',
      first_seen_in_feed: seenAt,
      last_seen_in_feed: seenAt,
      missing_since: null,
      override_enabled: false,
      status: 'active',
      expired_at: null,
      expiration_reason: null,
      purged_at: null,
      purged_by: null,
      purged_by_username: null,
      purge_reason: null,
      policy_expires_at: null,
      expires_at: null,
      explicit_confidence: 'high'
    };

    const client = {
      async query(sql, params) {
        const s = String(sql);
        if (s.includes('FROM threat_feed_expiration_policies') && s.includes('SELECT *')) {
          return { rows: [{ enabled: false, expiration_mode: 'never', feed_id: '11111111-1111-1111-1111-111111111111', observable_type: 'all' }] };
        }
        if (s.includes('FROM ioc_suppressions')) {
          return { rows: [] };
        }
        if (s.includes('FROM threat_feed_expiration_policies') && s.includes('feed_id = $1')) {
          return { rows: [{ enabled: false, expiration_mode: 'never' }] };
        }
        if (s.includes('FROM ioc_feed_memberships') && s.includes('ioc_item_id')) {
          return { rows: [membershipRow], rowCount: 1 };
        }
        if (s.startsWith('UPDATE ioc_feed_memberships') && s.includes('last_seen_in_feed')) {
          updates.push('touch');
          return { rows: [], rowCount: 0 };
        }
        if (s.startsWith('UPDATE ioc_feed_memberships') && s.includes('policy_expires_at')) {
          updates.push('computed');
          return { rows: [], rowCount: 0 };
        }
        if (s.startsWith('UPDATE ioc_feed_memberships') && s.includes('explicit_confidence')) {
          updates.push('confidence');
          return { rows: [], rowCount: 0 };
        }
        if (s.includes('FROM ioc_items') && s.includes('manual_status_override')) {
          return { rows: [{ id: 99, observable: 'evil.test', observable_type: 'domain', status: 'active', manual_status_override: false, expires_at: null, expired_at: null, expiration_reason: null }] };
        }
        if (s.includes('FROM ioc_feed_memberships m') && s.includes('INNER JOIN ioc_items')) {
          return { rows: [{ status: 'active', purged_at: null }] };
        }
        if (s.includes('MIN(m.expires_at)')) {
          return { rows: [{ min_exp: null }] };
        }
        return { rows: [], rowCount: 0 };
      }
    };

    await withImportOptimizationContext(client, async () => {
      await upsertMembershipOnImport(client, {
        iocItemId: 99,
        observableType: 'domain',
        feedId: '11111111-1111-1111-1111-111111111111',
        seenAt,
        explicitConfidence: 'high'
      });
    });

    assert.deepEqual(updates, []);
  });

  it('reactivates expired membership with UPDATE', async () => {
    const seenAt = new Date('2026-06-01T12:00:00Z');
    let reactivatedUpdate = false;
    const membershipRow = {
      id: 10,
      status: 'expired',
      override_enabled: false,
      last_seen_in_feed: '2026-01-01T00:00:00Z',
      missing_since: null,
      expired_at: '2026-05-01T00:00:00Z',
      expiration_reason: 'policy',
      purged_at: null,
      purged_by: null,
      purged_by_username: null,
      purge_reason: null,
      policy_expires_at: null,
      expires_at: null,
      first_seen_in_feed: '2026-01-01T00:00:00Z'
    };

    const client = {
      async query(sql) {
        const s = String(sql);
        if (s.includes('FROM threat_feed_expiration_policies')) {
          return { rows: [{ enabled: false, expiration_mode: 'never' }] };
        }
        if (s.includes('FROM ioc_feed_memberships') && s.includes('ioc_item_id')) {
          return { rows: [membershipRow], rowCount: 1 };
        }
        if (s.startsWith('UPDATE ioc_feed_memberships') && s.includes("status = 'active'")) {
          reactivatedUpdate = true;
          return { rows: [{ ...membershipRow, status: 'active' }], rowCount: 1 };
        }
        if (s.startsWith('UPDATE ioc_feed_memberships')) {
          return { rows: [{ ...membershipRow, status: 'active' }], rowCount: 1 };
        }
        if (s.includes('FROM ioc_items') && s.includes('manual_status_override')) {
          return { rows: [{ id: 99, observable: 'evil.test', observable_type: 'domain', status: 'expired', manual_status_override: false, expires_at: null, expired_at: '2026-05-01T00:00:00Z', expiration_reason: 'policy' }] };
        }
        if (s.includes('FROM ioc_feed_memberships m') && s.includes('INNER JOIN ioc_items')) {
          return { rows: [{ status: 'active', purged_at: null }] };
        }
        if (s.includes('MIN(m.expires_at)')) {
          return { rows: [{ min_exp: null }] };
        }
        if (s.startsWith('UPDATE ioc_items')) {
          return { rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      }
    };

    await upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: '11111111-1111-1111-1111-111111111111',
      seenAt
    });

    assert.equal(reactivatedUpdate, true);
  });
});

describe('deferred recompute scheduling', () => {
  it('deduplicates IOC keys in deferred set', () => {
    const ctx = { deferredRecomputes: new Map() };
    scheduleDeferredIocRecompute(ctx, { iocItemId: 1, observableType: 'domain' });
    scheduleDeferredIocRecompute(ctx, { iocItemId: 1, observableType: 'domain' });
    scheduleDeferredIocRecompute(ctx, { iocItemId: 2, observableType: 'domain' });
    assert.equal(ctx.deferredRecomputes.size, 2);
  });
});

describe('persistPublishedFeedSnapshot unchanged hash', () => {
  it('does not UPDATE when content hash is unchanged', async () => {
    const calls = [];
    const client = {
      async query(sql, params = []) {
        const normalized = String(sql).replace(/\s+/g, ' ').trim();
        calls.push(normalized);
        if (normalized === 'BEGIN' || normalized === 'COMMIT' || normalized === 'ROLLBACK') {
          return { rows: [] };
        }
        if (normalized.includes('pg_advisory_xact_lock')) return { rows: [] };
        if (normalized.includes('FOR UPDATE') && normalized.includes("status = 'success'")) {
          return { rows: [{ id: 42, content_hash: 'abc123' }] };
        }
        throw new Error(`Unexpected query: ${sql}`);
      },
      release() {}
    };
    const pool = { async connect() { return client; } };

    const result = await persistPublishedFeedSnapshot(pool, {
      feedId: 7,
      itemCount: 3,
      contentHash: 'abc123',
      content: '1.2.3.4',
      status: 'success',
      paramsJson: { ioc_type: 'ip', window: '1d', filters_hash: 'f1' }
    });

    assert.equal(result.skipped, true);
    assert.ok(!calls.some((c) => c.startsWith('UPDATE published_feed_snapshots')));
  });
});

describe('match-count fingerprint', () => {
  it('returns stable hash for identical aggregate rows', () => {
    const rows = [
      { observable_value: 'a.com', match_count: 2, first_seen_log: '2026-01-01', last_seen_log: '2026-01-02' },
      { observable_value: 'b.com', match_count: 1, first_seen_log: '2026-01-01', last_seen_log: '2026-01-01' }
    ];
    assert.equal(fingerprintAggregateRows(rows), fingerprintAggregateRows([...rows].reverse()));
  });
});
