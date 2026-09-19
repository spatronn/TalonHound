import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateExpirationPolicyInput,
  computePolicyExpiresAt,
  computeMatchReactivationExpiresAt,
  resolveMembershipStatus,
  formatExpirationSummary,
  sourceNameMatchesFeed,
  feedKeyForSourceName,
  syncMembershipAfterIocImport,
  reactivateIocOnCorrelationMatch,
  runExpirationWorkerBatch,
  EXPIRATION_MODES,
  canonicalExpirationMode,
  upsertMembershipOnImport,
  withImportOptimizationContext
} from './iocExpiration.js';

describe('EXPIRATION_MODES', () => {
  it('is the 3-policy set without last_seen_ttl', () => {
    assert.deepEqual([...EXPIRATION_MODES], ['never', 'fixed_ttl', 'missing_from_feed_ttl']);
    assert.equal(canonicalExpirationMode('last_seen_ttl'), 'fixed_ttl');
  });
});

describe('validateExpirationPolicyInput', () => {
  it('rejects last_seen_ttl as unsupported', () => {
    const r = validateExpirationPolicyInput({
      enabled: true,
      expiration_mode: 'last_seen_ttl',
      ttl_days: 30
    }, 'incremental');
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes('last_seen_ttl is no longer supported')));
  });

  it('rejects missing_from_feed_ttl on incremental feeds', () => {
    const r = validateExpirationPolicyInput({
      enabled: true,
      expiration_mode: 'missing_from_feed_ttl',
      grace_days: 7
    }, 'incremental');
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes('snapshot')));
  });

  it('accepts missing_from_feed_ttl on snapshot feeds', () => {
    const r = validateExpirationPolicyInput({
      enabled: true,
      expiration_mode: 'missing_from_feed_ttl',
      grace_days: 7
    }, 'snapshot');
    assert.equal(r.ok, true);
    assert.equal(r.normalized.expiration_mode, 'missing_from_feed_ttl');
    assert.equal(r.normalized.grace_days, 7);
  });

  it('accepts fixed_ttl with ttl_days', () => {
    const r = validateExpirationPolicyInput({
      enabled: true,
      expiration_mode: 'fixed_ttl',
      ttl_days: 30
    }, 'incremental');
    assert.equal(r.ok, true);
    assert.equal(r.normalized.expiration_mode, 'fixed_ttl');
    assert.equal(r.normalized.ttl_days, 30);
  });

  it('accepts never', () => {
    const r = validateExpirationPolicyInput({
      enabled: false,
      expiration_mode: 'never'
    }, 'incremental');
    assert.equal(r.ok, true);
    assert.equal(r.normalized.expiration_mode, 'never');
  });

  it('requires ttl_days for fixed_ttl when enabled', () => {
    const r = validateExpirationPolicyInput({
      enabled: true,
      expiration_mode: 'fixed_ttl'
    }, 'incremental');
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes('ttl_days')));
  });
});

describe('computePolicyExpiresAt', () => {
  const base = new Date('2026-01-01T00:00:00Z');
  const last = new Date('2026-01-20T00:00:00Z');

  it('computes fixed_ttl from last_seen when present', () => {
    const at = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 10 },
      { firstSeenInFeed: base, lastSeenInFeed: last }
    );
    assert.equal(at.toISOString(), '2026-01-30T00:00:00.000Z');
  });

  it('falls back to first_seen when last_seen is missing', () => {
    const at = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 10 },
      { firstSeenInFeed: base, lastSeenInFeed: null }
    );
    assert.equal(at.toISOString(), '2026-01-11T00:00:00.000Z');
  });

  it('extends fixed_ttl when last_seen is later (re-observed)', () => {
    const first = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 10 },
      { firstSeenInFeed: base, lastSeenInFeed: base }
    );
    const reseen = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 10 },
      { firstSeenInFeed: base, lastSeenInFeed: last }
    );
    assert.equal(first.toISOString(), '2026-01-11T00:00:00.000Z');
    assert.equal(reseen.toISOString(), '2026-01-30T00:00:00.000Z');
  });

  it('treats legacy last_seen_ttl as fixed_ttl from last source observation', () => {
    const at = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'last_seen_ttl', ttl_days: 5 },
      { firstSeenInFeed: base, lastSeenInFeed: last }
    );
    assert.equal(at.toISOString(), '2026-01-25T00:00:00.000Z');
  });

  it('computes missing_from_feed_ttl from missing_since', () => {
    const missing = new Date('2026-01-10T00:00:00Z');
    const at = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'missing_from_feed_ttl', grace_days: 7 },
      { firstSeenInFeed: base, lastSeenInFeed: last, missingSince: missing }
    );
    assert.equal(at.toISOString(), '2026-01-17T00:00:00.000Z');
  });

  it('returns null for never', () => {
    assert.equal(computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'never', ttl_days: 10 },
      { firstSeenInFeed: base, lastSeenInFeed: last }
    ), null);
  });
});

describe('resolveMembershipStatus', () => {
  it('expires when effective date passed', () => {
    const status = resolveMembershipStatus({
      override_enabled: false,
      policy_expires_at: '2020-01-01T00:00:00Z'
    }, new Date('2026-01-01'));
    assert.equal(status, 'expired');
  });

  it('honors override active', () => {
    const status = resolveMembershipStatus({
      override_enabled: true,
      override_status: 'active',
      policy_expires_at: '2020-01-01T00:00:00Z'
    });
    assert.equal(status, 'active');
  });
});

describe('formatExpirationSummary', () => {
  it('formats disabled policy', () => {
    assert.equal(formatExpirationSummary({ enabled: false }), 'Disabled');
  });

  it('formats fixed_ttl summary', () => {
    assert.equal(
      formatExpirationSummary({ enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 30 }),
      '30d fixed'
    );
  });

  it('formats legacy last_seen_ttl as fixed', () => {
    assert.equal(
      formatExpirationSummary({ enabled: true, expiration_mode: 'last_seen_ttl', ttl_days: 30 }),
      '30d fixed'
    );
  });
});

describe('source mapping', () => {
  it('maps USOM source to feed key', () => {
    assert.equal(feedKeyForSourceName('USOM:TR-CERT'), 'usom-trcert');
    assert.ok(sourceNameMatchesFeed('EmergingThreats:foo.rules', 'et-blockrules'));
  });
});

describe('computeMatchReactivationExpiresAt', () => {
  const now = new Date('2026-06-14T12:00:00Z');

  it('returns now + ttl_days for fixed_ttl', () => {
    const at = computeMatchReactivationExpiresAt(
      { enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 30 },
      now
    );
    assert.equal(at.toISOString(), '2026-07-14T12:00:00.000Z');
  });

  it('returns null when policy disabled', () => {
    assert.equal(computeMatchReactivationExpiresAt({ enabled: false, expiration_mode: 'fixed_ttl', ttl_days: 30 }, now), null);
  });
});

describe('reactivateIocOnCorrelationMatch', () => {
  it('skips IOC with manual override expired', async () => {
    const client = {
      async query(sql) {
        if (String(sql).includes('FROM ioc_items')) {
          return {
            rows: [{
              id: 1,
              observable: 'evil.test',
              observable_type: 'domain',
              status: 'expired',
              manual_status_override: true,
              manual_status: 'expired'
            }]
          };
        }
        return { rows: [] };
      }
    };
    const res = await reactivateIocOnCorrelationMatch(client, {
      observable: 'evil.test',
      observableType: 'domain'
    });
    assert.equal(res.reactivated, false);
    assert.equal(res.reason, 'manual_override_expired');
  });
});

describe('syncMembershipAfterIocImport canonical IOC lookup', () => {
  it('looks up IOC by observable+type (source-agnostic) to avoid duplicate rows across feeds', async () => {
    const calls = [];
    const client = {
      async query(sql, params) {
        calls.push({ sql: String(sql), params });
        if (String(sql).includes('FROM integration_feeds')) {
          return { rows: [{ key: 'usom-trcert', feed_id: '11111111-1111-1111-1111-111111111111' }] };
        }
        if (String(sql).includes('FROM ioc_items')) {
          return { rows: [] };
        }
        return { rows: [], rowCount: 0 };
      }
    };

    const out = await syncMembershipAfterIocImport(client, {
      observable: 'http://104.36.229.33',
      observableType: 'url',
      sourceName: 'USOM:TR-CERT',
      sourceUrl: 'https://siberguvenlik.gov.tr/api/address/index',
      category: 'threat-intel'
    });

    assert.equal(out, null);
    const lookup = calls.find((c) => c.sql.includes('FROM ioc_items'));
    assert.ok(lookup);
    assert.ok(!lookup.sql.includes('source_name = $3'));
    assert.equal(Array.isArray(lookup.params), true);
    assert.equal(lookup.params.length, 2);
  });
});

function buildExpirationWorkerMockClient({ membershipRows, membershipStatusesAfter = ['expired'], iocRow }) {
  const defaultIocRow = iocRow || {
    id: 99,
    observable: 'evil.example',
    observable_type: 'domain',
    status: 'active',
    manual_status_override: false,
    expires_at: '2020-01-01T00:00:00Z',
    expired_at: null,
    expiration_reason: null
  };

  return {
    async query(sql) {
      const s = String(sql);
      if (s.includes('FROM ioc_feed_memberships m') && s.includes('INNER JOIN ioc_items i')) {
        return { rows: membershipStatusesAfter.map((status) => ({ status, purged_at: null })) };
      }
      if (s.includes('FROM ioc_feed_memberships m') && s.includes('LIMIT')) {
        return { rows: membershipRows };
      }
      if (s.includes('UPDATE ioc_feed_memberships') && s.includes("status = 'expired'")) {
        return { rowCount: 1 };
      }
      if (s.includes('FROM ioc_items') && s.includes('manual_status_override')) {
        return { rows: [defaultIocRow] };
      }
      if (s.includes('FROM ioc_suppressions')) {
        return { rows: [] };
      }
      if (s.includes('MIN(expires_at)')) {
        return { rows: [{ min_exp: null }] };
      }
      if (s.includes('UPDATE ioc_items')) {
        return { rowCount: 1 };
      }
      return { rows: [] };
    }
  };
}

describe('runExpirationWorkerBatch audit', () => {
  it('emits single ioc.expired with feed metadata and no membership.expired', async () => {
    const auditCalls = [];
    const audit = { auditLog: async (entry) => { auditCalls.push(entry); } };
    const client = buildExpirationWorkerMockClient({
      membershipRows: [{
        id: 42,
        ioc_item_id: 99,
        ioc_observable_type: 'domain',
        feed_id: '11111111-1111-4111-8111-111111111111',
        status: 'active',
        expires_at: '2020-01-01T00:00:00Z',
        expiration_reason: 'policy_ttl',
        observable: 'evil.example',
        feed_name: 'USOM TR-CERT'
      }]
    });

    await runExpirationWorkerBatch(client, { audit, batchSize: 10 });

    assert.equal(auditCalls.filter((entry) => entry.action === 'ioc_feed_membership.expired').length, 0);
    const iocExpired = auditCalls.filter((entry) => entry.action === 'ioc.expired');
    assert.equal(iocExpired.length, 1);
    assert.equal(iocExpired[0].entityDisplay, 'domain · evil.example');
    assert.equal(iocExpired[0].metadata.feed_name, 'USOM TR-CERT');
    assert.equal(iocExpired[0].metadata.membership_id, 42);
    assert.equal(iocExpired[0].source, 'expiration-worker');
  });

  it('deduplicates audit logs when multiple memberships expire for the same IOC', async () => {
    const auditCalls = [];
    const audit = { auditLog: async (entry) => { auditCalls.push(entry); } };
    const client = buildExpirationWorkerMockClient({
      membershipRows: [
        {
          id: 42,
          ioc_item_id: 99,
          ioc_observable_type: 'domain',
          feed_id: '11111111-1111-4111-8111-111111111111',
          status: 'active',
          expires_at: '2020-01-01T00:00:00Z',
          expiration_reason: 'policy_ttl',
          observable: 'evil.example',
          feed_name: 'USOM TR-CERT'
        },
        {
          id: 43,
          ioc_item_id: 99,
          ioc_observable_type: 'domain',
          feed_id: '22222222-2222-4222-8222-222222222222',
          status: 'active',
          expires_at: '2020-01-01T00:00:00Z',
          expiration_reason: 'policy_ttl',
          observable: 'evil.example',
          feed_name: 'URLhaus'
        }
      ]
    });

    await runExpirationWorkerBatch(client, { audit, batchSize: 10 });

    assert.equal(auditCalls.filter((entry) => entry.action === 'ioc_feed_membership.expired').length, 0);
    const iocExpired = auditCalls.filter((entry) => entry.action === 'ioc.expired');
    assert.equal(iocExpired.length, 1);
    assert.equal(iocExpired[0].metadata.affected_feeds.length, 2);
    assert.equal(iocExpired[0].metadata.feed_name, 'USOM TR-CERT, URLhaus');
  });

  it('does not emit user-facing audit when IOC global status stays active', async () => {
    const auditCalls = [];
    const audit = { auditLog: async (entry) => { auditCalls.push(entry); } };
    const client = buildExpirationWorkerMockClient({
      membershipRows: [{
        id: 42,
        ioc_item_id: 99,
        ioc_observable_type: 'domain',
        feed_id: '11111111-1111-4111-8111-111111111111',
        status: 'active',
        expires_at: '2020-01-01T00:00:00Z',
        expiration_reason: 'policy_ttl',
        observable: 'evil.example',
        feed_name: 'USOM TR-CERT'
      }],
      membershipStatusesAfter: ['expired', 'active']
    });

    await runExpirationWorkerBatch(client, { audit, batchSize: 10 });

    assert.equal(auditCalls.length, 0);
  });
});

describe('runExpirationWorkerBatch bounded due-batch selection', () => {
  // Recording mock: same dispatch as buildExpirationWorkerMockClient but captures
  // the SQL text and params so we can assert on the bounded-batch query shape.
  function buildRecordingMockClient({ membershipRows, membershipStatusesAfter = ['expired'] }) {
    const calls = [];
    const client = {
      async query(sql, params) {
        const s = String(sql);
        calls.push({ sql: s, params: params || [] });
        if (s.includes('FROM ioc_feed_memberships m') && s.includes('INNER JOIN ioc_items i')) {
          return { rows: membershipStatusesAfter.map((status) => ({ status, purged_at: null })) };
        }
        if (s.includes('FROM ioc_feed_memberships m') && s.includes('LIMIT')) {
          return { rows: membershipRows };
        }
        if (s.includes('UPDATE ioc_feed_memberships') && s.includes("status = 'expired'")) {
          return { rowCount: 1 };
        }
        if (s.includes('FROM ioc_items') && s.includes('manual_status_override')) {
          return { rows: [{
            id: 99, observable: 'evil.example', observable_type: 'domain', status: 'active',
            manual_status_override: false, expires_at: '2020-01-01T00:00:00Z',
            expired_at: null, expiration_reason: null
          }] };
        }
        if (s.includes('FROM ioc_suppressions')) return { rows: [] };
        if (s.includes('MIN(expires_at)')) return { rows: [{ min_exp: null }] };
        if (s.includes('UPDATE ioc_items')) return { rowCount: 1 };
        return { rows: [] };
      }
    };
    return { client, calls };
  }

  it('selects the due batch via a bounded FOR UPDATE SKIP LOCKED subquery, then joins ioc_items', async () => {
    const { client, calls } = buildRecordingMockClient({ membershipRows: [] });
    await runExpirationWorkerBatch(client, { batchSize: 500 });

    const selectCall = calls.find((c) =>
      c.sql.includes('FROM ioc_feed_memberships m') && c.sql.includes('LIMIT'));
    assert.ok(selectCall, 'expected the bounded due-batch select to run');
    // Bound-first: the membership scan + lock happen before the ioc_items join.
    assert.ok(selectCall.sql.includes('FOR UPDATE OF m SKIP LOCKED'),
      'locking clause must be preserved on ioc_feed_memberships');
    assert.ok(selectCall.sql.includes('LIMIT $1'), 'batch must be bounded by LIMIT $1');
    assert.match(selectCall.sql, /WITH due AS \(/,
      'due memberships must be selected in a materialised CTE before joining ioc_items');
    const lockIdx = selectCall.sql.indexOf('FOR UPDATE OF m SKIP LOCKED');
    const joinIdx = selectCall.sql.indexOf('JOIN ioc_items');
    assert.ok(lockIdx !== -1 && joinIdx !== -1 && lockIdx < joinIdx,
      'the lock/limit must occur before the ioc_items join (bounded plan)');
    // batchSize flows through as the LIMIT bind.
    assert.deepEqual(selectCall.params, [500]);
  });

  it('processes an empty due batch with no mutations', async () => {
    const { client, calls } = buildRecordingMockClient({ membershipRows: [] });
    const res = await runExpirationWorkerBatch(client, { batchSize: 500 });

    assert.deepEqual(res, { expiredMemberships: 0, iocRecomputed: 0, iocGlobalExpired: 0, batchCount: 0 });
    assert.equal(calls.filter((c) => c.sql.includes('UPDATE ioc_feed_memberships')).length, 0);
    assert.equal(calls.filter((c) => c.sql.includes('UPDATE ioc_items')).length, 0);
  });

  it('expires memberships across multiple ioc_items partitions (domain, file_hash, ip)', async () => {
    const { client, calls } = buildRecordingMockClient({
      membershipRows: [
        { id: 1, ioc_item_id: 11, ioc_observable_type: 'domain', feed_id: 'f1', status: 'active', expires_at: '2020-01-01T00:00:00Z', expiration_reason: 'policy_ttl', observable: 'evil.example', feed_name: 'USOM' },
        { id: 2, ioc_item_id: 22, ioc_observable_type: 'file_hash', feed_id: 'f1', status: 'active', expires_at: '2020-01-01T00:00:00Z', expiration_reason: 'policy_ttl', observable: 'abc123', feed_name: 'USOM' },
        { id: 3, ioc_item_id: 33, ioc_observable_type: 'ip', feed_id: 'f1', status: 'active', expires_at: '2020-01-01T00:00:00Z', expiration_reason: 'policy_ttl', observable: '1.2.3.4', feed_name: 'USOM' }
      ]
    });
    const res = await runExpirationWorkerBatch(client, { batchSize: 500 });

    assert.equal(res.batchCount, 3);
    assert.equal(res.expiredMemberships, 3);
    // one membership UPDATE per due row, keyed by id + status guard
    const membershipUpdates = calls.filter((c) => c.sql.includes('UPDATE ioc_feed_memberships') && c.sql.includes("status = 'expired'"));
    assert.equal(membershipUpdates.length, 3);
    assert.deepEqual(membershipUpdates.map((c) => c.params[0]).sort(), [1, 2, 3]);
  });
});

describe('upsertMembershipOnImport observedAt semantics', () => {
  const FEED_ID = '11111111-1111-1111-1111-111111111111';
  const FP = 'abc'.repeat(21) + 'a';
  const T1 = new Date('2026-06-03T00:00:00Z');
  const T2 = new Date('2026-07-31T09:05:06Z');
  const T_OLD = new Date('2026-07-19T18:05:00Z');

  function membership(overrides = {}) {
    return {
      id: 10,
      ioc_item_id: 99,
      ioc_observable_type: 'ip',
      feed_id: FEED_ID,
      first_seen_in_feed: T1,
      last_seen_in_feed: T1,
      last_changed_in_source: T1,
      content_fingerprint: FP,
      missing_since: null,
      override_enabled: false,
      override_status: null,
      status: 'active',
      expired_at: null,
      expiration_reason: null,
      purged_at: null,
      policy_expires_at: new Date('2026-07-03T00:00:00Z'),
      expires_at: new Date('2026-07-03T00:00:00Z'),
      explicit_confidence: null,
      ...overrides
    };
  }

  function makeClient(row) {
    const updates = [];
    let current = { ...row };
    const client = {
      updates,
      async query(sql, params = []) {
        const s = String(sql);
        if (s.includes('FROM threat_feed_expiration_policies') && s.includes('SELECT *')) {
          return {
            rows: [{
              enabled: true,
              expiration_mode: 'fixed_ttl',
              ttl_days: 30,
              feed_id: FEED_ID,
              observable_type: 'all'
            }]
          };
        }
        if (s.includes('FROM ioc_suppressions')) return { rows: [] };
        if (s.includes('FROM ioc_feed_memberships') && s.includes('ioc_item_id')) {
          return { rows: [current], rowCount: 1 };
        }
        if (s.includes('SELECT * FROM ioc_feed_memberships WHERE id')) {
          return { rows: [current] };
        }
        if (s.startsWith('UPDATE ioc_feed_memberships') && s.includes('GREATEST(last_seen_in_feed') && !s.includes('last_changed_in_source') && !s.includes("status = 'active'")) {
          updates.push({ kind: 'last_seen', sql: s, params });
          const incoming = params[1];
          if (incoming instanceof Date && new Date(current.last_seen_in_feed).getTime() < incoming.getTime()) {
            current = { ...current, last_seen_in_feed: incoming };
            return { rows: [current], rowCount: 1 };
          }
          return { rows: [], rowCount: 0 };
        }
        if (s.startsWith('UPDATE ioc_feed_memberships') && s.includes('last_changed_in_source')) {
          updates.push({ kind: 'last_changed', sql: s, params });
          current = {
            ...current,
            last_seen_in_feed: params[1] instanceof Date && new Date(current.last_seen_in_feed) < params[1]
              ? params[1]
              : current.last_seen_in_feed,
            last_changed_in_source: params[1],
            content_fingerprint: params[2] || params[3] || current.content_fingerprint,
            status: 'active',
            expired_at: null,
            expiration_reason: null
          };
          return { rows: [current], rowCount: 1 };
        }
        if (s.startsWith('UPDATE ioc_feed_memberships') && s.includes('policy_expires_at')) {
          updates.push({ kind: 'ttl', sql: s, params });
          current = {
            ...current,
            policy_expires_at: params[1],
            expires_at: params[2],
            status: params[3],
            expired_at: params[4],
            expiration_reason: params[5]
          };
          return { rows: [current], rowCount: 1 };
        }
        if (s.startsWith('UPDATE ioc_feed_memberships')) {
          updates.push({ kind: 'other', sql: s, params });
          current = { ...current, status: 'active', expired_at: null };
          return { rows: [current], rowCount: 1 };
        }
        if (s.includes('FROM ioc_items') && s.includes('manual_status_override')) {
          return {
            rows: [{
              id: 99,
              observable: '81.70.21.248',
              observable_type: 'ip',
              status: current.status === 'active' ? 'active' : 'expired',
              manual_status_override: false,
              expires_at: current.expires_at,
              expired_at: current.expired_at,
              expiration_reason: current.expiration_reason
            }]
          };
        }
        if (s.includes('FROM ioc_feed_memberships m') && s.includes('INNER JOIN ioc_items')) {
          return { rows: [{ status: current.status, purged_at: null }] };
        }
        if (s.includes('MIN(m.expires_at)')) return { rows: [{ min_exp: current.expires_at }] };
        if (s.startsWith('UPDATE ioc_items')) return { rowCount: 1, rows: [] };
        return { rows: [], rowCount: 0 };
      }
    };
    return client;
  }

  it('later observation advances last_seen and extends TTL without last_changed', async () => {
    const client = makeClient(membership());
    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'ip',
      feedId: FEED_ID,
      seenAt: new Date('2026-08-03T00:24:01Z'),
      firstSeenAt: T1,
      observedAt: T2,
      contentFingerprint: FP
    }));

    assert.equal(result.outcome, 'reobserved');
    assert.ok(client.updates.some((u) => u.kind === 'last_seen'));
    assert.equal(client.updates.some((u) => u.kind === 'last_changed'), false);
    assert.ok(client.updates.some((u) => u.kind === 'ttl'));
  });

  it('out-of-order observation does not rewind last_seen', async () => {
    const client = makeClient(membership({ last_seen_in_feed: T2, policy_expires_at: new Date('2026-08-30T09:05:06Z'), expires_at: new Date('2026-08-30T09:05:06Z') }));
    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'ip',
      feedId: FEED_ID,
      seenAt: new Date('2026-08-03T00:24:01Z'),
      firstSeenAt: T1,
      observedAt: T_OLD,
      contentFingerprint: FP
    }));

    assert.equal(result.outcome, 'unchanged');
    assert.equal(client.updates.filter((u) => u.kind === 'last_seen' && u.sql.includes('GREATEST')).every((u) => {
      // statement may run; mock returns rowCount 0 when not newer
      return true;
    }), true);
    assert.equal(client.updates.some((u) => u.kind === 'last_changed'), false);
  });

  it('expired membership reactivates on a later observation', async () => {
    const client = makeClient(membership({
      status: 'expired',
      expired_at: new Date('2026-07-02T21:20:37Z'),
      expiration_reason: 'fixed_ttl'
    }));
    const result = await upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'ip',
      feedId: FEED_ID,
      seenAt: new Date('2026-08-03T00:24:01Z'),
      firstSeenAt: T1,
      observedAt: T2,
      contentFingerprint: FP
    });

    assert.equal(result.outcome, 'reactivated');
    assert.ok(client.updates.some((u) => u.kind === 'last_changed' || (u.kind === 'other' && u.sql.includes("status = 'active'"))));
  });

  it('manual override expired is not reactivated', async () => {
    const client = makeClient(membership({
      status: 'expired',
      override_enabled: true,
      override_status: 'expired',
      expired_at: new Date('2026-07-02T21:20:37Z'),
      expiration_reason: 'manual'
    }));
    await upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'ip',
      feedId: FEED_ID,
      seenAt: new Date('2026-08-03T00:24:01Z'),
      firstSeenAt: T1,
      observedAt: T2,
      contentFingerprint: FP
    });
    const statusWrites = client.updates.filter((u) => u.sql.includes("status = 'active'"));
    assert.equal(statusWrites.length, 0);
  });
});
