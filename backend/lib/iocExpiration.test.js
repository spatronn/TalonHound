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
  canonicalExpirationMode
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

  it('computes fixed_ttl from first_seen', () => {
    const at = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 10 },
      { firstSeenInFeed: base, lastSeenInFeed: last }
    );
    assert.equal(at.toISOString(), '2026-01-11T00:00:00.000Z');
  });

  it('does not reset fixed_ttl when last_seen is later (re-seen)', () => {
    const first = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 10 },
      { firstSeenInFeed: base, lastSeenInFeed: base }
    );
    const reseen = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 10 },
      { firstSeenInFeed: base, lastSeenInFeed: last }
    );
    assert.equal(first.toISOString(), '2026-01-11T00:00:00.000Z');
    assert.equal(reseen.toISOString(), first.toISOString());
  });

  it('treats legacy last_seen_ttl as fixed_ttl (first_seen, not last_seen)', () => {
    const at = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'last_seen_ttl', ttl_days: 5 },
      { firstSeenInFeed: base, lastSeenInFeed: last }
    );
    assert.equal(at.toISOString(), '2026-01-06T00:00:00.000Z');
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
