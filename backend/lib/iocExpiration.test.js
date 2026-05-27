import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateExpirationPolicyInput,
  computePolicyExpiresAt,
  resolveMembershipStatus,
  formatExpirationSummary,
  sourceNameMatchesFeed,
  feedKeyForSourceName
} from './iocExpiration.js';

describe('validateExpirationPolicyInput', () => {
  it('requires ttl_days for last_seen_ttl when enabled', () => {
    const r = validateExpirationPolicyInput({
      enabled: true,
      expiration_mode: 'last_seen_ttl'
    }, 'incremental');
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.includes('ttl_days')));
  });

  it('rejects missing_from_feed_ttl on incremental feeds', () => {
    const r = validateExpirationPolicyInput({
      enabled: true,
      expiration_mode: 'missing_from_feed_ttl',
      grace_days: 7
    }, 'incremental');
    assert.equal(r.ok, false);
  });

  it('accepts valid last_seen policy', () => {
    const r = validateExpirationPolicyInput({
      enabled: true,
      expiration_mode: 'last_seen_ttl',
      ttl_days: 30
    }, 'incremental');
    assert.equal(r.ok, true);
    assert.equal(r.normalized.ttl_days, 30);
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

  it('computes last_seen_ttl from last_seen', () => {
    const at = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'last_seen_ttl', ttl_days: 5 },
      { firstSeenInFeed: base, lastSeenInFeed: last }
    );
    assert.equal(at.toISOString(), '2026-01-25T00:00:00.000Z');
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

  it('formats last_seen summary', () => {
    assert.equal(
      formatExpirationSummary({ enabled: true, expiration_mode: 'last_seen_ttl', ttl_days: 30 }),
      '30d last_seen'
    );
  });
});

describe('source mapping', () => {
  it('maps USOM source to feed key', () => {
    assert.equal(feedKeyForSourceName('USOM:TR-CERT'), 'usom-trcert');
    assert.ok(sourceNameMatchesFeed('EmergingThreats:foo.rules', 'et-blockrules'));
  });
});
