import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatIocEntityDisplay,
  formatMembershipEntityDisplay,
  normalizeExpirationAuditReason,
  buildIocExpirationAuditPayload,
  buildMembershipExpirationAuditPayload
} from './auditIocContext.js';

describe('formatIocEntityDisplay', () => {
  it('combines type and value', () => {
    assert.equal(formatIocEntityDisplay('domain', 'evil.example'), 'domain · evil.example');
  });
});

describe('normalizeExpirationAuditReason', () => {
  it('maps policy_ttl to expires_at_reached', () => {
    assert.equal(normalizeExpirationAuditReason('policy_ttl'), 'expires_at_reached');
  });

  it('preserves explicit reasons', () => {
    assert.equal(normalizeExpirationAuditReason('all_feed_memberships_expired'), 'all_feed_memberships_expired');
  });
});

describe('buildIocExpirationAuditPayload', () => {
  it('includes analyst-friendly metadata', () => {
    const payload = buildIocExpirationAuditPayload({
      iocId: 2081878,
      observable: 'example-malicious-domain.com',
      observableType: 'domain',
      oldStatus: 'active',
      newStatus: 'expired',
      oldExpiresAt: '2026-05-28T10:04:52.762Z',
      expiredAt: '2026-05-28T10:05:08.313Z',
      reason: 'all_feed_memberships_expired',
      actor: { actor_type: 'system', source: 'expiration-worker' }
    });

    assert.equal(payload.entityDisplay, 'domain · example-malicious-domain.com');
    assert.equal(payload.metadata.ioc_id, 2081878);
    assert.equal(payload.metadata.ioc_value, 'example-malicious-domain.com');
    assert.equal(payload.metadata.old_status, 'active');
    assert.equal(payload.metadata.new_status, 'expired');
    assert.equal(payload.metadata.source, 'expiration-worker');
  });
});

describe('buildMembershipExpirationAuditPayload', () => {
  it('includes feed context in display and metadata', () => {
    const payload = buildMembershipExpirationAuditPayload({
      membershipId: 42,
      iocId: 99,
      observable: 'bad.url',
      observableType: 'url',
      feedId: '11111111-1111-4111-8111-111111111111',
      feedName: 'URLhaus',
      oldExpiresAt: '2026-05-28T10:04:52.762Z',
      expiredAt: '2026-05-28T10:05:08.313Z',
      reason: 'policy_ttl'
    });

    assert.equal(payload.entityDisplay, 'url · bad.url · URLhaus');
    assert.equal(payload.metadata.membership_id, 42);
    assert.equal(payload.metadata.feed_name, 'URLhaus');
    assert.equal(payload.metadata.reason, 'expires_at_reached');
  });
});

describe('formatMembershipEntityDisplay', () => {
  it('falls back to membership id', () => {
    assert.equal(formatMembershipEntityDisplay({ membershipId: 7 }), 'membership 7');
  });
});
