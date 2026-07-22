import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { upsertMembershipOnImport, withImportOptimizationContext } from './iocExpiration.js';
import { computeCustomThreatFeedContentFingerprint } from './customThreatFeedFingerprint.js';

const FEED_ID = '11111111-1111-1111-1111-111111111111';
const FP = computeCustomThreatFeedContentFingerprint({
  observable: 'evil.test',
  observableType: 'domain',
  confidence: 'medium'
});

function baseMembership(overrides = {}) {
  return {
    id: 10,
    ioc_item_id: 99,
    ioc_observable_type: 'domain',
    feed_id: FEED_ID,
    first_seen_in_feed: '2026-07-14T17:41:16.386Z',
    last_seen_in_feed: '2026-07-14T17:41:16.386Z',
    last_changed_in_source: null,
    content_fingerprint: null,
    missing_since: null,
    override_enabled: false,
    status: 'active',
    expired_at: null,
    expiration_reason: null,
    purged_at: null,
    purged_by: null,
    purged_by_username: null,
    purge_reason: null,
    // fixed_ttl 365d from first_seen — keep in sync so adopt/noop does not rewrite policy fields
    policy_expires_at: '2027-07-14T17:41:16.386Z',
    expires_at: '2027-07-14T17:41:16.386Z',
    explicit_confidence: 'medium',
    updated_at: '2026-07-14T17:41:16.386Z',
    ...overrides
  };
}

function makeClient({ membership, onUpdate }) {
  const updates = [];
  const client = {
    updates,
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM threat_feed_expiration_policies') && s.includes('SELECT *')) {
        return {
          rows: [{
            enabled: true,
            expiration_mode: 'fixed_ttl',
            ttl_days: 365,
            feed_id: FEED_ID,
            observable_type: 'all'
          }]
        };
      }
      if (s.includes('FROM ioc_suppressions')) {
        return { rows: [] };
      }
      if (s.includes('FROM ioc_feed_memberships') && s.includes('ioc_item_id')) {
        return membership
          ? { rows: [membership], rowCount: 1 }
          : { rows: [], rowCount: 0 };
      }
      if (s.startsWith('UPDATE ioc_feed_memberships') || s.startsWith('INSERT INTO ioc_feed_memberships')) {
        updates.push({ sql: s, params });
        if (onUpdate) onUpdate(s, params);
        const next = {
          ...membership,
          content_fingerprint: params.includes(FP) ? FP : membership?.content_fingerprint,
          last_seen_in_feed: params[1] instanceof Date ? params[1] : membership?.last_seen_in_feed,
          status: 'active'
        };
        return { rows: [next], rowCount: 1 };
      }
      if (s.includes('FROM ioc_items') && s.includes('manual_status_override')) {
        return {
          rows: [{
            id: 99,
            observable: 'evil.test',
            observable_type: 'domain',
            status: 'active',
            manual_status_override: false,
            expires_at: null,
            expired_at: null,
            expiration_reason: null
          }]
        };
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
  return client;
}

describe('upsertMembershipOnImport content fingerprint (custom feed path)', () => {
  it('adopts NULL fingerprint without bumping updated_at or last_changed_in_source', async () => {
    const membership = baseMembership({ content_fingerprint: null });
    const client = makeClient({ membership });
    const seenAt = new Date('2026-07-22T17:22:49.849Z');

    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: FEED_ID,
      seenAt,
      explicitConfidence: 'medium',
      contentFingerprint: FP
    }));

    assert.equal(result.outcome, 'adopted');
    assert.equal(client.updates.length, 1);
    assert.match(client.updates[0].sql, /SET content_fingerprint = \$2/);
    assert.equal(/updated_at/.test(client.updates[0].sql), false);
    assert.equal(/last_changed_in_source/.test(client.updates[0].sql), false);
    assert.equal(/last_seen_in_feed/.test(client.updates[0].sql), false);
  });

  it('no-ops when fingerprint matches on healthy membership (fixed_ttl)', async () => {
    const membership = baseMembership({ content_fingerprint: FP });
    const client = makeClient({ membership });
    const seenAt = new Date('2026-07-22T17:22:49.849Z');

    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: FEED_ID,
      seenAt,
      explicitConfidence: 'medium',
      contentFingerprint: FP
    }));

    assert.equal(result.outcome, 'unchanged');
    assert.equal(result.touched, false);
    assert.equal(
      client.updates.filter((u) => /last_seen_in_feed/.test(u.sql) || /updated_at/.test(u.sql)).length,
      0
    );
  });

  it('advances last_changed_in_source when fingerprint changes', async () => {
    const oldFp = computeCustomThreatFeedContentFingerprint({
      observable: 'evil.test',
      observableType: 'domain',
      confidence: 'low'
    });
    const membership = baseMembership({ content_fingerprint: oldFp });
    const client = makeClient({ membership });
    const seenAt = new Date('2026-07-22T17:22:49.849Z');

    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: FEED_ID,
      seenAt,
      explicitConfidence: 'medium',
      contentFingerprint: FP
    }));

    assert.equal(result.outcome, 'changed');
    const write = client.updates.find((u) => /last_changed_in_source/.test(u.sql));
    assert.ok(write, 'expected content-change UPDATE');
    assert.match(write.sql, /content_fingerprint = \$3/);
    assert.match(write.sql, /updated_at = NOW\(\)/);
  });

  it('reactivates expired membership and advances last_changed_in_source', async () => {
    const membership = baseMembership({
      content_fingerprint: FP,
      status: 'expired',
      expired_at: '2026-07-01T00:00:00Z',
      expiration_reason: 'policy'
    });
    const client = makeClient({ membership });
    const seenAt = new Date('2026-07-22T17:22:49.849Z');

    const result = await upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: FEED_ID,
      seenAt,
      explicitConfidence: 'medium',
      contentFingerprint: FP
    });

    assert.equal(result.outcome, 'reactivated');
    const write = client.updates.find((u) => /status = 'active'/.test(u.sql));
    assert.ok(write);
    assert.match(write.sql, /last_changed_in_source/);
  });
});
