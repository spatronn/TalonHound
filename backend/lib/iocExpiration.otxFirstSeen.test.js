import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { upsertMembershipOnImport, withImportOptimizationContext } from './iocExpiration.js';

/**
 * Regression coverage for the AlienVault OTX "First seen in source" fix.
 *
 * Bug: OTX imports never threaded the source date (indicator.created / pulse.created)
 * into ioc_feed_memberships.first_seen_in_feed, so it defaulted to the platform import
 * time. The detail API surfaces MIN(first_seen_in_feed) as "First seen in source", so it
 * wrongly showed the import time instead of the real OTX "Added" date.
 *
 * These tests pin the membership-layer contract that the fix relies on:
 *  - explicit firstSeenAt on a NEW membership → first_seen_in_feed = source date
 *  - no firstSeenAt → falls back to seenAt (import time)
 *  - re-import no-op → first_seen_in_feed never rewritten
 *  - LEAST semantics: a newer date never overwrites; a strictly-earlier date lowers it
 */

const FEED_ID = '11111111-1111-1111-1111-111111111111';
const IMPORT_TIME = new Date('2026-07-31T12:00:01.639Z');
const SOURCE_DATE = new Date('2026-07-30T13:03:20.000Z'); // OTX indicator.created

function baseMembership(overrides = {}) {
  return {
    id: 10,
    ioc_item_id: 99,
    ioc_observable_type: 'domain',
    feed_id: FEED_ID,
    first_seen_in_feed: '2026-07-30T13:03:20.000Z',
    last_seen_in_feed: '2026-07-31T12:00:01.639Z',
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
    // fixed_ttl 30d from first_seen — matches OTX domain policy in prod.
    policy_expires_at: '2026-08-29T13:03:20.000Z',
    expires_at: '2026-08-29T13:03:20.000Z',
    explicit_confidence: null,
    updated_at: '2026-07-31T12:00:01.639Z',
    ...overrides
  };
}

/**
 * Mock pg client. `membership` is the existing row (null => none exists).
 * Feed policy is fixed_ttl 30d (first_seen-derived), matching the OTX domain policy.
 */
function makeClient({ membership = null } = {}) {
  const updates = [];
  const client = {
    updates,
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM threat_feed_expiration_policies') && s.includes('SELECT *')) {
        return {
          rows: [{ enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 30, feed_id: FEED_ID, observable_type: 'all' }]
        };
      }
      if (s.includes('FROM ioc_suppressions')) return { rows: [] };
      // Existing-membership lookup (SELECT * ... WHERE ioc_item_id ...).
      if (s.includes('FROM ioc_feed_memberships') && s.includes('ioc_item_id') && s.includes('SELECT *')) {
        return membership ? { rows: [membership], rowCount: 1 } : { rows: [], rowCount: 0 };
      }
      // first_seen_in_feed LEAST lowering.
      if (s.startsWith('UPDATE ioc_feed_memberships') && /SET first_seen_in_feed = \$2/.test(s) && /first_seen_in_feed > \$2/.test(s)) {
        updates.push({ sql: s, params });
        const incoming = params[1];
        const stored = membership ? new Date(membership.first_seen_in_feed) : null;
        const lower = stored && incoming instanceof Date && incoming.getTime() < stored.getTime();
        if (lower) {
          const next = { ...membership, first_seen_in_feed: incoming };
          return { rows: [next], rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      }
      if (s.startsWith('INSERT INTO ioc_feed_memberships')) {
        updates.push({ sql: s, params });
        // Non-fp insert: (iocItemId, observableType, feedId, firstNow, now)
        const next = baseMembership({
          id: 10,
          first_seen_in_feed: params[3],
          last_seen_in_feed: params[4]
        });
        return { rows: [next], rowCount: 1 };
      }
      if (s.startsWith('UPDATE ioc_feed_memberships')) {
        updates.push({ sql: s, params });
        return { rows: [{ ...(membership || baseMembership()) }], rowCount: 1 };
      }
      // recomputeIocGlobalStatus support queries (only hit outside import context).
      if (s.includes('FROM ioc_items') && s.includes('manual_status_override')) {
        return { rows: [{ id: 99, observable: 'evil.test', observable_type: 'domain', status: 'active', manual_status_override: false, expires_at: null, expired_at: null, expiration_reason: null }] };
      }
      if (s.includes('FROM ioc_feed_memberships m') && s.includes('INNER JOIN ioc_items')) {
        return { rows: [{ status: 'active', purged_at: null }] };
      }
      if (s.includes('MIN(m.expires_at)')) return { rows: [{ min_exp: null }] };
      return { rows: [], rowCount: 0 };
    }
  };
  return client;
}

describe('upsertMembershipOnImport — OTX first_seen_in_feed source date', () => {
  it('writes the source date into first_seen_in_feed on a NEW membership', async () => {
    const client = makeClient({ membership: null });
    await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: FEED_ID,
      seenAt: IMPORT_TIME,
      firstSeenAt: SOURCE_DATE
    }));
    const insert = client.updates.find((u) => u.sql.startsWith('INSERT INTO ioc_feed_memberships'));
    assert.ok(insert, 'expected a membership INSERT');
    // params: [iocItemId, observableType, feedId, firstNow(=source date), now(=import time)]
    assert.equal(insert.params[3].getTime(), SOURCE_DATE.getTime(), 'first_seen_in_feed = OTX source date');
    assert.equal(insert.params[4].getTime(), IMPORT_TIME.getTime(), 'last_seen_in_feed = import time');
  });

  it('falls back to import time when no source date is supplied (null firstSeenAt)', async () => {
    const client = makeClient({ membership: null });
    await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: FEED_ID,
      seenAt: IMPORT_TIME,
      firstSeenAt: null
    }));
    const insert = client.updates.find((u) => u.sql.startsWith('INSERT INTO ioc_feed_memberships'));
    assert.equal(insert.params[3].getTime(), IMPORT_TIME.getTime(), 'first_seen_in_feed falls back to import time');
  });

  it('re-import no-op does NOT rewrite first_seen_in_feed (reactivateOnly, healthy)', async () => {
    const membership = baseMembership(); // first_seen already the source date
    const client = makeClient({ membership });
    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: FEED_ID,
      seenAt: new Date('2026-08-01T12:00:00.000Z'),
      firstSeenAt: SOURCE_DATE, // same date re-supplied
      reactivateOnly: true
    }));
    assert.equal(result.outcome, 'unchanged');
    assert.equal(result.touched, false);
    assert.equal(client.updates.length, 0, 'no membership writes on no-op');
  });

  it('a NEWER incoming source date never overwrites an existing earlier first_seen (LEAST)', async () => {
    const membership = baseMembership(); // first_seen = 2026-07-30
    const client = makeClient({ membership });
    const newer = new Date('2026-07-31T00:00:00.000Z');
    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: FEED_ID,
      seenAt: new Date('2026-08-01T12:00:00.000Z'),
      firstSeenAt: newer,
      reactivateOnly: true
    }));
    assert.equal(result.outcome, 'unchanged');
    assert.equal(result.touched, false);
    // No lowering UPDATE issued at all (JS guard short-circuits before querying).
    assert.equal(client.updates.filter((u) => /SET first_seen_in_feed = \$2/.test(u.sql)).length, 0);
  });

  it('a strictly-EARLIER source date lowers first_seen_in_feed even on the healthy no-op path (LEAST correction)', async () => {
    // Simulates the reported bug: membership already stored the import time; a real,
    // earlier source date arrives and must correct it.
    const membership = baseMembership({
      first_seen_in_feed: '2026-07-31T12:00:01.639Z', // wrong: import time
      policy_expires_at: '2026-08-30T12:00:01.639Z',
      expires_at: '2026-08-30T12:00:01.639Z'
    });
    const client = makeClient({ membership });
    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: FEED_ID,
      seenAt: new Date('2026-08-01T12:00:00.000Z'),
      firstSeenAt: SOURCE_DATE, // 2026-07-30, earlier than stored import time
      reactivateOnly: true
    }));
    assert.equal(result.outcome, 'changed');
    assert.equal(result.touched, true);
    const lower = client.updates.find((u) => /SET first_seen_in_feed = \$2/.test(u.sql));
    assert.ok(lower, 'expected a LEAST lowering UPDATE');
    assert.equal(lower.params[1].getTime(), SOURCE_DATE.getTime());
    assert.match(lower.sql, /first_seen_in_feed > \$2/, 'guarded so it never raises first_seen');
  });
});
