import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  computePolicyExpiresAt,
  upsertMembershipOnImport,
  withImportOptimizationContext
} from './iocExpiration.js';

/**
 * Mirrors migration 025 ThreatFox observation extraction:
 * only ThreatFox-sourced rows contribute; note last_seen/first_seen preferred.
 */
function extractThreatFoxObservation(items) {
  const rows = items.filter((i) => String(i.source_name || '').startsWith('ThreatFox:'));
  let observedAt = null;
  let firstObservedAt = null;
  for (const tf of rows) {
    const note = String(tf.note || '');
    const noteLast = note.match(/last_seen=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z?)/i)?.[1];
    const noteFirst = note.match(/first_seen=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z?)/i)?.[1];
    const obs = noteLast || noteFirst || tf.last_seen_at || null;
    const first = noteFirst || tf.first_seen_at || null;
    if (obs) {
      const t = new Date(obs);
      if (!observedAt || t > observedAt) observedAt = t;
    }
    if (first) {
      const t = new Date(first);
      if (!firstObservedAt || t < firstObservedAt) firstObservedAt = t;
    }
  }
  return { observedAt, firstObservedAt };
}

function applyThreatFoxMembershipBackfill(membership, items) {
  const { observedAt, firstObservedAt } = extractThreatFoxObservation(items);
  if (!observedAt) return { ...membership, touched: false };
  const next = { ...membership };
  if (firstObservedAt && new Date(next.first_seen_in_feed) > firstObservedAt) {
    next.first_seen_in_feed = firstObservedAt;
  }
  next.last_seen_in_feed = observedAt;
  next.touched = true;
  return next;
}

describe('migration 025 ThreatFox backfill source isolation', () => {
  const T1 = new Date('2026-07-31T09:05:06.000Z');
  const T2 = new Date('2026-09-10T12:00:00.000Z');
  const T0 = new Date('2026-06-03T00:00:00.000Z');

  it('does not attribute a later OTX item last_seen to ThreatFox membership', () => {
    const membership = {
      feed_key: 'threatfox-abusech',
      first_seen_in_feed: T0,
      last_seen_in_feed: T0,
      last_changed_in_source: null
    };
    const items = [
      {
        source_name: 'ThreatFox:abuse.ch',
        first_seen_at: T0,
        last_seen_at: T1,
        note: 'Auto-imported from ThreatFox API | ioc_id=1865994 | first_seen=2026-07-31T09:05:06.000Z'
      },
      {
        source_name: 'AlienVault OTX',
        first_seen_at: T2,
        last_seen_at: T2,
        note: 'OTX pulse'
      }
    ];

    const next = applyThreatFoxMembershipBackfill(membership, items);
    assert.equal(next.touched, true);
    assert.equal(new Date(next.last_seen_in_feed).toISOString(), T1.toISOString());
    assert.notEqual(new Date(next.last_seen_in_feed).toISOString(), T2.toISOString());
    assert.equal(new Date(next.first_seen_in_feed).toISOString(), T0.toISOString());
  });

  it('inverse: earlier OTX cannot rewrite ThreatFox last_seen either', () => {
    const membership = {
      first_seen_in_feed: T0,
      last_seen_in_feed: T1
    };
    const items = [
      {
        source_name: 'ThreatFox:abuse.ch',
        first_seen_at: T0,
        last_seen_at: T1,
        note: 'first_seen=2026-07-31T09:05:06.000Z'
      },
      {
        source_name: 'USOM:TR-CERT',
        first_seen_at: new Date('2026-01-01T00:00:00Z'),
        last_seen_at: new Date('2026-01-01T00:00:00Z'),
        note: 'usom'
      }
    ];
    const next = applyThreatFoxMembershipBackfill(membership, items);
    assert.equal(new Date(next.last_seen_in_feed).toISOString(), T1.toISOString());
  });

  it('leaves membership unchanged when no ThreatFox-scoped observation exists', () => {
    const membership = {
      first_seen_in_feed: T0,
      last_seen_in_feed: T0
    };
    const items = [
      {
        source_name: 'AlienVault OTX',
        first_seen_at: T2,
        last_seen_at: T2,
        note: 'otx only'
      }
    ];
    const next = applyThreatFoxMembershipBackfill(membership, items);
    assert.equal(next.touched, false);
    assert.equal(new Date(next.last_seen_in_feed).toISOString(), T0.toISOString());
  });

  it('SQL file never maxes last_seen across non-ThreatFox items', () => {
    const sql = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/025_ioc_source_last_seen.sql'),
      'utf8'
    );
    assert.match(sql, /source_name LIKE 'ThreatFox:%'/);
    assert.match(sql, /SOURCE ISOLATION/);
    assert.doesNotMatch(sql, /FROM ioc_items(?![\s\S]*ThreatFox)/);
  });
});

describe('ThreatFox TTL isolation from other sources', () => {
  const FEED_TF = '9f04b9f4-fc5b-4195-8802-0c99ac14b721';
  const T1 = new Date('2026-07-31T09:05:06.000Z');
  const T2 = new Date('2026-09-10T12:00:00.000Z');
  const FP = 'tf-semantic-fp';

  it('fixed_ttl for ThreatFox uses ThreatFox last_seen only', () => {
    const tfExpires = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 30 },
      { firstSeenInFeed: new Date('2026-06-03T00:00:00Z'), lastSeenInFeed: T1 }
    );
    const ifWronglyUsedOtx = computePolicyExpiresAt(
      { enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 30 },
      { firstSeenInFeed: new Date('2026-06-03T00:00:00Z'), lastSeenInFeed: T2 }
    );
    assert.equal(tfExpires.toISOString(), '2026-08-30T09:05:06.000Z');
    assert.notEqual(tfExpires.toISOString(), ifWronglyUsedOtx.toISOString());
  });

  it('upsertMembershipOnImport for ThreatFox ignores a later non-ThreatFox global time', async () => {
    // Membership last_seen stays at T1 when this ThreatFox upsert only receives T1.
    // A global IOC last_seen of T2 is not an input to upsertMembershipOnImport.
    const membership = {
      id: 10,
      ioc_item_id: 99,
      ioc_observable_type: 'ip',
      feed_id: FEED_TF,
      first_seen_in_feed: new Date('2026-06-03T00:00:00Z'),
      last_seen_in_feed: T1,
      last_changed_in_source: null,
      content_fingerprint: FP,
      missing_since: null,
      override_enabled: false,
      status: 'active',
      expired_at: null,
      expiration_reason: null,
      purged_at: null,
      policy_expires_at: new Date('2026-08-30T09:05:06.000Z'),
      expires_at: new Date('2026-08-30T09:05:06.000Z')
    };
    const updates = [];
    const client = {
      async query(sql, params = []) {
        const s = String(sql);
        if (s.includes('FROM threat_feed_expiration_policies')) {
          return { rows: [{ enabled: true, expiration_mode: 'fixed_ttl', ttl_days: 30, feed_id: FEED_TF, observable_type: 'all' }] };
        }
        if (s.includes('FROM ioc_suppressions')) return { rows: [] };
        if (s.includes('FROM ioc_feed_memberships') && s.includes('ioc_item_id')) {
          return { rows: [membership], rowCount: 1 };
        }
        if (s.includes('GREATEST(last_seen_in_feed') && !s.includes('last_changed_in_source')) {
          updates.push({ kind: 'last_seen', params });
          return { rows: [], rowCount: 0 };
        }
        if (s.includes('last_changed_in_source')) {
          updates.push({ kind: 'last_changed', params });
          return { rows: [membership], rowCount: 1 };
        }
        if (s.includes('policy_expires_at')) {
          updates.push({ kind: 'ttl', params });
          return { rowCount: 0, rows: [] };
        }
        return { rows: [], rowCount: 0 };
      }
    };

    const globalIocLastSeen = T2; // must not be passed into ThreatFox membership upsert
    assert.ok(globalIocLastSeen > T1);

    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'ip',
      feedId: FEED_TF,
      seenAt: new Date('2026-09-11T00:00:00Z'),
      firstSeenAt: new Date('2026-06-03T00:00:00Z'),
      observedAt: T1, // ThreatFox observation only
      contentFingerprint: FP
    }));

    assert.equal(result.outcome, 'unchanged');
    // GREATEST may be attempted; it must not move past T1 and must never see T2.
    for (const u of updates.filter((x) => x.kind === 'last_seen')) {
      assert.ok(u.params[1] instanceof Date);
      assert.equal(u.params[1].toISOString(), T1.toISOString());
      assert.notEqual(u.params[1].toISOString(), globalIocLastSeen.toISOString());
    }
    assert.equal(new Date(membership.last_seen_in_feed).toISOString(), T1.toISOString());
    assert.equal(new Date(membership.expires_at).toISOString(), '2026-08-30T09:05:06.000Z');
  });
});
