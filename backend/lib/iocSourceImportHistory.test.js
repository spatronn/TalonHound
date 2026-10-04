import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  IOC_SOURCE_IMPORTED_ACTION,
  buildDerivedSourceImportEvent,
  canonicalSourceFirstImportAt,
  decoratePersistedSourceImportRow,
  extractSourceImportFeedId,
  mergeIocAuditHistory,
  recordSourceImportAudit,
  sourceImportActionLabel,
  sourceImportDedupeKey
} from './iocSourceImportHistory.js';
import { upsertMembershipOnImport, withImportOptimizationContext } from './iocExpiration.js';

const OTX_FEED = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USOM_FEED = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const TF_FEED = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';

const IOC = {
  id: 3002619,
  public_id: '8a077cf3-ae43-4ff5-a0e7-484f09beb06e',
  observable: 'upd-domain-goloro.com',
  observable_type: 'domain'
};

function membership({ id, feedId, feedKey, feedName, firstSeen, createdAt = null }) {
  return {
    id,
    feed_id: feedId,
    feed_key: feedKey,
    feed_name: feedName,
    ioc_observable_type: 'domain',
    first_seen_in_feed: firstSeen,
    created_at: createdAt || firstSeen,
    status: 'active'
  };
}

describe('source import identity helpers', () => {
  it('dedupe key is (action, ioc, feed) not timestamp', () => {
    assert.equal(
      sourceImportDedupeKey({ iocId: 1, feedId: OTX_FEED }),
      `ioc.source_imported:1:${OTX_FEED}`
    );
    assert.notEqual(
      sourceImportDedupeKey({ iocId: 1, feedId: OTX_FEED }),
      sourceImportDedupeKey({ iocId: 1, feedId: USOM_FEED })
    );
  });

  it('action label names the feed', () => {
    assert.equal(sourceImportActionLabel('AlienVault OTX'), 'Imported from AlienVault OTX');
    assert.equal(
      sourceImportActionLabel('Siber Güvenlik Başkanlığı / USOM'),
      'Imported from Siber Güvenlik Başkanlığı / USOM'
    );
  });

  it('canonical timestamp prefers first_seen_in_feed over created_at', () => {
    assert.equal(
      canonicalSourceFirstImportAt({
        first_seen_in_feed: '2026-07-18T15:17:32.726Z',
        created_at: '2026-07-18T15:44:17.748Z'
      }),
      '2026-07-18T15:17:32.726Z'
    );
  });
});

describe('derived + merge semantics', () => {
  it('TEST 1/4/6/9: one derived event per feed with that feed\'s own first-import timestamp', () => {
    const otx = buildDerivedSourceImportEvent({
      membership: membership({
        id: 1,
        feedId: OTX_FEED,
        feedKey: 'alienvault-otx',
        feedName: 'AlienVault OTX',
        firstSeen: '2026-07-01T23:40:22.999Z'
      }),
      iocItem: IOC
    });
    const usom = buildDerivedSourceImportEvent({
      membership: membership({
        id: 2,
        feedId: USOM_FEED,
        feedKey: 'usom-trcert',
        feedName: 'Siber Güvenlik Başkanlığı / USOM',
        firstSeen: '2026-07-18T15:17:32.726Z'
      }),
      iocItem: IOC
    });
    const threatfox = buildDerivedSourceImportEvent({
      membership: membership({
        id: 3,
        feedId: TF_FEED,
        feedKey: 'threatfox',
        feedName: 'ThreatFox',
        firstSeen: '2026-08-01T10:00:00.000Z'
      }),
      iocItem: IOC
    });

    const items = mergeIocAuditHistory({
      persistedRows: [],
      derivedRows: [otx, usom, threatfox],
      limit: 50
    });

    assert.equal(items.length, 3);
    assert.equal(items[0].action_label, 'Imported from ThreatFox');
    assert.equal(new Date(items[0].created_at).toISOString(), '2026-08-01T10:00:00.000Z');
    assert.equal(items[1].action_label, 'Imported from Siber Güvenlik Başkanlığı / USOM');
    assert.equal(new Date(items[1].created_at).toISOString(), '2026-07-18T15:17:32.726Z');
    assert.equal(items[2].action_label, 'Imported from AlienVault OTX');
    assert.equal(new Date(items[2].created_at).toISOString(), '2026-07-01T23:40:22.999Z');
    for (const row of items) {
      assert.equal(row.action, IOC_SOURCE_IMPORTED_ACTION);
      assert.equal(row.actor_username, 'System');
      assert.equal(row.metadata.derived, true);
    }
  });

  it('TEST 7: historical IOC with 2 memberships and no persisted audits exposes 2 derived events', () => {
    const items = mergeIocAuditHistory({
      persistedRows: [],
      derivedRows: [
        buildDerivedSourceImportEvent({
          membership: membership({
            id: 3075596,
            feedId: OTX_FEED,
            feedKey: 'alienvault-otx',
            feedName: 'AlienVault OTX',
            firstSeen: '2026-07-01T23:40:22.999Z'
          }),
          iocItem: IOC
        }),
        buildDerivedSourceImportEvent({
          membership: membership({
            id: 3634662,
            feedId: USOM_FEED,
            feedKey: 'usom-trcert',
            feedName: 'Siber Güvenlik Başkanlığı / USOM',
            firstSeen: '2026-07-18T15:17:32.726Z'
          }),
          iocItem: IOC
        })
      ],
      limit: 50
    });
    assert.equal(items.length, 2);
    assert.deepEqual(
      items.map((r) => r.metadata.feed_key).sort(),
      ['alienvault-otx', 'usom-trcert']
    );
  });

  it('TEST 8: persisted OTX + historical-only USOM → no duplicate OTX', () => {
    const persisted = decoratePersistedSourceImportRow({
      id: 9001,
      created_at: '2026-07-01T23:40:22.999Z',
      actor_username: 'System',
      action: IOC_SOURCE_IMPORTED_ACTION,
      entity_type: 'ioc',
      entity_id: IOC.public_id,
      subject_ioc_id: IOC.id,
      metadata: {
        event_kind: 'source_import',
        feed_id: OTX_FEED,
        feed_key: 'alienvault-otx',
        feed_name: 'AlienVault OTX',
        first_seen_in_feed: '2026-07-01T23:40:22.999Z'
      }
    });
    const derivedOtx = buildDerivedSourceImportEvent({
      membership: membership({
        id: 1,
        feedId: OTX_FEED,
        feedKey: 'alienvault-otx',
        feedName: 'AlienVault OTX',
        firstSeen: '2026-07-01T23:40:22.999Z'
      }),
      iocItem: IOC
    });
    const derivedUsom = buildDerivedSourceImportEvent({
      membership: membership({
        id: 2,
        feedId: USOM_FEED,
        feedKey: 'usom-trcert',
        feedName: 'Siber Güvenlik Başkanlığı / USOM',
        firstSeen: '2026-07-18T15:17:32.726Z'
      }),
      iocItem: IOC
    });

    const items = mergeIocAuditHistory({
      persistedRows: [persisted],
      derivedRows: [derivedOtx, derivedUsom],
      limit: 50
    });

    const otx = items.filter((r) => extractSourceImportFeedId(r) === OTX_FEED);
    const usom = items.filter((r) => extractSourceImportFeedId(r) === USOM_FEED);
    assert.equal(otx.length, 1, 'exactly one OTX event');
    assert.equal(usom.length, 1, 'exactly one USOM event');
    assert.equal(otx[0].id, 9001, 'persisted OTX wins');
    assert.equal(otx[0].metadata.derived, undefined);
    assert.equal(usom[0].metadata.derived, true);
  });

  it('TEST 10: manual IOC history is not fabricated as feed import', () => {
    // No feed memberships → no derived source-import events.
    const items = mergeIocAuditHistory({
      persistedRows: [{
        id: 1,
        created_at: '2026-08-01T00:00:00.000Z',
        action: 'ioc.created',
        action_label: 'IOC Created',
        actor_username: 'analyst',
        entity_type: 'ioc',
        subject_ioc_id: 55,
        metadata: { origin: 'manual' }
      }],
      derivedRows: [],
      limit: 50
    });
    assert.equal(items.length, 1);
    assert.equal(items[0].action, 'ioc.created');
    assert.equal(items.some((r) => r.action === IOC_SOURCE_IMPORTED_ACTION), false);
  });

  it('TEST 11: Threat Library create is not a feed import unless memberships exist', () => {
    const items = mergeIocAuditHistory({
      persistedRows: [{
        id: 2,
        created_at: '2026-08-02T00:00:00.000Z',
        action: 'ioc.created',
        action_label: 'IOC Created',
        actor_username: 'analyst',
        entity_type: 'ioc',
        subject_ioc_id: 77,
        metadata: { origin: 'threat_library' }
      }],
      derivedRows: [],
      limit: 50
    });
    assert.equal(items.some((r) => r.action === IOC_SOURCE_IMPORTED_ACTION), false);
  });
});

describe('recordSourceImportAudit idempotency', () => {
  it('TEST 13: concurrent-style second insert is a no-op (WHERE NOT EXISTS)', async () => {
    let insertCount = 0;
    const client = {
      async query(sql) {
        const s = String(sql);
        if (s.includes('FROM integration_feeds')) {
          return { rows: [{ key: 'alienvault-otx', name: 'AlienVault OTX' }], rowCount: 1 };
        }
        if (s.includes('INSERT INTO audit_logs')) {
          insertCount += 1;
          if (insertCount === 1) return { rows: [{ id: 42 }], rowCount: 1 };
          // Second call: NOT EXISTS fails → zero rows.
          return { rows: [], rowCount: 0 };
        }
        return { rows: [], rowCount: 0 };
      }
    };

    const first = await recordSourceImportAudit(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: OTX_FEED,
      membershipId: 10,
      firstSeenAt: '2026-07-01T23:40:22.999Z'
    });
    const second = await recordSourceImportAudit(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: OTX_FEED,
      membershipId: 10,
      firstSeenAt: '2026-07-01T23:40:22.999Z'
    });

    assert.equal(first.written, true);
    assert.equal(second.written, false);
    assert.equal(insertCount, 2);
    assert.match(String(first.action_label), /AlienVault OTX/);
  });
});

describe('upsertMembershipOnImport source-import audit write amplification', () => {
  const FEED_ID = OTX_FEED;
  const FP = 'fp'.repeat(32);
  const T1 = new Date('2026-07-01T23:40:22.999Z');

  function makeClient({ existing = null } = {}) {
    const calls = [];
    let current = existing;
    const client = {
      calls,
      async query(sql, params = []) {
        const s = String(sql);
        calls.push({ sql: s, params });
        if (s.includes('FROM threat_feed_expiration_policies')) {
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
        if (s.includes('FROM ioc_feed_memberships') && s.includes('ioc_item_id') && s.includes('SELECT *')) {
          return current
            ? { rows: [current], rowCount: 1 }
            : { rows: [], rowCount: 0 };
        }
        if (s.startsWith('INSERT INTO ioc_feed_memberships')) {
          current = {
            id: 10,
            ioc_item_id: 99,
            ioc_observable_type: 'domain',
            feed_id: FEED_ID,
            first_seen_in_feed: params[3],
            last_seen_in_feed: params[4],
            last_changed_in_source: params[4],
            content_fingerprint: params[5] || null,
            missing_since: null,
            override_enabled: false,
            status: 'active',
            expired_at: null,
            expiration_reason: null,
            purged_at: null,
            policy_expires_at: null,
            expires_at: null,
            explicit_confidence: null
          };
          return { rows: [current], rowCount: 1 };
        }
        if (s.includes('FROM integration_feeds')) {
          return { rows: [{ key: 'alienvault-otx', name: 'AlienVault OTX' }], rowCount: 1 };
        }
        if (s.includes('INSERT INTO audit_logs')) {
          return { rows: [{ id: 500 }], rowCount: 1 };
        }
        if (s.startsWith('UPDATE ioc_feed_memberships') && s.includes('policy_expires_at')) {
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
          return { rows: [current], rowCount: 1 };
        }
        if (s.includes('FROM ioc_items') && s.includes('manual_status_override')) {
          return {
            rows: [{
              id: 99,
              observable: 'upd-domain-goloro.com',
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
        if (s.includes('MIN(m.expires_at)')) return { rows: [{ min_exp: null }] };
        if (s.startsWith('UPDATE ioc_items')) return { rows: [], rowCount: 0 };
        return { rows: [], rowCount: 0 };
      }
    };
    return client;
  }

  it('TEST 1: new IOC/membership from OTX writes exactly one source-import audit', async () => {
    const client = makeClient({ existing: null });
    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: FEED_ID,
      seenAt: T1,
      firstSeenAt: T1,
      contentFingerprint: FP
    }));
    assert.equal(result.outcome, 'created');
    const audits = client.calls.filter((c) => c.sql.includes('INSERT INTO audit_logs'));
    assert.equal(audits.length, 1);
    assert.equal(audits[0].params[1], IOC_SOURCE_IMPORTED_ACTION);
  });

  it('TEST 2/3/12: re-sight of existing membership writes zero source-import audits', async () => {
    const existing = {
      id: 10,
      ioc_item_id: 99,
      ioc_observable_type: 'domain',
      feed_id: FEED_ID,
      first_seen_in_feed: T1,
      last_seen_in_feed: T1,
      last_changed_in_source: T1,
      content_fingerprint: FP,
      missing_since: null,
      override_enabled: false,
      status: 'active',
      expired_at: null,
      expiration_reason: null,
      purged_at: null,
      policy_expires_at: new Date('2026-07-31T23:40:22.999Z'),
      expires_at: new Date('2026-07-31T23:40:22.999Z'),
      explicit_confidence: null
    };
    const client = makeClient({ existing });
    for (let i = 0; i < 10; i += 1) {
      const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
        iocItemId: 99,
        observableType: 'domain',
        feedId: FEED_ID,
        seenAt: new Date(`2026-07-${String(2 + i).padStart(2, '0')}T00:00:00Z`),
        firstSeenAt: T1,
        contentFingerprint: FP,
        reactivateOnly: true
      }));
      assert.equal(result.outcome, 'unchanged');
    }
    const audits = client.calls.filter((c) => c.sql.includes('INSERT INTO audit_logs'));
    assert.equal(audits.length, 0, 'bulk re-sight must not amplify source-import audits');
  });

  it('TEST 4/5: later first import by a second feed writes one new audit; re-sight writes zero', async () => {
    // First feed already exists — simulate USOM create then re-sight.
    let existingUsom = null;
    const calls = [];
    const client = {
      calls,
      async query(sql, params = []) {
        const s = String(sql);
        calls.push({ sql: s, params });
        if (s.includes('FROM threat_feed_expiration_policies')) {
          return {
            rows: [{
              enabled: true,
              expiration_mode: 'fixed_ttl',
              ttl_days: 365,
              feed_id: USOM_FEED,
              observable_type: 'all'
            }]
          };
        }
        if (s.includes('FROM ioc_suppressions')) return { rows: [] };
        if (s.includes('FROM ioc_feed_memberships') && s.includes('ioc_item_id') && s.includes('SELECT *')) {
          return existingUsom
            ? { rows: [existingUsom], rowCount: 1 }
            : { rows: [], rowCount: 0 };
        }
        if (s.startsWith('INSERT INTO ioc_feed_memberships')) {
          existingUsom = {
            id: 20,
            ioc_item_id: 99,
            ioc_observable_type: 'domain',
            feed_id: USOM_FEED,
            first_seen_in_feed: params[3],
            last_seen_in_feed: params[4],
            last_changed_in_source: params[4],
            content_fingerprint: null,
            missing_since: null,
            override_enabled: false,
            status: 'active',
            expired_at: null,
            expiration_reason: null,
            purged_at: null,
            policy_expires_at: null,
            expires_at: null,
            explicit_confidence: null
          };
          return { rows: [existingUsom], rowCount: 1 };
        }
        if (s.includes('FROM integration_feeds')) {
          return { rows: [{ key: 'usom-trcert', name: 'Siber Güvenlik Başkanlığı / USOM' }], rowCount: 1 };
        }
        if (s.includes('INSERT INTO audit_logs')) {
          return { rows: [{ id: 501 }], rowCount: 1 };
        }
        if (s.startsWith('UPDATE ioc_feed_memberships') && s.includes('policy_expires_at')) {
          existingUsom = {
            ...existingUsom,
            policy_expires_at: params[1],
            expires_at: params[2],
            status: params[3]
          };
          return { rows: [existingUsom], rowCount: 1 };
        }
        if (s.includes('FROM ioc_items') && s.includes('manual_status_override')) {
          return {
            rows: [{
              id: 99, observable: 'x', observable_type: 'domain', status: 'active',
              manual_status_override: false, expires_at: null, expired_at: null, expiration_reason: null
            }]
          };
        }
        if (s.includes('FROM ioc_feed_memberships m') && s.includes('INNER JOIN ioc_items')) {
          return { rows: [{ status: 'active', purged_at: null }] };
        }
        if (s.includes('MIN(m.expires_at)')) return { rows: [{ min_exp: null }] };
        if (s.startsWith('UPDATE ioc_items')) return { rows: [], rowCount: 0 };
        return { rows: [], rowCount: 0 };
      }
    };

    const created = await upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: USOM_FEED,
      seenAt: new Date('2026-07-18T15:17:32.726Z'),
      firstSeenAt: new Date('2026-07-18T15:17:32.726Z')
    });
    assert.equal(created.outcome, 'created');
    assert.equal(calls.filter((c) => c.sql.includes('INSERT INTO audit_logs')).length, 1);

    const beforeResight = calls.filter((c) => c.sql.includes('INSERT INTO audit_logs')).length;
    const resight = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: USOM_FEED,
      seenAt: new Date('2026-07-19T00:00:00Z'),
      firstSeenAt: new Date('2026-07-18T15:17:32.726Z'),
      reactivateOnly: true
    }));
    assert.equal(resight.outcome, 'unchanged');
    assert.equal(
      calls.filter((c) => c.sql.includes('INSERT INTO audit_logs')).length,
      beforeResight,
      'USOM re-sight must not write a second source-import audit'
    );
  });
});
