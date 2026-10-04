import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  IOC_SOURCE_IMPORTED_ACTION,
  buildDerivedSourceImportEvent,
  canonicalSourceImportedAt,
  decoratePersistedSourceImportRow,
  extractSourceImportFeedId,
  mergeIocAuditHistory,
  persistedSourceImportDisplayAt,
  recordSourceImportAudit,
  sourceImportActionLabel,
  sourceImportDedupeKey
} from './iocSourceImportHistory.js';
import { upsertMembershipOnImport, withImportOptimizationContext } from './iocExpiration.js';

const OTX_FEED = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const USOM_FEED = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const TF_FEED = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const URLHAUS_FEED = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';

const IOC = {
  id: 3002619,
  public_id: '8a077cf3-ae43-4ff5-a0e7-484f09beb06e',
  observable: 'upd-domain-goloro.com',
  observable_type: 'domain'
};

function membership({ id, feedId, feedKey, feedName, firstSeen, createdAt }) {
  return {
    id,
    feed_id: feedId,
    feed_key: feedKey,
    feed_name: feedName,
    ioc_observable_type: 'domain',
    first_seen_in_feed: firstSeen,
    created_at: createdAt,
    status: 'active'
  };
}

describe('source import identity helpers', () => {
  it('dedupe key is (action, ioc, feed) not timestamp', () => {
    assert.equal(
      sourceImportDedupeKey({ iocId: 1, feedId: OTX_FEED }),
      `ioc.source_imported:1:${OTX_FEED}`
    );
  });

  it('action label names the feed', () => {
    assert.equal(sourceImportActionLabel('URLhaus abuse.ch'), 'Imported from URLhaus abuse.ch');
  });

  it('canonical Audit timestamp uses membership.created_at, never first_seen_in_feed', () => {
    assert.equal(
      canonicalSourceImportedAt({
        first_seen_in_feed: '2026-10-04T20:02:13.000Z',
        created_at: '2026-10-04T20:40:04.695Z'
      }),
      '2026-10-04T20:40:04.695Z'
    );
  });
});

describe('Audit Date vs Overview First seen in source', () => {
  it('TEST 1 — exact production URLhaus bug: Audit uses import time not provider first_seen', () => {
    const event = buildDerivedSourceImportEvent({
      membership: membership({
        id: 12700803,
        feedId: URLHAUS_FEED,
        feedKey: 'urlhaus-abusech',
        feedName: 'URLhaus abuse.ch',
        firstSeen: '2026-10-04T20:02:13.000Z',
        createdAt: '2026-10-04T20:40:04.695Z'
      }),
      iocItem: {
        id: 3533649,
        public_id: 'fcd71507-42f1-41d5-b687-1bb8b612bbab',
        observable: 'http://92.243.113.232:16844/bin.sh',
        observable_type: 'url'
      }
    });

    assert.equal(new Date(event.created_at).toISOString(), '2026-10-04T20:40:04.695Z');
    assert.notEqual(new Date(event.created_at).toISOString(), '2026-10-04T20:02:13.000Z');
    assert.equal(event.action_label, 'Imported from URLhaus abuse.ch');
    assert.equal(event.metadata.first_seen_in_feed, '2026-10-04T20:02:13.000Z');
    assert.equal(event.metadata.source_imported_at, '2026-10-04T20:40:04.695Z');
  });

  it('TEST 2 — provider first_seen much older than TalonHound import', () => {
    const event = buildDerivedSourceImportEvent({
      membership: membership({
        id: 1,
        feedId: OTX_FEED,
        feedKey: 'alienvault-otx',
        feedName: 'AlienVault OTX',
        firstSeen: '2025-01-01T00:00:00.000Z',
        createdAt: '2026-10-04T12:00:00.000Z'
      }),
      iocItem: IOC
    });
    assert.equal(new Date(event.created_at).toISOString(), '2026-10-04T12:00:00.000Z');
  });

  it('TEST 3 — first source/new IOC: Audit = membership created_at (T1), Overview first_seen stays T0', () => {
    const T0 = '2026-10-04T20:02:13.000Z';
    const T1 = '2026-10-04T20:40:04.695Z';
    const event = buildDerivedSourceImportEvent({
      membership: membership({
        id: 9,
        feedId: URLHAUS_FEED,
        feedKey: 'urlhaus-abusech',
        feedName: 'URLhaus abuse.ch',
        firstSeen: T0,
        createdAt: T1
      }),
      iocItem: { id: 1, observable: 'http://x/', observable_type: 'url' }
    });
    assert.equal(event.created_at, T1);
    assert.equal(event.metadata.first_seen_in_feed, T0);
  });

  it('TEST 4 — second source on existing IOC uses Feed B membership created_at, not provider first_seen or IOC T1', () => {
    const T1 = '2026-07-02T14:00:00.000Z';
    const T2 = '2026-06-10T08:00:00.000Z'; // provider first_seen — earlier than import
    const T3 = '2026-08-15T17:30:00.000Z';
    const feedA = buildDerivedSourceImportEvent({
      membership: membership({
        id: 1, feedId: OTX_FEED, feedKey: 'alienvault-otx', feedName: 'AlienVault OTX',
        firstSeen: '2026-05-01T10:00:00.000Z', createdAt: T1
      }),
      iocItem: IOC
    });
    const feedB = buildDerivedSourceImportEvent({
      membership: membership({
        id: 2, feedId: USOM_FEED, feedKey: 'usom-trcert',
        feedName: 'Siber Güvenlik Başkanlığı / USOM',
        firstSeen: T2, createdAt: T3
      }),
      iocItem: IOC
    });
    const items = mergeIocAuditHistory({ persistedRows: [], derivedRows: [feedA, feedB], limit: 50 });
    assert.equal(items.length, 2);
    assert.equal(new Date(items[0].created_at).toISOString(), T3);
    assert.equal(items[0].action_label, 'Imported from Siber Güvenlik Başkanlığı / USOM');
    assert.equal(new Date(items[1].created_at).toISOString(), T1);
    assert.notEqual(items[0].created_at, T2);
    assert.notEqual(items[0].created_at, T1);
  });

  it('TEST 5 — 3 feeds each use own membership created_at', () => {
    const rows = [
      membership({
        id: 1, feedId: OTX_FEED, feedKey: 'alienvault-otx', feedName: 'AlienVault OTX',
        firstSeen: '2026-01-01T00:00:00.000Z', createdAt: '2026-07-02T14:00:00.000Z'
      }),
      membership({
        id: 2, feedId: TF_FEED, feedKey: 'threatfox', feedName: 'ThreatFox',
        firstSeen: '2026-02-01T00:00:00.000Z', createdAt: '2026-08-01T10:00:00.000Z'
      }),
      membership({
        id: 3, feedId: USOM_FEED, feedKey: 'usom-trcert', feedName: 'USOM',
        firstSeen: '2026-03-01T00:00:00.000Z', createdAt: '2026-09-20T12:00:00.000Z'
      })
    ].map((m) => buildDerivedSourceImportEvent({ membership: m, iocItem: IOC }));

    const items = mergeIocAuditHistory({ persistedRows: [], derivedRows: rows, limit: 50 });
    assert.deepEqual(
      items.map((r) => new Date(r.created_at).toISOString()),
      ['2026-09-20T12:00:00.000Z', '2026-08-01T10:00:00.000Z', '2026-07-02T14:00:00.000Z']
    );
  });

  it('TEST 6 — persisted + synthetic dedupe keeps one Feed A event with import timestamp', () => {
    const importedAt = '2026-07-02T14:00:00.000Z';
    const providerFirst = '2026-05-01T10:00:00.000Z';
    const persisted = decoratePersistedSourceImportRow({
      id: 9001,
      created_at: importedAt,
      actor_username: 'System',
      action: IOC_SOURCE_IMPORTED_ACTION,
      entity_type: 'ioc',
      subject_ioc_id: IOC.id,
      metadata: {
        event_kind: 'source_import',
        feed_id: OTX_FEED,
        feed_key: 'alienvault-otx',
        feed_name: 'AlienVault OTX',
        source_imported_at: importedAt,
        membership_created_at: importedAt,
        first_seen_in_feed: providerFirst
      }
    });
    const derived = buildDerivedSourceImportEvent({
      membership: membership({
        id: 1, feedId: OTX_FEED, feedKey: 'alienvault-otx', feedName: 'AlienVault OTX',
        firstSeen: providerFirst, createdAt: importedAt
      }),
      iocItem: IOC
    });
    const items = mergeIocAuditHistory({
      persistedRows: [persisted],
      derivedRows: [derived],
      limit: 50
    });
    assert.equal(items.length, 1);
    assert.equal(items[0].id, 9001);
    assert.equal(new Date(items[0].created_at).toISOString(), importedAt);
  });

  it('TEST 7 — historical derived event uses membership created_at (T2), not provider first_seen (T1)', () => {
    const T1 = '2026-07-18T15:17:32.726Z';
    const T2 = '2026-07-18T15:44:17.748Z';
    const event = buildDerivedSourceImportEvent({
      membership: membership({
        id: 3634662,
        feedId: USOM_FEED,
        feedKey: 'usom-trcert',
        feedName: 'Siber Güvenlik Başkanlığı / USOM',
        firstSeen: T1,
        createdAt: T2
      }),
      iocItem: IOC
    });
    assert.equal(new Date(event.created_at).toISOString(), T2);
  });

  it('TEST 9 — decorate never falls back to first_seen_in_feed for Date', () => {
    const row = {
      id: 1,
      created_at: '2026-10-04T20:40:04.695Z',
      action: IOC_SOURCE_IMPORTED_ACTION,
      subject_ioc_id: 1,
      metadata: {
        feed_id: URLHAUS_FEED,
        feed_name: 'URLhaus abuse.ch',
        source_imported_at: '2026-10-04T20:40:04.695Z',
        first_seen_in_feed: '2026-10-04T20:02:13.000Z'
      }
    };
    assert.equal(
      new Date(persistedSourceImportDisplayAt(row)).toISOString(),
      '2026-10-04T20:40:04.695Z'
    );
    const decorated = decoratePersistedSourceImportRow(row);
    assert.equal(new Date(decorated.created_at).toISOString(), '2026-10-04T20:40:04.695Z');
  });

  it('TEST 10 — manual / Threat Library rows are not fabricated as feed imports', () => {
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
    assert.equal(items.some((r) => r.action === IOC_SOURCE_IMPORTED_ACTION), false);
  });
});

describe('recordSourceImportAudit idempotency + importedAt', () => {
  it('TEST 9 retry: second insert is a no-op; first uses importedAt not provider first_seen', async () => {
    let insertParams = null;
    let insertCount = 0;
    const client = {
      async query(sql, params = []) {
        const s = String(sql);
        if (s.includes('FROM integration_feeds')) {
          return { rows: [{ key: 'urlhaus-abusech', name: 'URLhaus abuse.ch' }], rowCount: 1 };
        }
        if (s.includes('INSERT INTO audit_logs')) {
          insertCount += 1;
          insertParams = params;
          if (insertCount === 1) return { rows: [{ id: 42 }], rowCount: 1 };
          return { rows: [], rowCount: 0 };
        }
        return { rows: [], rowCount: 0 };
      }
    };

    const importedAt = '2026-10-04T20:40:04.695Z';
    const providerFirst = '2026-10-04T20:02:13.000Z';
    const first = await recordSourceImportAudit(client, {
      iocItemId: 99,
      observableType: 'url',
      feedId: URLHAUS_FEED,
      membershipId: 10,
      importedAt,
      firstSeenInFeed: providerFirst
    });
    const second = await recordSourceImportAudit(client, {
      iocItemId: 99,
      observableType: 'url',
      feedId: URLHAUS_FEED,
      membershipId: 10,
      importedAt,
      firstSeenInFeed: providerFirst
    });

    assert.equal(first.written, true);
    assert.equal(second.written, false);
    assert.equal(insertCount, 2);
    assert.equal(new Date(insertParams[0]).toISOString(), importedAt);
    const meta = JSON.parse(insertParams[9]);
    assert.equal(meta.source_imported_at, importedAt);
    assert.equal(meta.first_seen_in_feed, providerFirst);
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
            explicit_confidence: null,
            created_at: '2026-10-04T20:40:04.695Z'
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

  it('TEST 1 create: writes one source-import audit using membership.created_at', async () => {
    const client = makeClient({ existing: null });
    const result = await withImportOptimizationContext(client, async () => upsertMembershipOnImport(client, {
      iocItemId: 99,
      observableType: 'domain',
      feedId: FEED_ID,
      seenAt: T1,
      firstSeenAt: new Date('2026-10-04T20:02:13.000Z'),
      contentFingerprint: FP
    }));
    assert.equal(result.outcome, 'created');
    const audits = client.calls.filter((c) => c.sql.includes('INSERT INTO audit_logs'));
    assert.equal(audits.length, 1);
    assert.equal(new Date(audits[0].params[0]).toISOString(), '2026-10-04T20:40:04.695Z');
    const meta = JSON.parse(audits[0].params[9]);
    assert.equal(meta.source_imported_at, '2026-10-04T20:40:04.695Z');
    assert.equal(meta.first_seen_in_feed, '2026-10-04T20:02:13.000Z');
  });

  it('TEST 8 re-sight: existing membership writes zero source-import audits', async () => {
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
      explicit_confidence: null,
      created_at: '2026-07-01T23:40:21.000Z'
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
    assert.equal(client.calls.filter((c) => c.sql.includes('INSERT INTO audit_logs')).length, 0);
  });
});
