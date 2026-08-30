import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createImportMetrics } from './lib/import-metrics.js';
import { buildUrlhausNote, mapUrlhausRow, splitCsvLine } from './lib/urlhaus.js';
import { upsertUrlhausObservable } from './importer.js';

// Scripted mock that replays queries in a defined sequence.
// Each handler's match() is tried in order; first match wins.
// importSideEffect swallows errors so unexpected queries cause silent assertion failures —
// all expected queries must be handled.
function makeScriptedClient(handlers) {
  const calls = [];
  return {
    calls,
    async query(sql, params = []) {
      const text = String(sql);
      calls.push({ sql: text, params });
      const handler = handlers.find((h) => h.match(text));
      if (!handler) throw new Error(`expired-membership mock: unexpected query: ${text.slice(0, 160)}`);
      return handler.result(text, params);
    }
  };
}

function sampleEntry(overrides = {}) {
  const row = mapUrlhausRow(splitCsvLine(
    '3858192,2026-06-04 00:22:19,https://zkenezc.baccaratbazi.com/1cd153b6-68f9-451b-bb81-b8d7f4f263cb,offline,,malware_download,ClearFake,https://urlhaus.abuse.ch/url/3858192/,anonymous'
  ));
  return { ...row, ...overrides };
}

const IOC_ITEM_ID = 'aaaaaaaa-0000-0000-0000-000000000001';
const MEMB_ID = 'bbbbbbbb-0000-0000-0000-000000000001';
const FEED_ID = 'cccccccc-0000-0000-0000-000000000001';
const OBSERVABLE = 'https://zkenezc.baccaratbazi.com/1cd153b6-68f9-451b-bb81-b8d7f4f263cb';

// Query sequence for URLhaus unchanged + expired membership (no explicit confidence):
// Q1  SELECT ioc_items (updateUrlhausExistingIocBySource) → unchanged
// Q2  FROM integration_feeds                     → urlhaus feed
// Q3  ioc_items by observable                   → found
// Q4  FROM threat_feed_expiration_policies       → no policy
// Q5  ioc_feed_memberships by ioc_item_id        → expired
// Q6  UPDATE ioc_feed_memberships reactivation   → sets status='active'
//     applyMembershipComputedFields              → no-op (null policy, clean row)
//     explicit_confidence                        → skipped (no confidence in URLhaus)
//     reactivated=true → recomputeIocGlobalStatus:
// Q7  ioc_items by id                            → status='expired'
// Q8  ioc_suppressions                           → none
// Q9  ioc_feed_memberships status select         → [{status:'active'}]
// Q10 MIN expires_at                             → null
// Q11 UPDATE ioc_items SET status='active'       → recomputed
const HANDLERS = [
  {
    match: (s) => s.includes('FROM ioc_items') && s.includes('source_name = $3') && s.includes('LIMIT 1'),
    result: () => {
      const entry = sampleEntry();
      const note = buildUrlhausNote(entry);
      return {
        rowCount: 1,
        rows: [{
          public_id: 'pub-1',
          note,
          category: entry.threat || 'malware-url',
          first_seen_at: entry.dateAdded,
          last_seen_at: null,
          provider_fingerprint: null
        }]
      };
    }
  },
  {
    match: (s) => s.includes('UPDATE ioc_items') && s.includes('SET provider_fingerprint'),
    result: () => ({ rowCount: 1, rows: [{ public_id: 'pub-1' }] })
  },
  {
    match: (s) => s.includes('FROM integration_feeds'),
    result: () => ({
      rows: [{ key: 'urlhaus-abusech', feed_id: FEED_ID, feed_update_mode: 'incremental', name: 'URLhaus', feed_kind: 'builtin' }]
    })
  },
  {
    match: (s) => s.includes('FROM ioc_items') && s.includes('WHERE observable = '),
    result: () => ({ rows: [{ id: IOC_ITEM_ID, observable_type: 'url' }] })
  },
  {
    match: (s) => s.includes('FROM threat_feed_expiration_policies'),
    result: () => ({ rows: [] })
  },
  {
    match: (s) => s.includes('FROM integration_feed_expiration_type_policies'),
    result: () => ({ rows: [] })
  },
  {
    match: (s) => s.includes('FROM ioc_feed_memberships') && s.includes('WHERE ioc_item_id'),
    result: () => ({
      rowCount: 1,
      rows: [{
        id: MEMB_ID,
        status: 'expired',
        expired_at: new Date('2026-06-20T00:00:00Z'),
        expiration_reason: 'policy_ttl',
        missing_since: null,
        purged_at: null,
        purged_by: null,
        purged_by_username: null,
        purge_reason: null,
        override_enabled: false,
        first_seen_in_feed: new Date('2026-06-01T00:00:00Z'),
        last_seen_in_feed: new Date('2026-06-20T00:00:00Z')
      }]
    })
  },
  {
    // Reactivation UPDATE — returns a clean active row without policy_expires_at/expires_at
    // so that applyMembershipComputedFields sees no computed field changes and skips its UPDATE.
    match: (s) => s.includes('UPDATE ioc_feed_memberships') && s.includes('SET last_seen_in_feed'),
    result: () => ({
      rowCount: 1,
      rows: [{
        id: MEMB_ID,
        status: 'active',
        last_seen_in_feed: new Date(),
        missing_since: null,
        expired_at: null,
        expiration_reason: null,
        purged_at: null,
        purged_by: null,
        purged_by_username: null,
        purge_reason: null,
        first_seen_in_feed: new Date('2026-06-01T00:00:00Z')
      }]
    })
  },
  {
    match: (s) => s.includes('FROM ioc_items') && s.includes('WHERE id = $1'),
    result: () => ({
      rows: [{
        id: IOC_ITEM_ID,
        observable: OBSERVABLE,
        observable_type: 'url',
        status: 'expired',
        manual_status_override: false,
        manual_status: null,
        manual_expires_at: null,
        expires_at: new Date('2026-06-20T00:00:00Z'),
        expired_at: new Date('2026-06-20T00:00:00Z'),
        expiration_reason: 'all_feed_memberships_expired'
      }]
    })
  },
  {
    match: (s) => s.includes('FROM ioc_suppressions'),
    result: () => ({ rows: [] })
  },
  {
    match: (s) => s.includes('SELECT m.status, m.purged_at'),
    result: () => ({ rows: [{ status: 'active', purged_at: null }] })
  },
  {
    match: (s) => s.includes('SELECT MIN(m.expires_at)'),
    result: () => ({ rows: [{ min_exp: null }] })
  },
  {
    match: (s) => s.includes('UPDATE ioc_items') && s.includes('SET status = '),
    result: () => ({ rowCount: 1, rows: [] })
  }
];

describe('upsertUrlhausObservable expired membership reactivation', () => {
  it('reactivates expired URLhaus membership when unchanged IOC reappears in feed', async () => {
    const client = makeScriptedClient(HANDLERS);
    const metrics = createImportMetrics();

    await upsertUrlhausObservable(client, sampleEntry(), 'URLhaus:abuse.ch', null, metrics, 'high');

    // ioc_items was NOT updated (unchanged metadata → no records_updated)
    assert.equal(metrics.records_updated, 0, 'ioc_items must not be updated for unchanged metadata');
    assert.equal(metrics.records_inserted, 0, 'no insert for existing IOC');
    assert.equal(metrics.records_unchanged, 1, 'counted as unchanged (not skipped/rejected)');
    assert.equal(metrics.records_skipped, 0, 'existing/no-op must not increment skipped');

    // Membership WAS reactivated
    assert.ok(
      client.calls.some((c) => c.sql.includes('UPDATE ioc_feed_memberships') && c.sql.includes('SET last_seen_in_feed')),
      'expired membership must be reactivated via UPDATE ioc_feed_memberships'
    );

    // IOC global status WAS recomputed (because reactivated=true)
    assert.ok(
      client.calls.some((c) => c.sql.includes('UPDATE ioc_items') && c.sql.includes('SET status = ')),
      'IOC global status must be recomputed after membership reactivation'
    );

    assert.ok(
      !client.calls.some((c) => c.sql.startsWith('UPDATE ioc_items') && c.sql.includes('SET note = ')),
      'unchanged metadata must not rewrite ioc_items note/category'
    );
  });
});
