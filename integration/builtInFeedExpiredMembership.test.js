import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildMalwareBazaarNote, mapMalwareBazaarRecord } from './lib/malwarebazaar.js';
import { updateMalwareBazaarObservableBySource } from './importer.js';

// Scripted mock — replays queries by first-match on the match() predicate.
// importSideEffect swallows errors, so all expected queries must be handled
// or the reactivation silently won't happen and assertions will fail.
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

function malwareEntry(overrides = {}) {
  return {
    ...mapMalwareBazaarRecord({
      first_seen_utc: '2026-06-28 04:00:01',
      sha256_hash: 'a'.repeat(64),
      md5_hash: 'b'.repeat(32),
      sha1_hash: 'c'.repeat(40),
      signature: 'ExampleFamily',
      file_type: 'exe',
      mime_type: 'application/x-dosexec',
      reporter: 'abuse_ch',
      tags: 'exe,malware',
      malwarebazaar_link: 'https://bazaar.abuse.ch/sample/' + 'a'.repeat(64) + '/'
    }),
    ...overrides
  };
}

const IOC_ITEM_ID = 'aaaaaaaa-0000-0000-0000-000000000002';
const MEMB_ID = 'bbbbbbbb-0000-0000-0000-000000000002';
const FEED_ID = 'cccccccc-0000-0000-0000-000000000002';

function expiredMembershipRow() {
  return {
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
  };
}

function reactivatedMembershipRow() {
  // Returned without policy_expires_at/expires_at so that applyMembershipComputedFields
  // sees no computed field changes (null policy + undefined fields → all equal → skips UPDATE).
  return {
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
  };
}

// Query sequence for unchanged + expired membership WITH explicit confidence (MalwareBazaar):
// Q2  FROM integration_feeds                     → feed row
// Q3  ioc_items by observable                   → found
// Q4  FROM threat_feed_expiration_policies       → no policy
// Q5  ioc_feed_memberships by ioc_item_id        → expired
// Q6  UPDATE ioc_feed_memberships reactivation   → sets status='active'
//     applyMembershipComputedFields              → no-op
// Q7  UPDATE ioc_feed_memberships explicit_conf  → confidence set
//     reactivated=true → recomputeIocGlobalStatus:
// Q8  ioc_items by id                            → status='expired'
// Q9  ioc_suppressions                           → none
// Q10 ioc_feed_memberships status select         → [{status:'active'}]
// Q11 MIN expires_at                             → null
// Q12 UPDATE ioc_items SET status='active'       → recomputed
function buildHandlers({ feedKey, feedId, observable, observableType, iocItemId }) {
  return [
    {
      match: (s) => s.includes('WITH existing AS'),
      result: () => ({ rowCount: 1, rows: [{ status: 'unchanged', public_id: 'pub-2' }] })
    },
    {
      match: (s) => s.includes('FROM ioc_items') && s.includes('source_name = $3') && s.includes('LIMIT 1'),
      result: () => ({
        rowCount: 1,
        rows: [{
          public_id: 'pub-2',
          note: 'unchanged-note',
          category: 'threat-intel',
          first_seen_at: new Date('2026-06-28T04:00:01Z'),
          last_seen_at: new Date('2026-06-28T04:00:01Z')
        }]
      })
    },
    {
      match: (s) => s.includes('FROM integration_feeds'),
      result: () => ({
        rows: [{ key: feedKey, feed_id: feedId, feed_update_mode: 'incremental', name: feedKey, feed_kind: 'builtin' }]
      })
    },
    {
      match: (s) => s.includes('FROM ioc_items') && s.includes('WHERE observable = '),
      result: () => ({ rows: [{ id: iocItemId, observable_type: observableType }] })
    },
    {
      match: (s) => s.includes('FROM threat_feed_expiration_policies'),
      result: () => ({ rows: [] })
    },
    {
      match: (s) => s.includes('FROM ioc_feed_memberships') && s.includes('WHERE ioc_item_id'),
      result: () => ({ rowCount: 1, rows: [expiredMembershipRow()] })
    },
    {
      match: (s) => s.includes('UPDATE ioc_feed_memberships') && s.includes('SET last_seen_in_feed'),
      result: () => ({ rowCount: 1, rows: [reactivatedMembershipRow()] })
    },
    {
      match: (s) => s.includes('SELECT * FROM ioc_feed_memberships WHERE id = $1'),
      result: () => ({ rows: [reactivatedMembershipRow()] })
    },
    {
      match: (s) => s.includes('UPDATE ioc_feed_memberships') && s.includes('policy_expires_at'),
      result: () => ({ rowCount: 0, rows: [] })
    },
    {
      // explicit_confidence UPDATE (fired because entry.confidence is 'high')
      match: (s) => s.includes('UPDATE ioc_feed_memberships') && s.includes('explicit_confidence'),
      result: () => ({ rowCount: 1, rows: [] })
    },
    {
      match: (s) => s.includes('FROM ioc_items') && s.includes('WHERE id = $1'),
      result: () => ({
        rows: [{
          id: iocItemId,
          observable,
          observable_type: observableType,
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
}

describe('built-in feed expired membership reactivation', () => {
  it('reactivates expired MalwareBazaar membership when unchanged IOC reappears in feed', async () => {
    const entry = malwareEntry();
    const client = makeScriptedClient(buildHandlers({
      feedKey: 'malwarebazaar-abusech',
      feedId: FEED_ID,
      observable: 'a'.repeat(64),
      observableType: 'sha256',
      iocItemId: IOC_ITEM_ID
    }));

    const result = await updateMalwareBazaarObservableBySource(
      client,
      entry,
      'MalwareBazaar:abuse.ch',
      buildMalwareBazaarNote(entry),
      entry.category || 'malware'
    );

    // ioc_items NOT updated (unchanged metadata → result.status still 'unchanged')
    assert.equal(result.status, 'unchanged', 'function must report unchanged (ioc_items not updated)');

    // Membership WAS reactivated
    assert.ok(
      client.calls.some((c) => c.sql.includes('UPDATE ioc_feed_memberships') && c.sql.includes('SET last_seen_in_feed')),
      'expired membership must be reactivated via UPDATE ioc_feed_memberships'
    );

    // IOC global status recomputed after reactivation
    assert.ok(
      client.calls.some((c) => c.sql.includes('UPDATE ioc_items') && c.sql.includes('SET status = ')),
      'IOC global status must be recomputed after membership reactivation'
    );
  });
});
