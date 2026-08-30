import test from 'node:test';
import assert from 'node:assert/strict';
import { finalizeUsomImport } from './usomImportStore.js';

const FEED_ID = '7848ece4-ab84-44b9-a206-46826091c44c';
const SEEN_AT = new Date('2026-07-20T19:48:00.000Z');

function makeClient(classification = { created: 0, changed: 0, unchanged: 1, reactivated: 0 }) {
  const calls = [];
  const client = {
    calls,
    async query(sql, params = []) {
      calls.push({ sql, params });
      if (sql.includes('FROM integration_feeds')) {
        return {
          rows: [{
            integration_id: FEED_ID,
            key: 'usom-trcert',
            name: 'USOM',
            default_confidence: 'medium',
            feed_update_mode: 'snapshot'
          }]
        };
      }
      if (sql.includes('AS created') && sql.includes('AS unchanged')) {
        return { rows: [classification] };
      }
      if (sql.includes('AS suppressed FROM removed')) return { rows: [{ suppressed: 0 }] };
      if (sql.includes('threat_feed_expiration_policies')) {
        return { rows: [{ enabled: false, expiration_mode: 'never', ttl_days: 30, grace_days: 7 }] };
      }
      if (sql.includes(`COUNT(*)::int AS count FROM usom_import_stage`)) {
        return { rows: [{ count: 0 }] };
      }
      return { rows: [], rowCount: 0 };
    }
  };
  return client;
}

test('finalize builds canonical stage table once before classify and again after insert', async () => {
  const client = makeClient();
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'incremental' });

  const canonicalCreates = client.calls.filter((c) => c.sql.includes('CREATE TEMP TABLE usom_stage_canonical'));
  assert.equal(canonicalCreates.length, 2, 'canonical mapping is built before classify and refreshed after insert');

  const lateralJoins = client.calls.filter((c) => /JOIN LATERAL/i.test(c.sql));
  assert.equal(lateralJoins.length, 0, 'finalize path must not use per-row LATERAL IOC lookups');
});

test('refreshGlobalIocStatus uses one grouped membership_state pass', async () => {
  const client = makeClient();
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'incremental' });

  const refresh = client.calls.find((c) => c.sql.includes('membership_state AS'));
  assert.ok(refresh, 'refreshGlobalIocStatus must run');
  assert.match(refresh.sql, /GROUP BY t\.observable_type, t\.observable/);
  assert.equal(/FROM touched t[\s\S]*EXISTS \(/i.test(refresh.sql), false,
    'must not use per-identity correlated EXISTS subqueries');
});

test('membership upsert reads from canonical stage table', async () => {
  const client = makeClient({ created: 0, changed: 0, unchanged: 2, reactivated: 0 });
  await finalizeUsomImport(client, { stats: {}, seenAt: SEEN_AT, mode: 'incremental' });

  const upsert = client.calls.find((c) => c.sql.includes('INSERT INTO ioc_feed_memberships'));
  assert.ok(upsert);
  assert.match(upsert.sql, /FROM usom_stage_canonical c/);
  assert.match(upsert.sql, /WHERE c\.ioc_item_id IS NOT NULL/);
});
