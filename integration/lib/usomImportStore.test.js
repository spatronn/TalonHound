import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createUsomImportStage,
  dropUsomImportStage,
  finalizeUsomImport,
  loadUsomLookupCache,
  saveUsomLookupCache,
  stageUsomEntries,
  markMissingMemberships
} from './usomImportStore.js';

test('bulk staging uses a temp table and ignores run-local duplicates', async () => {
  const calls = [];
  const client = {
    async query(sql, params = []) {
      calls.push({ sql, params });
      if (sql.includes('COUNT(*) FILTER (WHERE inserted)::int AS staged')) {
        return { rows: [{ staged: 1 }] };
      }
      return { rows: [], rowCount: 0 };
    }
  };

  await createUsomImportStage(client);
  const result = await stageUsomEntries(client, [
    {
      observable: 'example.com',
      observableType: 'domain',
      providerFingerprint: 'fingerprint-1',
      providerMetadata: { provider_record_id: 1, provider_date_utc: '2026-07-18T10:00:00.000Z' }
    },
    {
      observable: 'example.com',
      observableType: 'domain',
      providerFingerprint: 'fingerprint-2',
      providerMetadata: { provider_record_id: 2, provider_date_utc: '2026-07-17T10:00:00.000Z' }
    }
  ]);
  await dropUsomImportStage(client);

  assert.deepEqual(result, { staged: 1, duplicate: 1 });
  const bulkCall = calls.find((call) => call.sql.includes('jsonb_to_recordset'));
  assert.match(bulkCall.sql, /ON CONFLICT \(observable_type, observable\) DO UPDATE/);
  assert.match(bulkCall.sql, /provider_record_timestamp/);
  assert.equal(JSON.parse(bulkCall.params[0]).length, 1);
  assert.equal(JSON.parse(bulkCall.params[0])[0].provider_record_id, '1');
  assert.equal(calls.some((call) => /CREATE TEMP TABLE usom_import_stage/.test(call.sql)), true);
  assert.match(calls.at(-1).sql, /DROP TABLE IF EXISTS usom_import_stage/);
});

test('persistence starts a transaction and rolls back without checkpointing on failure', async () => {
  const calls = [];
  const client = {
    async query(sql, params = []) {
      calls.push({ sql, params });
      if (sql.includes('FROM integration_feeds')) throw new Error('database unavailable');
      return { rows: [], rowCount: 0 };
    }
  };

  await assert.rejects(finalizeUsomImport(client, {
    stats: {},
    seenAt: new Date(),
    statementTimeoutMs: 1_200_000,
    idleInTxTimeoutMs: 300_000
  }), /database unavailable/);
  assert.equal(calls[0].sql, 'BEGIN');
  assert.match(calls[1].sql, /set_config\('statement_timeout'/);
  assert.deepEqual(calls[1].params, ['1200000ms', '300000ms']);
  assert.equal(calls.at(-1).sql, 'ROLLBACK');
  assert.equal(calls.some((call) => call.sql.includes('integration_checkpoints')), false);
  assert.equal(calls.some((call) => call.sql.includes('usom_import_cursors')), false);
});

test('incremental success atomically merges seen rows, advances non-empty cursors and completes run', async () => {
  const calls = [];
  const client = {
    async query(sql, params = []) {
      calls.push({ sql, params });
      if (sql.includes('FROM integration_feeds')) {
        return {
          rows: [{
            integration_id: '7848ece4-ab84-44b9-a206-46826091c44c',
            key: 'usom-trcert',
            name: 'Siber Güvenlik Başkanlığı / USOM',
            default_confidence: 'medium',
            feed_update_mode: 'snapshot'
          }]
        };
      }
      if (sql.includes('AS created') && sql.includes('AS unchanged')) {
        return { rows: [{ created: 1, changed: 2, unchanged: 3, reactivated: 0 }] };
      }
      if (sql.includes('AS suppressed FROM removed')) return { rows: [{ suppressed: 0 }] };
      return { rows: [], rowCount: 0 };
    }
  };
  const result = await finalizeUsomImport(client, {
    stats: { skipped_invalid: 1, skipped_unsupported_ip_network: 1 },
    seenAt: new Date('2026-07-20T12:00:00.000Z'),
    mode: 'incremental',
    highwaters: {
      domain: { timestamp: '2026-07-20T11:00:00.000Z', providerId: '10' }
    },
    runId: 42,
    inRunDuplicates: 4,
    runDetails: { requested_mode: 'incremental' }
  });
  assert.equal(result.markedMissing, 0);
  assert.equal(calls.some((call) => call.sql.includes('SET missing_since = COALESCE')), false);
  assert.equal(calls.filter((call) => call.sql.includes('INSERT INTO usom_import_cursors')).length, 1);
  assert.equal(calls.some((call) => call.sql.includes('INSERT INTO usom_import_state')), false);
  const successIndex = calls.findIndex((call) => call.sql.includes('UPDATE integration_runs'));
  const commitIndex = calls.findIndex((call) => call.sql === 'COMMIT');
  assert.ok(successIndex > 0 && successIndex < commitIndex);
  assert.equal(result.metrics.records_duplicate, 7);
});

test('lookup cache persists rows in source state and Last-Modified in checkpoints', async () => {
  const calls = [];
  const client = {
    async query(sql, params = []) {
      calls.push({ sql, params });
      if (sql.includes('SELECT s.items_json')) {
        return {
          rows: [{
            items_json: {
              rows: [{ id: 'PH', en_title: 'Phishing' }],
              checked_at: '2026-07-20T10:00:00.000Z'
            },
            updated_at: '2026-07-20T10:00:00.000Z',
            last_cursor: 'Mon, 20 Jul 2026 10:00:00 GMT'
          }]
        };
      }
      return { rows: [], rowCount: 1 };
    }
  };
  const cache = await loadUsomLookupCache(client);
  assert.equal(cache.descriptions.rows[0].en_title, 'Phishing');
  await saveUsomLookupCache(client, 'descriptions', {
    rows: [{ id: 'PH' }],
    lastModified: 'Mon, 20 Jul 2026 11:00:00 GMT',
    checkedAt: new Date('2026-07-20T12:00:00.000Z')
  });
  assert.equal(calls.some((call) => call.sql.includes('integration_source_state')), true);
  assert.equal(calls.some((call) => call.sql.includes('integration_checkpoints')), true);
});

test('unchanged full snapshot still merges seen rows but skips absent reconciliation', async () => {
  const calls = [];
  const client = {
    async query(sql, params = []) {
      calls.push({ sql, params });
      if (sql.includes('FROM integration_feeds')) {
        return {
          rows: [{
            integration_id: '7848ece4-ab84-44b9-a206-46826091c44c',
            key: 'usom-trcert',
            name: 'USOM',
            default_confidence: 'medium'
          }]
        };
      }
      if (sql.includes('AS created') && sql.includes('AS unchanged')) {
        return { rows: [{ created: 0, changed: 1, unchanged: 2, reactivated: 0 }] };
      }
      if (sql.includes('AS suppressed FROM removed')) return { rows: [{ suppressed: 0 }] };
      return { rows: [], rowCount: 0 };
    }
  };
  const result = await finalizeUsomImport(client, {
    stats: {},
    mode: 'full_reconciliation',
    snapshotHash: 'same-hash',
    priorSnapshotHash: 'same-hash',
    highwaters: {}
  });
  assert.equal(result.snapshotUnchanged, true);
  assert.equal(result.markedMissing, 0);
  assert.equal(calls.some((call) => call.sql.includes('SELECT COUNT(*)::int AS count FROM usom_import_stage')), false);
  assert.equal(calls.some((call) => call.sql.includes('INSERT INTO usom_import_state')), true);
  assert.equal(calls.some((call) => call.sql.includes('INSERT INTO ioc_feed_memberships')), true);
});

test('unstable full pagination merges seen rows without absence reconciliation or full-state success', async () => {
  const calls = [];
  const client = {
    async query(sql, params = []) {
      calls.push({ sql, params });
      if (sql.includes('FROM integration_feeds')) {
        return {
          rows: [{
            integration_id: '7848ece4-ab84-44b9-a206-46826091c44c',
            key: 'usom-trcert',
            name: 'USOM',
            default_confidence: 'medium'
          }]
        };
      }
      if (sql.includes('AS created') && sql.includes('AS unchanged')) {
        return { rows: [{ created: 0, changed: 1, unchanged: 2, reactivated: 0 }] };
      }
      if (sql.includes('AS suppressed FROM removed')) return { rows: [{ suppressed: 0 }] };
      return { rows: [], rowCount: 0 };
    }
  };
  const result = await finalizeUsomImport(client, {
    stats: {},
    mode: 'full_reconciliation',
    snapshotHash: 'unstable-hash',
    snapshotStable: false,
    highwaters: {}
  });
  assert.equal(result.markedMissing, 0);
  assert.equal(result.runDetails.reconciliation_complete, false);
  assert.equal(result.runDetails.absent_reconciliation_skip_reason, 'pagination_changed');
  assert.equal(calls.some((call) => call.sql.includes('SELECT COUNT(*)::int AS count FROM usom_import_stage')), false);
  assert.equal(calls.some((call) => call.sql.includes('INSERT INTO usom_import_state')), false);
});

test('markMissingMemberships updates across multiple id-keyset batches', async () => {
  const feedId = '11111111-1111-1111-1111-111111111111';
  const seenAt = new Date('2026-08-01T00:00:00.000Z');
  // Simulate 5 matching membership ids for domain; batchSize=2 => 3 UPDATE loops.
  const domainIds = [10, 20, 30, 40, 50];
  let cursor = 0;
  const updateCalls = [];

  const client = {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('SELECT COUNT(*)::int AS count FROM usom_import_stage')) {
        return { rows: [{ count: 1 }] };
      }
      if (s.includes('FROM threat_feed_expiration_policies')) {
        const obsType = params[1];
        if (obsType === 'domain') {
          return {
            rows: [{
              feed_id: feedId,
              observable_type: 'domain',
              enabled: true,
              expiration_mode: 'missing_from_feed_ttl',
              grace_days: 7,
              ttl_days: 7
            }]
          };
        }
        return { rows: [] };
      }
      if (s.includes('FROM integration_feed_expiration_type_policies')) {
        return { rows: [] };
      }
      if (s.includes('AS newly_missing')) {
        return { rows: [{ newly_missing: 3 }] };
      }
      if (s.includes('WITH doomed AS') && s.includes('UPDATE ioc_feed_memberships')) {
        updateCalls.push([...params]);
        const afterId = Number(params[4]);
        const limit = Number(params[5]);
        const batch = domainIds.filter((id) => id > afterId).slice(0, limit);
        cursor += batch.length;
        return { rowCount: batch.length, rows: batch.map((id) => ({ id })) };
      }
      return { rows: [], rowCount: 0 };
    }
  };

  const result = await markMissingMemberships(client, feedId, seenAt, { batchSize: 2 });
  assert.equal(result.newlyMissing, 3);
  assert.equal(result.markedMissing, 5);
  assert.equal(updateCalls.length, 3); // 2 + 2 + 1
  assert.equal(updateCalls[0][4], 0);
  assert.equal(updateCalls[0][5], 2);
  assert.equal(updateCalls[1][4], 20); // after max of first batch
  assert.equal(updateCalls[2][4], 40);
  assert.equal(cursor, 5);
});
