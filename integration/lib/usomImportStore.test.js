import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createUsomImportStage,
  dropUsomImportStage,
  finalizeUsomImport,
  loadUsomLookupCache,
  saveUsomLookupCache,
  stageUsomEntries
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
      if (sql.includes('AS inserted') && sql.includes('AS updated')) {
        return { rows: [{ inserted: 1, updated: 2, duplicate: 3 }] };
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
      if (sql.includes('AS inserted') && sql.includes('AS updated')) {
        return { rows: [{ inserted: 0, updated: 1, duplicate: 2 }] };
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
      if (sql.includes('AS inserted') && sql.includes('AS updated')) {
        return { rows: [{ inserted: 0, updated: 1, duplicate: 2 }] };
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
