import test from 'node:test';
import assert from 'node:assert/strict';
import {
  archiveIntegrationFeed,
  computeReimportPossible,
  findActivePurgeJobForFeed,
  isBuiltInFeed,
  previewFeedDataPurge,
  purgeFeedData,
  restoreIntegrationFeed,
  validatePurgeConfirmName
} from './feedLifecycle.js';

function createMockClient(state) {
  return {
    async query(sql, params = []) {
      state.queries.push({ sql, params });
      if (typeof state.handler === 'function') {
        return state.handler(sql, params, state);
      }
      return { rows: [], rowCount: 0 };
    }
  };
}

test('isBuiltInFeed defaults to built_in', () => {
  assert.equal(isBuiltInFeed({ feed_kind: 'built_in' }), true);
  assert.equal(isBuiltInFeed({ feed_kind: 'custom' }), false);
});

test('previewFeedDataPurge returns 404 for unknown feed', async () => {
  const state = { queries: [], handler: () => ({ rows: [], rowCount: 0 }) };
  const client = createMockClient(state);
  const result = await previewFeedDataPurge(client, 'missing');
  assert.equal(result.ok, false);
  assert.equal(result.status, 404);
});

test('previewFeedDataPurge returns preview stats', async () => {
  const state = {
    queries: [],
    handler: (sql) => {
      if (sql.includes('FROM integration_feeds')) {
        return {
          rows: [{
            key: 'usom-trcert',
            integration_id: '11111111-1111-4111-8111-111111111111',
            name: 'USOM TR-CERT',
            active: false,
            feed_kind: 'built_in',
            archived_at: null
          }],
          rowCount: 1
        };
      }
      if (sql.includes('WITH feed_active')) {
        return {
          rows: [{
            active_memberships: 5,
            affected_iocs: 5,
            iocs_only_from_this_feed: 4,
            iocs_shared_with_other_sources: 1
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    }
  };
  const client = createMockClient(state);
  const result = await previewFeedDataPurge(client, 'usom-trcert');
  assert.equal(result.ok, true);
  assert.equal(result.preview.feed_name, 'USOM TR-CERT');
  assert.equal(result.preview.active_memberships, 5);
  assert.equal(result.preview.iocs_only_from_this_feed, 4);
  assert.equal(result.preview.will_preserve_history, true);
  assert.equal(result.preview.incidents_deleted, 0);
  assert.equal(result.preview.feed_enabled, false);
  assert.equal(result.preview.feed_archived, false);
  assert.equal(result.preview.reimport_possible, false);
});

test('computeReimportPossible is true only for enabled non-archived feeds', () => {
  assert.equal(computeReimportPossible({ active: true, archived_at: null }), true);
  assert.equal(computeReimportPossible({ active: false, archived_at: null }), false);
  assert.equal(computeReimportPossible({ active: true, archived_at: new Date().toISOString() }), false);
});

test('previewFeedDataPurge reports reimport_possible for enabled feed', async () => {
  const state = {
    queries: [],
    handler: (sql) => {
      if (sql.includes('FROM integration_feeds')) {
        return {
          rows: [{
            key: 'et-blockrules',
            integration_id: '11111111-1111-4111-8111-111111111111',
            name: 'Emerging Threats',
            active: true,
            feed_kind: 'built_in',
            archived_at: null
          }],
          rowCount: 1
        };
      }
      if (sql.includes('WITH feed_active')) {
        return {
          rows: [{
            active_memberships: 1,
            affected_iocs: 1,
            iocs_only_from_this_feed: 1,
            iocs_shared_with_other_sources: 0
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    }
  };
  const client = createMockClient(state);
  const result = await previewFeedDataPurge(client, 'et-blockrules');
  assert.equal(result.ok, true);
  assert.equal(result.preview.feed_enabled, true);
  assert.equal(result.preview.reimport_possible, true);
});

test('archiveIntegrationFeed rejects built-in feed', async () => {
  const state = {
    queries: [],
    handler: (sql) => {
      if (sql.includes('FROM integration_feeds')) {
        return {
          rows: [{
            key: 'usom-trcert',
            integration_id: '11111111-1111-4111-8111-111111111111',
            name: 'USOM TR-CERT',
            feed_kind: 'built_in',
            archived_at: null
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    }
  };
  const client = createMockClient(state);
  const result = await archiveIntegrationFeed(client, 'usom-trcert', { actor: { userId: 'u1', username: 'admin' } });
  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
});

test('archiveIntegrationFeed archives custom feed', async () => {
  const state = {
    queries: [],
    handler: (sql) => {
      if (sql.includes('FROM integration_feeds') && sql.includes('LIMIT 1')) {
        return {
          rows: [{
            key: 'custom-feed',
            integration_id: '22222222-2222-4222-8222-222222222222',
            name: 'Custom Feed',
            feed_kind: 'custom',
            archived_at: null
          }],
          rowCount: 1
        };
      }
      if (sql.startsWith('UPDATE integration_feeds')) {
        return {
          rows: [{
            key: 'custom-feed',
            integration_id: '22222222-2222-4222-8222-222222222222',
            name: 'Custom Feed',
            feed_kind: 'custom',
            active: false,
            archived_at: new Date().toISOString()
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    }
  };
  const client = createMockClient(state);
  const result = await archiveIntegrationFeed(client, 'custom-feed', { actor: { userId: 'u1', username: 'admin' } });
  assert.equal(result.ok, true);
  assert.equal(result.feed.feed_kind, 'custom');
  assert.equal(result.feed.active, false);
});

test('validatePurgeConfirmName requires exact trimmed match', () => {
  assert.equal(validatePurgeConfirmName('USOM TR-CERT', 'USOM TR-CERT'), true);
  assert.equal(validatePurgeConfirmName('USOM TR-CERT', ' USOM TR-CERT '), true);
  assert.equal(validatePurgeConfirmName('USOM TR-CERT', 'usom tr-cert'), false);
  assert.equal(validatePurgeConfirmName('USOM TR-CERT', 'USOM'), false);
});

test('findActivePurgeJobForFeed returns active purge job', async () => {
  const state = {
    queries: [],
    handler: (sql) => {
      if (sql.includes('integration_queue_jobs') && sql.includes('feed_data_purge')) {
        return { rows: [{ job_id: 'job-1', status: 'running' }], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    }
  };
  const client = createMockClient(state);
  const row = await findActivePurgeJobForFeed(client, 'usom-trcert');
  assert.equal(row?.job_id, 'job-1');
});

test('purgeFeedData soft-purges memberships without deleting incidents', async () => {
  const feedId = '11111111-1111-4111-8111-111111111111';
  let batchSelectCalls = 0;
  const state = {
    queries: [],
    handler: (sql, params) => {
      if (sql === 'BEGIN' || sql === 'COMMIT' || sql === 'ROLLBACK') {
        return { rows: [], rowCount: 0 };
      }
      if (sql.includes('FROM integration_feeds') && sql.includes('LIMIT 1')) {
        return {
          rows: [{
            key: 'usom-trcert',
            integration_id: feedId,
            name: 'USOM TR-CERT',
            active: false,
            feed_kind: 'built_in',
            archived_at: null
          }],
          rowCount: 1
        };
      }
      if (sql.includes('WITH feed_active')) {
        return {
          rows: [{
            active_memberships: 2,
            affected_iocs: 2,
            iocs_only_from_this_feed: 2,
            iocs_shared_with_other_sources: 0
          }],
          rowCount: 1
        };
      }
      if (sql.includes('FROM ioc_feed_memberships') && sql.includes("status = 'active'") && sql.includes('LIMIT')) {
        batchSelectCalls += 1;
        if (batchSelectCalls === 1) {
          return {
            rows: [
              { id: 1, ioc_item_id: 10, ioc_observable_type: 'ip' },
              { id: 2, ioc_item_id: 11, ioc_observable_type: 'domain' }
            ],
            rowCount: 2
          };
        }
        return { rows: [], rowCount: 0 };
      }
      if (sql.startsWith('UPDATE ioc_feed_memberships') && sql.includes("status = 'purged'")) {
        return {
          rows: [
            { id: 1, ioc_item_id: 10, ioc_observable_type: 'ip' },
            { id: 2, ioc_item_id: 11, ioc_observable_type: 'domain' }
          ],
          rowCount: 2
        };
      }
      if (sql.includes('FROM ioc_items') && sql.includes('SELECT status')) {
        return { rows: [{ status: 'active' }], rowCount: 1 };
      }
      if (sql.includes('FROM ioc_feed_memberships') && sql.includes('SELECT status')) {
        return { rows: [{ status: 'purged' }], rowCount: 1 };
      }
      if (sql.startsWith('UPDATE ioc_items')) {
        return { rows: [], rowCount: 1 };
      }
      return { rows: [], rowCount: 0 };
    }
  };
  const client = createMockClient(state);
  const result = await purgeFeedData(client, 'usom-trcert', {
    actor: { userId: 'u1', username: 'analyst1' },
    audit: null
  });
  assert.equal(result.ok, true);
  assert.equal(result.result.active_memberships_removed, 2);
  assert.equal(result.result.preserved_incidents, true);
  assert.equal(result.result.preserved_events, true);
  assert.ok(state.queries.some((q) => q.sql.includes("status = 'purged'")));
});

test('restoreIntegrationFeed clears archived_at', async () => {
  const state = {
    queries: [],
    handler: (sql) => {
      if (sql.includes('FROM integration_feeds') && sql.includes('LIMIT 1')) {
        return {
          rows: [{
            key: 'custom-feed',
            integration_id: '22222222-2222-4222-8222-222222222222',
            name: 'Custom Feed',
            feed_kind: 'custom',
            archived_at: new Date().toISOString()
          }],
          rowCount: 1
        };
      }
      if (sql.startsWith('UPDATE integration_feeds') && sql.includes('archived_at = NULL')) {
        return {
          rows: [{
            key: 'custom-feed',
            integration_id: '22222222-2222-4222-8222-222222222222',
            name: 'Custom Feed',
            feed_kind: 'custom',
            active: false,
            archived_at: null
          }],
          rowCount: 1
        };
      }
      return { rows: [], rowCount: 0 };
    }
  };
  const client = createMockClient(state);
  const result = await restoreIntegrationFeed(client, 'custom-feed');
  assert.equal(result.ok, true);
  assert.equal(result.feed.archived_at, null);
});
