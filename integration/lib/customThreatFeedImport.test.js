import test from 'node:test';
import assert from 'node:assert/strict';
import { runCustomThreatFeedImport } from './customThreatFeedImport.js';

function makePool({ feed, client = null }) {
  let connectCount = 0;
  const queries = [];
  const pool = {
    async query(sql, params = []) {
      queries.push({ sql: String(sql), params });
      if (String(sql).includes('FROM custom_threat_feeds c')) {
        return { rows: feed ? [feed] : [], rowCount: feed ? 1 : 0 };
      }
      return { rows: [], rowCount: 0 };
    },
    async connect() {
      connectCount += 1;
      return client || {
        query: async () => ({ rows: [], rowCount: 0 }),
        release() {}
      };
    },
    get connectCount() {
      return connectCount;
    },
    queries
  };
  return pool;
}

const completedRunOnceFeed = {
  id: '11111111-1111-1111-1111-111111111111',
  feed_id: '22222222-2222-2222-2222-222222222222',
  integration_feed_id: '22222222-2222-2222-2222-222222222222',
  integration_key: 'ctf-abc123',
  feed_name: 'Completed Run Once Feed',
  url: 'https://ti.example.com/feed.txt',
  url_host: 'ti.example.com',
  format: 'txt',
  ioc_type_mode: 'auto',
  fixed_ioc_type: null,
  timeout_ms: 30000,
  default_confidence: 'medium',
  deactivated_at: null,
  integration_active: true,
  schedule: 'run_once',
  last_success_at: '2026-06-28T10:00:00.000Z'
};

test('run_once completed custom feed is hard-skipped for automatic scheduler trigger before sync execution', async () => {
  const pool = makePool({ feed: completedRunOnceFeed });

  const result = await runCustomThreatFeedImport(pool, {
    integrationKey: completedRunOnceFeed.integration_key,
    job: {
      id: 'auto-job-1',
      data: {
        integration_key: completedRunOnceFeed.integration_key,
        triggeredBy: 'scheduler'
      }
    }
  });

  assert.equal(result.skipped, true);
  assert.equal(result.reason, 'run_once_already_completed');
  assert.equal(pool.connectCount, 0, 'automatic completed run_once guard must return before opening sync client');
});

test('run_once completed custom feed still allows manual trigger', async () => {
  let syncStarted = false;
  const client = {
    async query(sql) {
      syncStarted = syncStarted || String(sql).includes('INSERT INTO custom_threat_feed_runs');
      throw new Error('manual sync reached execution path');
    },
    release() {}
  };
  const pool = makePool({ feed: completedRunOnceFeed, client });

  await assert.rejects(
    () => runCustomThreatFeedImport(pool, {
      integrationKey: completedRunOnceFeed.integration_key,
      triggeredBy: 'manual-ui:analyst',
      jobId: 'manual-job-1'
    }),
    /manual sync reached execution path/
  );
  assert.equal(pool.connectCount, 1);
  assert.equal(syncStarted, true);
});
