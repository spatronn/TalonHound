import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerPublicFeedRoutes } from './publicFeeds.js';
import { hashApiKey, generatePublishedFeedApiKey } from '../lib/publishedFeedApiKey.js';
import { hashFeedAccessToken } from '../lib/feedAccessToken.js';

function baseKey(over = {}) {
  return {
    id: 1, token_hash: 'x', key_type: 'published_feed', enabled: true,
    revoked_at: null, deleted_at: null, expires_at: null, feed_id: null, ...over
  };
}

function snapshotRow(feedId) {
  return {
    id: feedId * 10, content: `1.1.1.${feedId}\n2.2.2.${feedId}`, content_hash: `h${feedId}`,
    item_count: 2, generated_at: new Date().toISOString(),
    params: { ioc_type: 'ip', window: 'all' }
  };
}

function createMockPool({ keys = [], feeds = [] }) {
  return {
    async query(sql, params = []) {
      const s = String(sql);

      if (s.includes('FROM published_feed_access_keys') && s.includes('key_type = $2')) {
        // The pull endpoint filters out soft-deleted keys in SQL.
        const row = keys.find((k) => k.token_hash === params[0] && k.key_type === params[1] && !k.deleted_at);
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }
      // legacy join lookup (also excludes soft-deleted keys)
      if (s.includes('FROM published_feed_access_keys k') && s.includes('JOIN published_feeds')) {
        const row = keys.find((k) => k.token_hash === params[0] && !k.deleted_at);
        if (!row) return { rows: [], rowCount: 0 };
        const feed = feeds.find((f) => f.id === row.feed_id);
        return {
          rows: [{
            ...row, feed_id: row.feed_id, feed_enabled: feed?.enabled ?? false,
            ioc_type: feed?.ioc_type, time_window: feed?.time_window, max_items: feed?.max_items
          }],
          rowCount: 1
        };
      }
      if (s.includes('FROM published_feeds WHERE slug = $1')) {
        const feed = feeds.find((f) => f.slug === params[0]);
        return { rows: feed ? [feed] : [], rowCount: feed ? 1 : 0 };
      }
      if (s.includes('FROM published_feed_snapshots')) {
        const feedId = params[0];
        const feed = feeds.find((f) => f.id === feedId);
        return { rows: feed ? [snapshotRow(feedId)] : [], rowCount: feed ? 1 : 0 };
      }
      if (s.includes('UPDATE published_feed_access_keys')) return { rows: [], rowCount: 1 };
      throw new Error('unexpected SQL: ' + s.slice(0, 80));
    }
  };
}

function makeApp(pool) {
  const app = express();
  registerPublicFeedRoutes(app, pool);
  // Sentinel standing in for the admin/session feed-config route.
  app.get('/api/published-feeds/:slug', (_req, res) => res.status(200).send('ADMIN'));
  return app;
}

async function get(app, path) {
  const { createServer } = await import('node:http');
  const server = createServer(app);
  await new Promise((r) => server.listen(0, r));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`);
    return { status: res.status, text: await res.text() };
  } finally {
    server.close();
  }
}

const FEEDS = [
  { id: 1, slug: 'malware-domains', enabled: true, ioc_type: 'ip', time_window: 'all', max_items: null },
  { id: 2, slug: 'phishing-urls', enabled: true, ioc_type: 'ip', time_window: 'all', max_items: null }
];

test('valid Published Feed key pulls a feed by slug', async () => {
  const raw = generatePublishedFeedApiKey();
  const keys = [baseKey({ token_hash: hashApiKey(raw) })];
  const app = makeApp(createMockPool({ keys, feeds: FEEDS }));
  const res = await get(app, `/api/published-feeds/malware-domains?api_key=${raw}`);
  assert.equal(res.status, 200);
  assert.match(res.text, /1\.1\.1\.1/);
});

test('the same key can pull a different feed (no per-feed binding)', async () => {
  const raw = generatePublishedFeedApiKey();
  const keys = [baseKey({ token_hash: hashApiKey(raw) })];
  const app = makeApp(createMockPool({ keys, feeds: FEEDS }));
  const res = await get(app, `/api/published-feeds/phishing-urls?api_key=${raw}`);
  assert.equal(res.status, 200);
  assert.match(res.text, /1\.1\.1\.2/);
});

test('a legacy feed_access key is rejected on the new endpoint', async () => {
  const raw = 'legacy-token-value';
  const keys = [baseKey({ token_hash: hashFeedAccessToken(raw), key_type: 'feed_access', feed_id: 1 })];
  const app = makeApp(createMockPool({ keys, feeds: FEEDS }));
  const res = await get(app, `/api/published-feeds/malware-domains?api_key=${raw}`);
  assert.equal(res.status, 401);
});

test('revoked / expired / disabled keys are rejected', async () => {
  for (const over of [{ revoked_at: new Date().toISOString() }, { expires_at: new Date(Date.now() - 1000).toISOString() }, { enabled: false }]) {
    const raw = generatePublishedFeedApiKey();
    const keys = [baseKey({ token_hash: hashApiKey(raw), ...over })];
    const app = makeApp(createMockPool({ keys, feeds: FEEDS }));
    const res = await get(app, `/api/published-feeds/malware-domains?api_key=${raw}`);
    assert.equal(res.status, 403);
  }
});

test('a soft-deleted key is rejected (treated as unknown)', async () => {
  const raw = generatePublishedFeedApiKey();
  const keys = [baseKey({ token_hash: hashApiKey(raw), deleted_at: new Date().toISOString() })];
  const app = makeApp(createMockPool({ keys, feeds: FEEDS }));
  const res = await get(app, `/api/published-feeds/malware-domains?api_key=${raw}`);
  assert.equal(res.status, 401);
});

test('a soft-deleted legacy key is rejected on the legacy endpoint', async () => {
  const raw = 'legacy-token-value';
  const keys = [baseKey({
    token_hash: hashFeedAccessToken(raw), key_type: 'feed_access', feed_id: 1,
    deleted_at: new Date().toISOString()
  })];
  const app = makeApp(createMockPool({ keys, feeds: FEEDS }));
  const res = await get(app, '/public/feeds/legacy-token-value/feed.txt');
  assert.equal(res.status, 404);
});

test('missing api_key falls through to the admin route', async () => {
  const app = makeApp(createMockPool({ keys: [], feeds: FEEDS }));
  const res = await get(app, '/api/published-feeds/malware-domains');
  assert.equal(res.status, 200);
  assert.equal(res.text, 'ADMIN');
});

test('an invalid api_key is rejected', async () => {
  const app = makeApp(createMockPool({ keys: [], feeds: FEEDS }));
  const res = await get(app, '/api/published-feeds/malware-domains?api_key=th_pf_nope');
  assert.equal(res.status, 401);
});

test('unknown slug returns 404 for a valid key', async () => {
  const raw = generatePublishedFeedApiKey();
  const keys = [baseKey({ token_hash: hashApiKey(raw) })];
  const app = makeApp(createMockPool({ keys, feeds: FEEDS }));
  const res = await get(app, `/api/published-feeds/does-not-exist?api_key=${raw}`);
  assert.equal(res.status, 404);
});
