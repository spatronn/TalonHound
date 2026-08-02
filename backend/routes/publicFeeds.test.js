import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerPublicFeedRoutes } from './publicFeeds.js';
import { hashApiKey, generatePublishedFeedApiKey } from '../lib/publishedFeedApiKey.js';
import { hashFeedAccessToken } from '../lib/feedAccessToken.js';
import { computeResponseEtag } from '../lib/feedFormatter.js';

function baseKey(over = {}) {
  return {
    id: 1, token_hash: 'x', key_type: 'published_feed', enabled: true,
    revoked_at: null, deleted_at: null, expires_at: null, feed_id: null, ...over
  };
}

function snapshotRow(feedId, over = {}) {
  return {
    id: feedId * 10,
    content: `1.1.1.${feedId}\n2.2.2.${feedId}\n`,
    content_hash: `h${feedId}`,
    content_bytes: `1.1.1.${feedId}\n2.2.2.${feedId}\n`.length,
    item_count: 2,
    generated_at: new Date('2026-08-01T12:00:00.000Z').toISOString(),
    params: { ioc_type: 'ip', window: 'all' },
    ...over
  };
}

/**
 * Mock pool that distinguishes metadata vs content snapshot queries and
 * records which paths ran.
 */
function createMockPool({ keys = [], feeds = [], snapshotsByFeedId = null, onSnapshotQuery = null }) {
  const queries = [];
  return {
    queries,
    async query(sql, params = []) {
      const s = String(sql);
      queries.push({ sql: s, params: [...params] });

      if (s.includes('FROM published_feed_access_keys') && s.includes('key_type = $2')) {
        const row = keys.find((k) => k.token_hash === params[0] && k.key_type === params[1] && !k.deleted_at);
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }
      if (s.includes('FROM published_feed_access_keys k') && s.includes('JOIN published_feeds')) {
        const row = keys.find((k) => k.token_hash === params[0] && !k.deleted_at);
        if (!row) return { rows: [], rowCount: 0 };
        const feed = feeds.find((f) => f.id === row.feed_id);
        return {
          rows: [{
            ...row, feed_id: row.feed_id, feed_enabled: feed?.enabled ?? false,
            ioc_types: feed?.ioc_types, time_window: feed?.time_window, max_items: feed?.max_items,
            feed_slug: feed?.slug
          }],
          rowCount: 1
        };
      }
      if (s.includes('FROM published_feeds WHERE slug = $1')) {
        const feed = feeds.find((f) => f.slug === params[0]);
        return { rows: feed ? [feed] : [], rowCount: feed ? 1 : 0 };
      }
      if (s.includes('FROM published_feed_snapshots')) {
        const kind = s.includes('octet_length(content)')
          ? 'meta'
          : (s.includes('content_hash = $2') ? 'content_by_id' : 'legacy_full');
        if (onSnapshotQuery) onSnapshotQuery(kind, params);

        if (kind === 'meta') {
          const feedId = params[0];
          const snap = snapshotsByFeedId?.(feedId) ?? (feeds.find((f) => f.id === feedId) ? snapshotRow(feedId) : null);
          if (!snap) return { rows: [], rowCount: 0 };
          const { content, ...meta } = snap;
          return { rows: [meta], rowCount: 1 };
        }
        if (kind === 'content_by_id') {
          const id = Number(params[0]);
          const hash = String(params[1]);
          for (const feed of feeds) {
            const snap = snapshotsByFeedId?.(feed.id) ?? snapshotRow(feed.id);
            if (snap && Number(snap.id) === id && String(snap.content_hash) === hash) {
              return { rows: [snap], rowCount: 1 };
            }
          }
          return { rows: [], rowCount: 0 };
        }
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
  app.get('/api/published-feeds/:slug', (_req, res) => res.status(200).send('ADMIN'));
  return app;
}

async function get(app, path, headers = {}) {
  const { createServer } = await import('node:http');
  const server = createServer(app);
  await new Promise((r) => server.listen(0, r));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, { headers });
    const text = await res.text();
    return {
      status: res.status,
      text,
      headers: {
        etag: res.headers.get('etag'),
        lastModified: res.headers.get('last-modified'),
        cacheControl: res.headers.get('cache-control')
      }
    };
  } finally {
    server.close();
  }
}

const FEEDS = [
  { id: 1, slug: 'malware-domains', enabled: true, ioc_types: ['ip'], time_window: 'all', max_items: null },
  { id: 2, slug: 'phishing-urls', enabled: true, ioc_types: ['ip'], time_window: 'all', max_items: null }
];

test('valid Published Feed key pulls a feed by slug', async () => {
  const raw = generatePublishedFeedApiKey();
  const keys = [baseKey({ token_hash: hashApiKey(raw) })];
  const kinds = [];
  const app = makeApp(createMockPool({
    keys,
    feeds: FEEDS,
    onSnapshotQuery: (kind) => kinds.push(kind)
  }));
  const res = await get(app, `/api/published-feeds/malware-domains?api_key=${raw}`);
  assert.equal(res.status, 200);
  assert.match(res.text, /1\.1\.1\.1/);
  assert.ok(kinds.includes('meta'));
  assert.ok(kinds.includes('content_by_id'));
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

test('If-None-Match returns 304 without loading snapshot content', async () => {
  const raw = generatePublishedFeedApiKey();
  const keys = [baseKey({ token_hash: hashApiKey(raw) })];
  const snap = snapshotRow(1);
  const kinds = [];
  const app = makeApp(createMockPool({
    keys,
    feeds: FEEDS,
    snapshotsByFeedId: () => snap,
    onSnapshotQuery: (kind) => kinds.push(kind)
  }));
  const etag = computeResponseEtag(snap.content_hash, 'ip', 'all', 'all');
  const res = await get(app, `/api/published-feeds/malware-domains?api_key=${raw}`, {
    'if-none-match': etag
  });
  assert.equal(res.status, 304);
  assert.equal(res.text, '');
  assert.deepEqual(kinds, ['meta']);
  assert.ok(!kinds.includes('content_by_id'));
});

test('If-Modified-Since returns 304 without loading snapshot content', async () => {
  const raw = generatePublishedFeedApiKey();
  const keys = [baseKey({ token_hash: hashApiKey(raw) })];
  const snap = snapshotRow(1);
  const kinds = [];
  const app = makeApp(createMockPool({
    keys,
    feeds: FEEDS,
    snapshotsByFeedId: () => snap,
    onSnapshotQuery: (kind) => kinds.push(kind)
  }));
  const ims = new Date(snap.generated_at).toUTCString();
  const res = await get(app, `/api/published-feeds/malware-domains?api_key=${raw}`, {
    'if-modified-since': ims
  });
  assert.equal(res.status, 304);
  assert.deepEqual(kinds, ['meta']);
});

test('200 request lazy-loads content after metadata', async () => {
  const raw = generatePublishedFeedApiKey();
  const keys = [baseKey({ token_hash: hashApiKey(raw) })];
  const kinds = [];
  const app = makeApp(createMockPool({
    keys,
    feeds: FEEDS,
    onSnapshotQuery: (kind) => kinds.push(kind)
  }));
  const res = await get(app, `/api/published-feeds/malware-domains?api_key=${raw}`);
  assert.equal(res.status, 200);
  assert.deepEqual(kinds, ['meta', 'content_by_id']);
  assert.ok(res.headers.etag);
  assert.ok(res.headers.lastModified);
});

test('content id+hash miss retries metadata once; exhausted race returns 503', async () => {
  const raw = generatePublishedFeedApiKey();
  const keys = [baseKey({ token_hash: hashApiKey(raw) })];
  const kinds = [];
  let metaCount = 0;
  const pool = {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM published_feed_access_keys') && s.includes('key_type = $2')) {
        return { rows: [keys[0]], rowCount: 1 };
      }
      if (s.includes('FROM published_feeds WHERE slug')) {
        return { rows: [FEEDS[0]], rowCount: 1 };
      }
      if (s.includes('UPDATE published_feed_access_keys')) return { rows: [], rowCount: 1 };
      if (s.includes('octet_length(content)')) {
        kinds.push('meta');
        metaCount += 1;
        return {
          rows: [{
            id: 10,
            content_hash: `hash-${metaCount}`,
            item_count: 1,
            generated_at: new Date('2026-08-01T12:00:00.000Z').toISOString(),
            params: { ioc_type: 'ip', window: 'all' },
            content_bytes: 4
          }],
          rowCount: 1
        };
      }
      if (s.includes('content_hash = $2')) {
        kinds.push('content_by_id');
        // Always miss — simulates continuous publish race / deleted row.
        return { rows: [], rowCount: 0 };
      }
      throw new Error('unexpected: ' + s.slice(0, 60));
    }
  };
  const app = makeApp(pool);
  const res = await get(app, `/api/published-feeds/malware-domains?api_key=${raw}`);
  assert.equal(res.status, 503);
  assert.deepEqual(kinds, ['meta', 'content_by_id', 'meta', 'content_by_id']);
});

test('content id+hash miss then consistent retry returns 200 with new body', async () => {
  const raw = generatePublishedFeedApiKey();
  const keys = [baseKey({ token_hash: hashApiKey(raw) })];
  const kinds = [];
  let metaCount = 0;
  const pool = {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM published_feed_access_keys') && s.includes('key_type = $2')) {
        return { rows: [keys[0]], rowCount: 1 };
      }
      if (s.includes('FROM published_feeds WHERE slug')) {
        return { rows: [FEEDS[0]], rowCount: 1 };
      }
      if (s.includes('UPDATE published_feed_access_keys')) return { rows: [], rowCount: 1 };
      if (s.includes('octet_length(content)')) {
        kinds.push('meta');
        metaCount += 1;
        return {
          rows: [{
            id: 10,
            content_hash: metaCount === 1 ? 'hash-old' : 'hash-new',
            item_count: 1,
            generated_at: new Date('2026-08-01T12:00:00.000Z').toISOString(),
            params: { ioc_type: 'ip', window: 'all' },
            content_bytes: 8
          }],
          rowCount: 1
        };
      }
      if (s.includes('content_hash = $2')) {
        kinds.push('content_by_id');
        if (params[1] === 'hash-old') return { rows: [], rowCount: 0 };
        return {
          rows: [{
            id: 10,
            content: 'fresh\n',
            content_hash: 'hash-new',
            item_count: 1,
            generated_at: new Date('2026-08-01T12:00:00.000Z').toISOString(),
            params: { ioc_type: 'ip', window: 'all' }
          }],
          rowCount: 1
        };
      }
      throw new Error('unexpected: ' + s.slice(0, 60));
    }
  };
  const app = makeApp(pool);
  const res = await get(app, `/api/published-feeds/malware-domains?api_key=${raw}`);
  assert.equal(res.status, 200);
  assert.equal(res.text, 'fresh\n');
  assert.equal(res.headers.etag, computeResponseEtag('hash-new', 'ip', 'all', 'all'));
  assert.deepEqual(kinds, ['meta', 'content_by_id', 'meta', 'content_by_id']);
});

test('legacy public endpoint also uses metadata 304 fast path', async () => {
  const raw = 'legacy-token-value';
  const keys = [baseKey({
    token_hash: hashFeedAccessToken(raw), key_type: 'feed_access', feed_id: 1
  })];
  const snap = snapshotRow(1);
  const kinds = [];
  const app = makeApp(createMockPool({
    keys,
    feeds: FEEDS,
    snapshotsByFeedId: () => snap,
    onSnapshotQuery: (kind) => kinds.push(kind)
  }));
  const etag = computeResponseEtag(snap.content_hash, 'ip', 'all', 'all');
  const res = await get(app, `/public/feeds/${raw}/feed.txt`, { 'if-none-match': etag });
  assert.equal(res.status, 304);
  assert.deepEqual(kinds, ['meta']);
});
