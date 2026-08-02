import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerPublishedFeedRoutes } from './publishedFeeds.js';

/**
 * Lightweight validation coverage for create/update ioc_types handling.
 * DB writes are mocked; we assert HTTP status + message for invalid payloads
 * and that valid multi-type creates bind JSON arrays.
 */
function createMockPool(store = { feeds: [] }) {
  let nextId = 1;
  return {
    store,
    async query(sql, params = []) {
      const s = String(sql).replace(/\s+/g, ' ').trim();
      if (s.includes('SELECT slug FROM published_feeds')) {
        return { rows: store.feeds.map((f) => ({ slug: f.slug })) };
      }
      if (s.startsWith('INSERT INTO published_feeds')) {
        const row = {
          id: nextId++,
          name: params[0],
          slug: params[1],
          description: params[2],
          enabled: params[3] ?? true,
          ioc_types: typeof params[4] === 'string' ? JSON.parse(params[4]) : params[4],
          format: params[5] || 'txt',
          min_confidence: params[6],
          include_feed_keys: params[7] ? JSON.parse(params[7]) : null,
          include_tags: params[8] ? JSON.parse(params[8]) : null,
          exclude_tags: params[9] ? JSON.parse(params[9]) : null,
          exclude_false_positive: params[10] ?? true,
          exclude_expired: params[11] ?? true,
          time_window: params[12],
          max_items: params[13],
          refresh_interval_minutes: params[14] ?? 15,
          last_generated_at: null,
          last_status: null,
          last_error: null,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        store.feeds.push(row);
        return { rows: [row] };
      }
      if (s.includes('SELECT * FROM published_feeds WHERE id')) {
        const row = store.feeds.find((f) => f.id === Number(params[0]));
        return { rows: row ? [row] : [] };
      }
      if (s.startsWith('UPDATE published_feeds SET')) {
        const id = Number(params[0]);
        const row = store.feeds.find((f) => f.id === id);
        if (!row) return { rows: [] };
        // PATCH only sets ioc_types in these tests (plus updated_at).
        if (s.includes('ioc_types')) {
          row.ioc_types = typeof params[1] === 'string' ? JSON.parse(params[1]) : params[1];
        }
        row.updated_at = new Date().toISOString();
        return { rows: [row] };
      }
      if (s.includes('FROM published_feed_snapshots')) return { rows: [] };
      if (s.includes('FROM integration_feeds') || s.includes('FROM custom_threat_feeds') || s.includes('FROM ioc_sources')) {
        return { rows: [] };
      }
      throw new Error(`Unexpected query: ${s.slice(0, 120)}`);
    }
  };
}

function makeApp(pool) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { id: 1, role: 'admin', email: 'admin@test' };
    next();
  });
  registerPublishedFeedRoutes(app, pool, { auditSuccess() {} });
  return app;
}

async function req(app, method, path, body) {
  const { createServer } = await import('node:http');
  const server = createServer(app);
  await new Promise((r) => server.listen(0, r));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: body ? { 'content-type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* plain */ }
    return { status: res.status, body: json, text };
  } finally {
    server.close();
  }
}

describe('publishedFeeds ioc_types API', () => {
  it('creates a single-type feed and returns ioc_types array', async () => {
    const pool = createMockPool();
    const app = makeApp(pool);
    const res = await req(app, 'POST', '/api/published-feeds', {
      name: 'IP Blocklist',
      ioc_types: ['ip'],
      time_window: 'all'
    });
    assert.equal(res.status, 201);
    assert.deepEqual(res.body.feed.ioc_types, ['ip']);
    assert.equal(res.body.feed.ioc_type, undefined);
  });

  it('creates and updates multi-type feeds', async () => {
    const pool = createMockPool();
    const app = makeApp(pool);
    const created = await req(app, 'POST', '/api/published-feeds', {
      name: 'Mixed',
      ioc_types: ['domain', 'url'],
      time_window: '7d'
    });
    assert.equal(created.status, 201);
    assert.deepEqual(created.body.feed.ioc_types, ['domain', 'url']);

    const id = created.body.feed.id;
    const updated = await req(app, 'PATCH', `/api/published-feeds/${id}`, {
      ioc_types: ['ip', 'domain', 'url', 'hash']
    });
    assert.equal(updated.status, 200);
    assert.deepEqual(updated.body.feed.ioc_types, ['ip', 'domain', 'url', 'hash']);
  });

  it('accepts legacy scalar ioc_type on create', async () => {
    const pool = createMockPool();
    const app = makeApp(pool);
    const res = await req(app, 'POST', '/api/published-feeds', {
      name: 'Legacy',
      ioc_type: 'hash',
      time_window: 'all'
    });
    assert.equal(res.status, 201);
    assert.deepEqual(res.body.feed.ioc_types, ['hash']);
  });

  it('rejects empty, duplicate, and unknown types', async () => {
    const pool = createMockPool();
    const app = makeApp(pool);
    const empty = await req(app, 'POST', '/api/published-feeds', { name: 'X', ioc_types: [] });
    assert.equal(empty.status, 400);
    assert.match(empty.body.message, /at least one/i);

    const dup = await req(app, 'POST', '/api/published-feeds', { name: 'X', ioc_types: ['ip', 'ip'] });
    assert.equal(dup.status, 400);
    assert.match(dup.body.message, /duplicates/i);

    const bad = await req(app, 'POST', '/api/published-feeds', { name: 'X', ioc_types: ['mutex'] });
    assert.equal(bad.status, 400);
    assert.match(bad.body.message, /ip, domain, url, or hash/);
  });
});
