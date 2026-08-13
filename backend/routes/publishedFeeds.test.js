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
        const formats = typeof params[5] === 'string' ? JSON.parse(params[5]) : (params[5] || ['txt']);
        const row = {
          id: nextId++,
          name: params[0],
          slug: params[1],
          description: params[2],
          enabled: params[3] ?? true,
          ioc_types: typeof params[4] === 'string' ? JSON.parse(params[4]) : params[4],
          formats,
          format: Array.isArray(formats) && formats.includes('txt')
            ? 'txt'
            : (Array.isArray(formats) && formats[0] ? formats[0] : 'txt'),
          min_confidence: params[6],
          include_feed_keys: params[7] ? JSON.parse(params[7]) : null,
          include_tags: params[8] ? JSON.parse(params[8]) : null,
          exclude_tags: params[9] ? JSON.parse(params[9]) : null,
          exclude_false_positive: params[10] ?? true,
          exclude_expired: params[11] ?? true,
          time_window: params[12],
          max_items: params[13],
          refresh_interval_minutes: params[14] ?? 15,
          filter_mode: params[15] ?? 'basic',
          advanced_query: params[16] ?? null,
          include_source_metadata: params[17] ?? true,
          include_classification: params[18] ?? true,
          include_enrichment: params[19] ?? false,
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
        // Reflect the SET columns present in this PATCH onto the stored row. The route
        // emits `col = $n[::cast]` in field order after the id ($1); map each back.
        const assignments = [...s.matchAll(/(\w+)\s*=\s*\$(\d+)/g)];
        for (const [, col, idx] of assignments) {
          const val = params[Number(idx) - 1];
          if (col === 'updated_at') continue;
          if (col === 'ioc_types' || col === 'include_feed_keys' || col === 'include_tags' || col === 'exclude_tags' || col === 'formats') {
            row[col] = typeof val === 'string' ? JSON.parse(val) : val;
            if (col === 'formats' && Array.isArray(row.formats)) {
              row.format = row.formats.includes('txt') ? 'txt' : (row.formats[0] || 'txt');
            }
          } else {
            row[col] = val;
          }
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

  it('treats a feed with no filter_mode as basic on read', async () => {
    const pool = createMockPool();
    const app = makeApp(pool);
    const created = await req(app, 'POST', '/api/published-feeds', {
      name: 'Legacy', ioc_types: ['ip'], time_window: 'all'
    });
    assert.equal(created.body.feed.filter_mode, 'basic');
    assert.equal(created.body.feed.advanced_query, null);
  });

  it('creates an Advanced Query feed with a valid query (ioc_types not required)', async () => {
    const pool = createMockPool();
    const app = makeApp(pool);
    const res = await req(app, 'POST', '/api/published-feeds', {
      name: 'Adv',
      filter_mode: 'query',
      advanced_query: 'source equals "MalwareBazaar" AND type equals "domain"'
      // no ioc_types provided on purpose
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.feed.filter_mode, 'query');
    // Stored query is the canonical/normalized form from the shared parser.
    assert.match(res.body.feed.advanced_query, /source equals "MalwareBazaar"/);
    assert.match(res.body.feed.advanced_query, /type equals "domain"/);
    // A valid non-empty ioc_types default is still persisted for the DB constraint.
    assert.ok(Array.isArray(res.body.feed.ioc_types) && res.body.feed.ioc_types.length);
  });

  it('rejects an Advanced Query feed with invalid syntax', async () => {
    const pool = createMockPool();
    const app = makeApp(pool);
    const badSyntax = await req(app, 'POST', '/api/published-feeds', {
      name: 'Bad', filter_mode: 'query', advanced_query: 'source == bogus ('
    });
    assert.equal(badSyntax.status, 400);

    const badField = await req(app, 'POST', '/api/published-feeds', {
      name: 'Bad2', filter_mode: 'query', advanced_query: 'not_a_field equals "x"'
    });
    assert.equal(badField.status, 400);

    const empty = await req(app, 'POST', '/api/published-feeds', {
      name: 'Bad3', filter_mode: 'query', advanced_query: '   '
    });
    assert.equal(empty.status, 400);
    assert.match(empty.body.message, /required/i);
  });

  it('switches an existing basic feed to query mode and back via PATCH', async () => {
    const pool = createMockPool();
    const app = makeApp(pool);
    const created = await req(app, 'POST', '/api/published-feeds', {
      name: 'Switch', ioc_types: ['ip'], time_window: 'all'
    });
    const id = created.body.feed.id;

    const toQuery = await req(app, 'PATCH', `/api/published-feeds/${id}`, {
      filter_mode: 'query',
      advanced_query: 'ioc contains "example.com"'
    });
    assert.equal(toQuery.status, 200);
    assert.equal(toQuery.body.feed.filter_mode, 'query');
    assert.match(toQuery.body.feed.advanced_query, /example\.com/);
    // ioc_types is preserved (Basic values are not destroyed by the switch).
    assert.deepEqual(toQuery.body.feed.ioc_types, ['ip']);

    const backToBasic = await req(app, 'PATCH', `/api/published-feeds/${id}`, {
      filter_mode: 'basic'
    });
    assert.equal(backToBasic.status, 200);
    assert.equal(backToBasic.body.feed.filter_mode, 'basic');
    // The Advanced Query is cleared and inert once back in basic mode.
    assert.equal(backToBasic.body.feed.advanced_query, null);
  });

  it('rejects switching to query mode without a query', async () => {
    const pool = createMockPool();
    const app = makeApp(pool);
    const created = await req(app, 'POST', '/api/published-feeds', {
      name: 'NoQuery', ioc_types: ['ip'], time_window: 'all'
    });
    const id = created.body.feed.id;
    const res = await req(app, 'PATCH', `/api/published-feeds/${id}`, { filter_mode: 'query' });
    assert.equal(res.status, 400);
    assert.match(res.body.message, /required/i);
  });

  it('regenerate returns 409 generation_in_progress when lock is held', async () => {
    let released = 0;
    const client = {
      async query(sql) {
        if (String(sql).includes('pg_try_advisory_lock')) return { rows: [{ ok: false }] };
        throw new Error(`unexpected query: ${sql}`);
      },
      release() { released += 1; }
    };
    const pool = {
      ...createMockPool(),
      async connect() { return client; }
    };
    const app = makeApp(pool);
    const res = await req(app, 'POST', '/api/published-feeds/9/regenerate');
    assert.equal(res.status, 409);
    assert.equal(res.body.code, 'generation_in_progress');
    assert.equal(res.body.message, 'Generation already in progress');
    assert.equal(released, 1);
  });
});

describe('publishedFeeds output format API', () => {
  it('existing/legacy create defaults to txt with default include flags', async () => {
    const app = makeApp(createMockPool());
    const res = await req(app, 'POST', '/api/published-feeds', { name: 'Default', ioc_types: ['ip'] });
    assert.equal(res.status, 201);
    assert.deepEqual(res.body.feed.formats, ['txt']);
    assert.equal(res.body.feed.format, 'txt');
    assert.equal(res.body.feed.include_source_metadata, true);
    assert.equal(res.body.feed.include_classification, true);
    assert.equal(res.body.feed.include_enrichment, false);
  });

  it('creates a JSON feed and persists include flags', async () => {
    const app = makeApp(createMockPool());
    const res = await req(app, 'POST', '/api/published-feeds', {
      name: 'JSON Feed', ioc_types: ['domain'],
      output_format: 'json', include_enrichment: true, include_classification: false
    });
    assert.equal(res.status, 201);
    assert.deepEqual(res.body.feed.formats, ['json']);
    assert.equal(res.body.feed.format, 'json');
    assert.equal(res.body.feed.include_enrichment, true);
    assert.equal(res.body.feed.include_classification, false);
    assert.equal(res.body.feed.include_source_metadata, true);
  });

  it('creates a dual-format feed via formats[]', async () => {
    const app = makeApp(createMockPool());
    const res = await req(app, 'POST', '/api/published-feeds', {
      name: 'Dual', ioc_types: ['ip'], formats: ['json', 'txt']
    });
    assert.equal(res.status, 201);
    assert.deepEqual(res.body.feed.formats, ['txt', 'json']);
    assert.equal(res.body.feed.format, 'txt');
  });

  it('creates a STIX feed via formats[]', async () => {
    const app = makeApp(createMockPool());
    const res = await req(app, 'POST', '/api/published-feeds', {
      name: 'STIX', ioc_types: ['ip'], formats: ['stix']
    });
    assert.equal(res.status, 201);
    assert.deepEqual(res.body.feed.formats, ['stix']);
    assert.equal(res.body.feed.format, 'stix');
  });

  it('rejects an unknown output_format with 400', async () => {
    const app = makeApp(createMockPool());
    const res = await req(app, 'POST', '/api/published-feeds', {
      name: 'Bad', ioc_types: ['ip'], output_format: 'xml'
    });
    assert.equal(res.status, 400);
    assert.match(res.body.message, /output_format/);
  });

  it('rejects empty formats with 400', async () => {
    const app = makeApp(createMockPool());
    const res = await req(app, 'POST', '/api/published-feeds', {
      name: 'Bad', ioc_types: ['ip'], formats: []
    });
    assert.equal(res.status, 400);
    assert.match(res.body.message, /formats/);
  });

  it('rejects a non-boolean include flag with 400', async () => {
    const app = makeApp(createMockPool());
    const res = await req(app, 'POST', '/api/published-feeds', {
      name: 'Bad', ioc_types: ['ip'], output_format: 'json', include_enrichment: 'yes'
    });
    assert.equal(res.status, 400);
    assert.match(res.body.message, /include_enrichment must be a boolean/);
  });

  it('updates TXT -> JSON and back to TXT without corrupting config', async () => {
    const pool = createMockPool();
    const app = makeApp(pool);
    const created = await req(app, 'POST', '/api/published-feeds', { name: 'Flip', ioc_types: ['ip'] });
    const id = created.body.feed.id;
    assert.equal(created.body.feed.format, 'txt');

    const toJson = await req(app, 'PATCH', `/api/published-feeds/${id}`, {
      output_format: 'json', include_source_metadata: false
    });
    assert.equal(toJson.status, 200);
    assert.deepEqual(toJson.body.feed.formats, ['json']);
    assert.equal(toJson.body.feed.format, 'json');
    assert.equal(toJson.body.feed.include_source_metadata, false);
    assert.deepEqual(toJson.body.feed.ioc_types, ['ip']);

    const toTxt = await req(app, 'PATCH', `/api/published-feeds/${id}`, { output_format: 'txt' });
    assert.equal(toTxt.status, 200);
    assert.deepEqual(toTxt.body.feed.formats, ['txt']);
    assert.equal(toTxt.body.feed.format, 'txt');
    // Saved JSON include config is preserved even while serving as TXT.
    assert.equal(toTxt.body.feed.include_source_metadata, false);
  });

  it('accepts the legacy `format` field alias on create', async () => {
    const app = makeApp(createMockPool());
    const res = await req(app, 'POST', '/api/published-feeds', { name: 'Alias', ioc_types: ['ip'], format: 'json' });
    assert.equal(res.status, 201);
    assert.deepEqual(res.body.feed.formats, ['json']);
    assert.equal(res.body.feed.format, 'json');
  });
});
