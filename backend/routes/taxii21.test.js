import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerTaxii21Routes } from './taxii21.js';
import { generateApiKeyForProfile, hashApiKey } from '../lib/publishedFeedApiKey.js';
import { ACCESS_PROFILE, API_SCOPE } from '../lib/apiKeyProfiles.js';
import { StixBundleWriter, indicatorFromPublishedItem } from '../lib/publishedFeedStix.js';
import { TAXII_CONTENT_TYPE } from '../lib/taxii21.js';

function stixBundle(slug, items) {
  const w = new StixBundleWriter({ slug });
  for (const item of items) w.addIndicator(indicatorFromPublishedItem(item));
  return w.finish();
}

const TS = { imported_at: '2026-08-01T12:00:00.000Z', first_seen_in_source: '2026-08-01T12:00:00.000Z' };

function baseKey(over = {}) {
  const plaintext = over.plaintext || generateApiKeyForProfile(ACCESS_PROFILE.PUBLISHED_FEED);
  return {
    id: 1,
    name: 'taxii-test',
    token_hash: hashApiKey(plaintext),
    key_type: ACCESS_PROFILE.PUBLISHED_FEED,
    scopes: [API_SCOPE.PUBLISHED_FEEDS_READ],
    enabled: true,
    revoked_at: null,
    deleted_at: null,
    expires_at: null,
    plaintext,
    ...over
  };
}

function createMockPool({ keys = [], feeds = [], snapshotsByFeedId = new Map() }) {
  return {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM published_feed_access_keys') && s.includes('token_hash = $1') && s.includes('deleted_at IS NULL')) {
        const row = keys.find((k) => k.token_hash === params[0] && !k.deleted_at);
        if (!row) return { rows: [], rowCount: 0 };
        const { plaintext, ...rest } = row;
        void plaintext;
        return { rows: [rest], rowCount: 1 };
      }
      if (s.includes('FROM published_feeds') && s.includes('WHERE enabled = TRUE')) {
        return { rows: feeds.filter((f) => f.enabled), rowCount: feeds.filter((f) => f.enabled).length };
      }
      if (s.includes('FROM published_feeds') && s.includes('WHERE slug = $1')) {
        const feed = feeds.find((f) => f.slug === params[0]);
        return { rows: feed ? [feed] : [], rowCount: feed ? 1 : 0 };
      }
      if (s.includes('FROM published_feed_snapshots') && s.includes("COALESCE(artifact_format")) {
        const feedId = Number(params[0]);
        const fmt = params[3];
        const snap = snapshotsByFeedId.get(`${feedId}:${fmt}`) || snapshotsByFeedId.get(feedId);
        if (!snap) return { rows: [], rowCount: 0 };
        const { content, ...meta } = snap;
        void content;
        return { rows: [meta], rowCount: 1 };
      }
      if (s.includes('FROM published_feed_snapshots') && s.includes('content_hash = $2') && s.includes('SELECT id, content')) {
        for (const snap of snapshotsByFeedId.values()) {
          if (Number(snap.id) === Number(params[0]) && String(snap.content_hash) === String(params[1])) {
            return { rows: [snap], rowCount: 1 };
          }
        }
        return { rows: [], rowCount: 0 };
      }
      if (s.includes('FROM published_feed_snapshots') && s.includes('storage_path IS NOT NULL')) {
        return { rows: [], rowCount: 0 };
      }
      if (s.includes('UPDATE published_feed_access_keys')) return { rows: [], rowCount: 1 };
      throw new Error('unexpected SQL: ' + s.slice(0, 120));
    }
  };
}

function makeApp(pool) {
  const app = express();
  registerTaxii21Routes(app, pool);
  return app;
}

async function http(app, path, { headers = {}, method = 'GET' } = {}) {
  const { createServer } = await import('node:http');
  const server = createServer(app);
  await new Promise((r) => server.listen(0, r));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not json */ }
    return {
      status: res.status,
      text,
      json,
      contentType: res.headers.get('content-type') || ''
    };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

const stixFeed = {
  id: 11,
  name: 'Temp STIX',
  slug: 'temp-stix-p5',
  description: null,
  enabled: true,
  formats: ['txt', 'json', 'stix'],
  ioc_types: ['ip'],
  time_window: 'all',
  filter_mode: 'basic'
};

const txtOnlyFeed = {
  id: 12,
  name: 'TXT only',
  slug: 'txt-only',
  enabled: true,
  formats: ['txt'],
  ioc_types: ['ip'],
  time_window: 'all'
};

const disabledStixFeed = {
  id: 13,
  name: 'Disabled STIX',
  slug: 'disabled-stix',
  enabled: false,
  formats: ['stix'],
  ioc_types: ['ip'],
  time_window: 'all'
};

function sampleSnap() {
  const bundle = stixBundle('temp-stix-p5', [
    { type: 'ip', value: '192.0.2.10', timestamps: TS },
    { type: 'domain', value: 'evil.example', timestamps: TS },
    { type: 'url', value: 'https://evil.example/a', timestamps: TS },
    { type: 'md5', value: 'd41d8cd98f00b204e9800998ecf8427e', timestamps: TS }
  ]);
  return {
    id: 110,
    content: bundle.content,
    content_hash: bundle.content_hash,
    content_bytes: Buffer.byteLength(bundle.content, 'utf8'),
    item_count: bundle.item_count,
    generated_at: '2026-08-13T00:00:00.000Z',
    params: { ioc_type: 'ip', window: 'all', output_format: 'stix' },
    storage_path: null,
    artifact_format: 'stix'
  };
}

test('TAXII discovery requires auth', async () => {
  const key = baseKey();
  const app = makeApp(createMockPool({ keys: [key], feeds: [stixFeed] }));
  const missing = await http(app, '/taxii2/');
  assert.equal(missing.status, 401);
  assert.match(missing.contentType, /application\/taxii\+json/);
  assert.equal(missing.json.title, 'Authentication Failure');

  const ok = await http(app, '/taxii2/', { headers: { Authorization: `Bearer ${key.plaintext}` } });
  assert.equal(ok.status, 200);
  assert.match(ok.contentType, /application\/taxii\+json;version=2\.1/);
  assert.ok(ok.json.api_roots[0].includes('/taxii2/talonhound/'));
});

test('TAXII query api_key is accepted', async () => {
  const key = baseKey();
  const app = makeApp(createMockPool({ keys: [key], feeds: [stixFeed] }));
  const ok = await http(app, `/taxii2/?api_key=${encodeURIComponent(key.plaintext)}`);
  assert.equal(ok.status, 200);
  assert.equal(ok.json.title, 'TalonHound TAXII 2.1');
});

test('insufficient scope is 403', async () => {
  const key = baseKey({
    key_type: ACCESS_PROFILE.IOC_READ,
    scopes: [API_SCOPE.IOC_READ, API_SCOPE.IOC_EXPORT],
    plaintext: generateApiKeyForProfile(ACCESS_PROFILE.IOC_READ)
  });
  key.token_hash = hashApiKey(key.plaintext);
  const app = makeApp(createMockPool({ keys: [key], feeds: [stixFeed] }));
  const res = await http(app, '/taxii2/', { headers: { Authorization: `Bearer ${key.plaintext}` } });
  assert.equal(res.status, 403);
  assert.match(res.json.description, /published_feeds:read/);
});

test('collections lists only STIX-enabled enabled feeds', async () => {
  const key = baseKey();
  const app = makeApp(createMockPool({
    keys: [key],
    feeds: [stixFeed, txtOnlyFeed, disabledStixFeed]
  }));
  const res = await http(app, '/taxii2/talonhound/collections/', {
    headers: { Authorization: `Bearer ${key.plaintext}` }
  });
  assert.equal(res.status, 200);
  assert.equal(res.json.collections.length, 1);
  assert.equal(res.json.collections[0].id, 'temp-stix-p5');
  assert.equal(res.json.collections[0].can_read, true);
  assert.equal(res.json.collections[0].can_write, false);
  assert.ok(res.json.collections[0].media_types.includes('application/stix+json;version=2.1'));
});

test('disabled or non-STIX collection is 404', async () => {
  const key = baseKey();
  const app = makeApp(createMockPool({
    keys: [key],
    feeds: [stixFeed, txtOnlyFeed, disabledStixFeed]
  }));
  const headers = { Authorization: `Bearer ${key.plaintext}` };
  const txt = await http(app, '/taxii2/talonhound/collections/txt-only/', { headers });
  assert.equal(txt.status, 404);
  const dis = await http(app, '/taxii2/talonhound/collections/disabled-stix/objects/', { headers });
  assert.equal(dis.status, 404);
});

test('objects returns STIX Indicators with pagination and media type', async () => {
  const key = baseKey();
  const snap = sampleSnap();
  const app = makeApp(createMockPool({
    keys: [key],
    feeds: [stixFeed],
    snapshotsByFeedId: new Map([['11:stix', snap], [11, snap]])
  }));
  const headers = { Authorization: `Bearer ${key.plaintext}` };
  const res = await http(app, '/taxii2/talonhound/collections/temp-stix-p5/objects/?limit=2', { headers });
  assert.equal(res.status, 200);
  assert.equal(res.contentType, TAXII_CONTENT_TYPE);
  assert.equal(res.json.objects.length, 2);
  assert.equal(res.json.more, true);
  assert.ok(res.json.next);
  assert.equal(res.json.objects[0].type, 'indicator');
  assert.equal(res.json.objects[0].spec_version, '2.1');
  assert.match(res.json.objects[0].pattern, /ipv4-addr:value = '192\.0\.2\.10'/);

  const page2 = await http(
    app,
    `/taxii2/talonhound/collections/temp-stix-p5/objects/?limit=2&next=${encodeURIComponent(res.json.next)}`,
    { headers }
  );
  assert.equal(page2.status, 200);
  assert.equal(page2.json.objects.length, 2);
  assert.equal(page2.json.more, false);
  assert.match(page2.json.objects[0].pattern, /url:value/);
});

test('POST objects is 405', async () => {
  const key = baseKey();
  const app = makeApp(createMockPool({ keys: [key], feeds: [stixFeed] }));
  const res = await http(app, '/taxii2/talonhound/collections/temp-stix-p5/objects/', {
    method: 'POST',
    headers: { Authorization: `Bearer ${key.plaintext}` }
  });
  assert.equal(res.status, 405);
});

test('disabled API key is 403', async () => {
  const key = baseKey({ enabled: false });
  const app = makeApp(createMockPool({ keys: [key], feeds: [stixFeed] }));
  const res = await http(app, '/taxii2/', { headers: { Authorization: `Bearer ${key.plaintext}` } });
  assert.equal(res.status, 403);
});
