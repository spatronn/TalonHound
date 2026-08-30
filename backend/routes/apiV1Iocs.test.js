import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerApiV1IocRoutes } from './apiV1Iocs.js';
import { registerApiDocsRoutes } from './apiDocs.js';
import { hashApiKey, generateApiKeyForProfile } from '../lib/publishedFeedApiKey.js';
import { scopesForAccessProfile, ACCESS_PROFILE, API_SCOPE } from '../lib/apiKeyProfiles.js';
import { buildOpenApiDocument } from '../lib/openapiDocument.js';

process.env.API_KEY_ENCRYPTION_KEY = process.env.API_KEY_ENCRYPTION_KEY || 'b'.repeat(64);

function makeKeys() {
  const feedRaw = generateApiKeyForProfile(ACCESS_PROFILE.PUBLISHED_FEED);
  const iocRaw = generateApiKeyForProfile(ACCESS_PROFILE.IOC_MANAGEMENT);
  const readRaw = generateApiKeyForProfile(ACCESS_PROFILE.IOC_READ);
  return {
    feedRaw,
    iocRaw,
    readRaw,
    feed: {
      id: 1,
      name: 'feed-key',
      token_hash: hashApiKey(feedRaw),
      key_type: ACCESS_PROFILE.PUBLISHED_FEED,
      scopes: scopesForAccessProfile(ACCESS_PROFILE.PUBLISHED_FEED),
      enabled: true,
      revoked_at: null,
      deleted_at: null,
      expires_at: null
    },
    ioc: {
      id: 2,
      name: 'ioc-key',
      token_hash: hashApiKey(iocRaw),
      key_type: ACCESS_PROFILE.IOC_MANAGEMENT,
      scopes: scopesForAccessProfile(ACCESS_PROFILE.IOC_MANAGEMENT),
      enabled: true,
      revoked_at: null,
      deleted_at: null,
      expires_at: null
    },
    read: {
      id: 4,
      name: 'read-key',
      token_hash: hashApiKey(readRaw),
      key_type: ACCESS_PROFILE.IOC_READ,
      scopes: scopesForAccessProfile(ACCESS_PROFILE.IOC_READ),
      enabled: true,
      revoked_at: null,
      deleted_at: null,
      expires_at: null
    },
    disabled: null
  };
}

function createPool(store) {
  const iocs = store.iocs || [];
  let iocSeq = 100;
  return {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM published_feed_access_keys') && s.includes('token_hash')) {
        const row = [store.feed, store.ioc, store.read, store.disabled].filter(Boolean)
          .find((k) => k.token_hash === params[0] && !k.deleted_at);
        return { rows: row ? [row] : [] };
      }
      if (s.includes('UPDATE published_feed_access_keys') && s.includes('last_used_at')) {
        return { rows: [], rowCount: 1 };
      }
      if (s.includes('FROM ioc_sources') && s.includes("name = $1")) {
        return {
          rows: [{
            id: 9,
            name: 'API',
            default_confidence: 'medium',
            default_threat_classification: null,
            default_expire_policy: 'never',
            default_expire_days: null,
            active: true,
            archived_at: null
          }]
        };
      }
      if (s.includes('FROM ioc_sources WHERE id')) {
        return {
          rows: [{
            id: 9,
            name: 'API',
            default_confidence: 'medium',
            default_threat_classification: null,
            default_expire_policy: 'never',
            default_expire_days: null,
            active: true,
            archived_at: null
          }]
        };
      }
      if (s.includes('FROM ioc_items') && s.includes('observable_type = $1') && s.includes('observable = $2')) {
        const found = iocs.find((r) => r.observable_type === params[0] && r.observable === params[1]);
        return { rows: found ? [found] : [] };
      }
      if (s.includes('INSERT INTO ioc_items')) {
        const row = {
          id: ++iocSeq,
          public_id: `pub-${iocSeq}`,
          observable: params[0],
          observable_type: params[1],
          source_name: params[2],
          source_url: params[3],
          confidence: params[4],
          category: params[5],
          threat_classification: params[6],
          threat_actor_id: params[7],
          note: params[8],
          ioc_source_id: params[9],
          status: 'active',
          created_at: new Date().toISOString(),
          created_origin: params[15],
          expires_at: null,
          expired_at: null,
          expiration_reason: null,
          manual_status_override: true,
          manual_status: 'active',
          manual_expires_at: null
        };
        iocs.push(row);
        return { rows: [row] };
      }
      if (s.includes('FROM ioc_items WHERE public_id')) {
        const row = iocs.find((r) => String(r.public_id) === String(params[0]));
        return { rows: row ? [row] : [] };
      }
      if (s.includes('SELECT * FROM ioc_items WHERE id = $1') || s.includes('FROM ioc_items WHERE id = $1 LIMIT 1')) {
        const row = iocs.find((r) => Number(r.id) === Number(params[0]));
        return { rows: row ? [row] : [] };
      }
      if (s.includes('FROM ioc_items') && s.includes('created_at DESC')) {
        let rows = [...iocs];
        const typeMatch = s.match(/observable_type = \$(\d+)/);
        if (typeMatch && !s.includes('observable =')) {
          rows = rows.filter((r) => r.observable_type === params[Number(typeMatch[1]) - 1]);
        }
        const statusMatch = s.match(/COALESCE\((?:i\.)?status, 'active'\) = \$(\d+)/);
        if (statusMatch) {
          rows = rows.filter((r) => (r.status || 'active') === params[Number(statusMatch[1]) - 1]);
        }
        if (s.includes('(created_at, id) <') || s.includes('(i.created_at, i.id) <')) {
          const t = params[params.length - 3];
          const id = params[params.length - 2];
          const tMs = new Date(t).getTime();
          rows = rows.filter((r) => {
            const rt = new Date(r.created_at).getTime();
            return rt < tMs || (rt === tMs && Number(r.id) < Number(id));
          });
        }
        rows.sort((a, b) => {
          const d = new Date(b.created_at) - new Date(a.created_at);
          return d !== 0 ? d : Number(b.id) - Number(a.id);
        });
        const limit = Number(params[params.length - 1]);
        if (Number.isFinite(limit) && limit > 0) rows = rows.slice(0, limit);
        return { rows, rowCount: rows.length };
      }
      if (s.includes('UPDATE ioc_items')) {
        const row = iocs.find((r) => Number(r.id) === Number(params[0]));
        if (row && s.includes('confidence =')) row.confidence = params[2];
        if (row && s.includes('note =')) row.note = params[2];
        return { rows: [], rowCount: row ? 1 : 0 };
      }
      if (s.includes('FROM ioc_threat_classifications') || s.includes('ioc_threat_classifications') || s.includes('FROM ioc_tags') || s.includes('FROM tags') || s.includes('INSERT INTO ioc_observables') || s.includes('DELETE FROM')) {
        return { rows: [], rowCount: 0 };
      }
      return { rows: [], rowCount: 0 };
    },
    async connect() {
      const self = this;
      return {
        query: (...a) => self.query(...a),
        release() {}
      };
    }
  };
}

function makeApp(pool, auditEvents = []) {
  const app = express();
  app.use(express.json());
  registerApiDocsRoutes(app);
  registerApiV1IocRoutes(app, pool, {
    auditSuccess: (e) => { auditEvents.push(e); }
  });
  // Mimic a protected admin route that must NOT accept API keys via this stack.
  app.get('/api/users', (_req, res) => res.json({ ok: true }));
  return app;
}

async function req(app, method, path, { token, body } = {}) {
  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(body ? { 'Content-Type': 'application/json' } : {})
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* plain */ }
    return { status: res.status, json, text };
  } finally {
    await new Promise((r) => server.close(r));
  }
}

test('missing Bearer token -> 401 INVALID_API_KEY', async () => {
  const keys = makeKeys();
  const app = makeApp(createPool(keys));
  const res = await req(app, 'POST', '/api/v1/iocs', { body: { type: 'domain', value: 'a.example.com' } });
  assert.equal(res.status, 401);
  assert.equal(res.json.error.code, 'INVALID_API_KEY');
});

test('invalid token -> 401', async () => {
  const keys = makeKeys();
  const app = makeApp(createPool(keys));
  const res = await req(app, 'POST', '/api/v1/iocs', {
    token: 'th_ioc_not-a-real-key',
    body: { type: 'domain', value: 'a.example.com' }
  });
  assert.equal(res.status, 401);
  assert.equal(res.json.error.code, 'INVALID_API_KEY');
});

test('disabled token -> API_KEY_DISABLED', async () => {
  const keys = makeKeys();
  keys.disabled = {
    ...keys.ioc,
    id: 3,
    name: 'disabled',
    token_hash: hashApiKey('th_ioc_disabledkeyvalue0000000000000000000001'),
    enabled: false
  };
  // Use a dedicated raw for disabled
  const raw = 'th_ioc_disabledkeyvalue0000000000000000000001';
  keys.disabled.token_hash = hashApiKey(raw);
  const app = makeApp(createPool(keys));
  const res = await req(app, 'POST', '/api/v1/iocs', {
    token: raw,
    body: { type: 'domain', value: 'a.example.com' }
  });
  assert.equal(res.status, 403);
  assert.equal(res.json.error.code, 'API_KEY_DISABLED');
});

test('Published Feed key cannot POST/PATCH IOCs (403 INSUFFICIENT_SCOPE)', async () => {
  const keys = makeKeys();
  const app = makeApp(createPool(keys));
  const post = await req(app, 'POST', '/api/v1/iocs', {
    token: keys.feedRaw,
    body: { type: 'domain', value: 'a.example.com' }
  });
  assert.equal(post.status, 403);
  assert.equal(post.json.error.code, 'INSUFFICIENT_SCOPE');

  const patch = await req(app, 'PATCH', '/api/v1/iocs/1', {
    token: keys.feedRaw,
    body: { note: 'x' }
  });
  assert.equal(patch.status, 403);
  assert.equal(patch.json.error.code, 'INSUFFICIENT_SCOPE');
});

test('IOC Management key can create IOC (201) and duplicate returns 200', async () => {
  const keys = makeKeys();
  keys.iocs = [];
  const pool = createPool(keys);
  const app = makeApp(pool);
  const first = await req(app, 'POST', '/api/v1/iocs', {
    token: keys.iocRaw,
    body: { type: 'domain', value: 'Malicious-Example.com', confidence: 'high' }
  });
  assert.equal(first.status, 201);
  assert.equal(first.json.created, true);
  assert.equal(first.json.value, 'malicious-example.com');

  const second = await req(app, 'POST', '/api/v1/iocs', {
    token: keys.iocRaw,
    body: { type: 'domain', value: 'malicious-example.com', confidence: 'low' }
  });
  assert.equal(second.status, 200);
  assert.equal(second.json.created, false);
  assert.equal(second.json.existing, true);
  assert.equal(second.json.id, first.json.id);
});

test('invalid type/value return structured validation errors', async () => {
  const keys = makeKeys();
  const app = makeApp(createPool(keys));
  const badType = await req(app, 'POST', '/api/v1/iocs', {
    token: keys.iocRaw,
    body: { type: 'email', value: 'a@b.c' }
  });
  assert.equal(badType.status, 400);
  assert.equal(badType.json.error.code, 'INVALID_IOC_TYPE');

  const badValue = await req(app, 'POST', '/api/v1/iocs', {
    token: keys.iocRaw,
    body: { type: 'domain', value: 'not a domain' }
  });
  assert.equal(badValue.status, 400);
  assert.equal(badValue.json.error.code, 'INVALID_IOC_VALUE');
});

test('PATCH updates note; rejects identity changes; 404 missing', async () => {
  const keys = makeKeys();
  keys.iocs = [{
    id: 42,
    observable: 'evil.example.com',
    observable_type: 'domain',
    confidence: 'medium',
    note: null,
    status: 'active',
    created_at: new Date().toISOString()
  }];
  const app = makeApp(createPool(keys));

  const ok = await req(app, 'PATCH', '/api/v1/iocs/42', {
    token: keys.iocRaw,
    body: { note: 'updated via api' }
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.note, 'updated via api');

  const immutable = await req(app, 'PATCH', '/api/v1/iocs/42', {
    token: keys.iocRaw,
    body: { type: 'ip' }
  });
  assert.equal(immutable.status, 400);

  const missing = await req(app, 'PATCH', '/api/v1/iocs/404', {
    token: keys.iocRaw,
    body: { note: 'x' }
  });
  assert.equal(missing.status, 404);
  assert.equal(missing.json.error.code, 'IOC_NOT_FOUND');
});

test('openapi.json documents create, update, get, search, and export', async () => {
  const doc = buildOpenApiDocument();
  assert.equal(doc.openapi, '3.1.0');
  assert.ok(doc.paths['/api/v1/iocs']?.post);
  assert.ok(doc.paths['/api/v1/iocs']?.get);
  assert.ok(doc.paths['/api/v1/iocs/{id}']?.patch);
  assert.ok(doc.paths['/api/v1/iocs/{id}']?.get);
  assert.ok(doc.paths['/api/v1/iocs/search']?.post);
  assert.ok(doc.paths['/api/v1/iocs/export']?.post);
  assert.ok(doc.components.securitySchemes.ApiKeyBearer);
  assert.deepEqual(doc.paths['/api/v1/iocs'].post['x-required-scopes'], [API_SCOPE.IOC_CREATE]);
  assert.deepEqual(doc.paths['/api/v1/iocs'].get['x-required-scopes'], [API_SCOPE.IOC_READ]);
  assert.deepEqual(doc.paths['/api/v1/iocs/{id}'].patch['x-required-scopes'], [API_SCOPE.IOC_UPDATE]);
  assert.deepEqual(doc.paths['/api/v1/iocs/{id}'].get['x-required-scopes'], [API_SCOPE.IOC_READ]);
  assert.deepEqual(doc.paths['/api/v1/iocs/search'].post['x-required-scopes'], [API_SCOPE.IOC_READ]);
  assert.deepEqual(doc.paths['/api/v1/iocs/export'].post['x-required-scopes'], [API_SCOPE.IOC_EXPORT]);
  assert.ok(doc.components.schemas.ApiError.properties.error.properties.code.enum.includes('QUERY_TOO_EXPENSIVE'));

  const keys = makeKeys();
  const app = makeApp(createPool(keys));
  const res = await req(app, 'GET', '/api/openapi.json');
  assert.equal(res.status, 200);
  assert.equal(res.json.openapi, '3.1.0');
});

test('deleted key is rejected as invalid', async () => {
  const keys = makeKeys();
  keys.ioc.deleted_at = new Date().toISOString();
  const app = makeApp(createPool(keys));
  const res = await req(app, 'POST', '/api/v1/iocs', {
    token: keys.iocRaw,
    body: { type: 'domain', value: 'a.example.com' }
  });
  assert.equal(res.status, 401);
  assert.equal(res.json.error.code, 'INVALID_API_KEY');
});

function sampleIocs() {
  return [
    {
      id: 42,
      public_id: '11111111-1111-4111-8111-111111111111',
      observable: 'evil.example.com',
      observable_type: 'domain',
      confidence: 'high',
      note: 'tracked',
      status: 'active',
      created_at: '2026-08-03T00:00:00.000Z',
      threat_classification: 'phishing',
      source_name: 'internal-should-not-leak',
      source_url: 'https://secret.example/feed',
      created_origin: 'api'
    },
    {
      id: 41,
      public_id: '22222222-2222-4222-8222-222222222222',
      observable: '198.51.100.10',
      observable_type: 'ip',
      confidence: 'medium',
      note: null,
      status: 'active',
      created_at: '2026-08-02T00:00:00.000Z',
      threat_classification: null
    },
    {
      id: 40,
      public_id: '33333333-3333-4333-8333-333333333333',
      observable: 'old.example.com',
      observable_type: 'domain',
      confidence: 'low',
      note: null,
      status: 'expired',
      created_at: '2026-08-01T00:00:00.000Z',
      threat_classification: null
    }
  ];
}

function assertPublicIocShape(item) {
  assert.equal(item.source_name, undefined);
  assert.equal(item.source_url, undefined);
  assert.equal(item.created_origin, undefined);
  assert.equal(item.token_hash, undefined);
  assert.ok(item.id != null);
  assert.ok(item.type);
  assert.ok(item.value);
}

test('GET /api/v1/iocs missing Bearer -> 401', async () => {
  const keys = makeKeys();
  keys.iocs = sampleIocs();
  const app = makeApp(createPool(keys));
  const res = await req(app, 'GET', '/api/v1/iocs');
  assert.equal(res.status, 401);
  assert.equal(res.json.error.code, 'INVALID_API_KEY');
});

test('GET /api/v1/iocs query-string api_key is not accepted', async () => {
  const keys = makeKeys();
  keys.iocs = sampleIocs();
  const app = makeApp(createPool(keys));
  const res = await req(app, 'GET', `/api/v1/iocs?api_key=${keys.readRaw}`);
  assert.equal(res.status, 401);
  assert.equal(res.json.error.code, 'INVALID_API_KEY');
});

test('disabled read key -> API_KEY_DISABLED on GET', async () => {
  const keys = makeKeys();
  keys.read.enabled = false;
  keys.iocs = sampleIocs();
  const app = makeApp(createPool(keys));
  const res = await req(app, 'GET', '/api/v1/iocs', { token: keys.readRaw });
  assert.equal(res.status, 403);
  assert.equal(res.json.error.code, 'API_KEY_DISABLED');
});

test('deleted read key -> INVALID_API_KEY on GET', async () => {
  const keys = makeKeys();
  keys.read.deleted_at = new Date().toISOString();
  keys.iocs = sampleIocs();
  const app = makeApp(createPool(keys));
  const res = await req(app, 'GET', '/api/v1/iocs', { token: keys.readRaw });
  assert.equal(res.status, 401);
  assert.equal(res.json.error.code, 'INVALID_API_KEY');
});

test('Published Feed and IOC Management keys cannot GET/search/export', async () => {
  const keys = makeKeys();
  keys.iocs = sampleIocs();
  const app = makeApp(createPool(keys));
  for (const token of [keys.feedRaw, keys.iocRaw]) {
    const list = await req(app, 'GET', '/api/v1/iocs', { token });
    assert.equal(list.status, 403);
    assert.equal(list.json.error.code, 'INSUFFICIENT_SCOPE');
    const search = await req(app, 'POST', '/api/v1/iocs/search', {
      token,
      body: { query: 'type equals "domain"' }
    });
    assert.equal(search.status, 403);
    assert.equal(search.json.error.code, 'INSUFFICIENT_SCOPE');
    const exp = await req(app, 'POST', '/api/v1/iocs/export', {
      token,
      body: { query: 'type equals "domain"', format: 'json' }
    });
    assert.equal(exp.status, 403);
    assert.equal(exp.json.error.code, 'INSUFFICIENT_SCOPE');
  }
});

test('IOC Read key cannot POST or PATCH', async () => {
  const keys = makeKeys();
  keys.iocs = sampleIocs();
  const app = makeApp(createPool(keys));
  const post = await req(app, 'POST', '/api/v1/iocs', {
    token: keys.readRaw,
    body: { type: 'domain', value: 'a.example.com' }
  });
  assert.equal(post.status, 403);
  assert.equal(post.json.error.code, 'INSUFFICIENT_SCOPE');

  const patch = await req(app, 'PATCH', '/api/v1/iocs/42', {
    token: keys.readRaw,
    body: { note: 'nope' }
  });
  assert.equal(patch.status, 403);
  assert.equal(patch.json.error.code, 'INSUFFICIENT_SCOPE');
});

test('GET single IOC by numeric id and public_id', async () => {
  const keys = makeKeys();
  keys.iocs = sampleIocs();
  const app = makeApp(createPool(keys));
  const byId = await req(app, 'GET', '/api/v1/iocs/42', { token: keys.readRaw });
  assert.equal(byId.status, 200);
  assert.equal(byId.json.id, 42);
  assert.equal(byId.json.value, 'evil.example.com');
  assert.equal(byId.json.type, 'domain');
  assertPublicIocShape(byId.json);

  const byUuid = await req(app, 'GET', '/api/v1/iocs/11111111-1111-4111-8111-111111111111', {
    token: keys.readRaw
  });
  assert.equal(byUuid.status, 200);
  assert.equal(byUuid.json.id, 42);

  const missing = await req(app, 'GET', '/api/v1/iocs/999', { token: keys.readRaw });
  assert.equal(missing.status, 404);
  assert.equal(missing.json.error.code, 'IOC_NOT_FOUND');
});

test('GET list is bounded, paginates, and omits internal fields', async () => {
  const keys = makeKeys();
  keys.iocs = sampleIocs();
  const app = makeApp(createPool(keys));
  const page1 = await req(app, 'GET', '/api/v1/iocs?limit=2', { token: keys.readRaw });
  assert.equal(page1.status, 200);
  assert.equal(page1.json.limit, 2);
  assert.equal(page1.json.items.length, 2);
  assert.equal(page1.json.has_more, true);
  assert.ok(page1.json.next_cursor);
  assert.equal(page1.json.items[0].id, 42);
  assertPublicIocShape(page1.json.items[0]);

  const page2 = await req(app, 'GET', `/api/v1/iocs?limit=2&cursor=${page1.json.next_cursor}`, {
    token: keys.readRaw
  });
  assert.equal(page2.status, 200);
  assert.equal(page2.json.items.length, 1);
  assert.equal(page2.json.items[0].id, 40);
  assert.equal(page2.json.has_more, false);

  const clamped = await req(app, 'GET', '/api/v1/iocs?limit=5000', { token: keys.readRaw });
  assert.equal(clamped.status, 200);
  assert.equal(clamped.json.limit, 100);

  const typed = await req(app, 'GET', '/api/v1/iocs?type=ip', { token: keys.readRaw });
  assert.equal(typed.status, 200);
  assert.equal(typed.json.items.length, 1);
  assert.equal(typed.json.items[0].type, 'ip');
});

test('POST search accepts cheap DSL and rejects malformed / expensive queries', async () => {
  const keys = makeKeys();
  keys.iocs = sampleIocs();
  const app = makeApp(createPool(keys));
  const ok = await req(app, 'POST', '/api/v1/iocs/search', {
    token: keys.readRaw,
    body: { query: 'type equals "domain"', limit: 50 }
  });
  assert.equal(ok.status, 200);
  assert.ok(Array.isArray(ok.json.items));
  assert.ok(ok.json.items.length >= 1);
  assert.equal(ok.json.limit, 50);
  assert.ok(ok.json.normalized_query);
  ok.json.items.forEach(assertPublicIocShape);

  const malformed = await req(app, 'POST', '/api/v1/iocs/search', {
    token: keys.readRaw,
    body: { query: 'severity equals "high"' }
  });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.json.error.code, 'VALIDATION_ERROR');

  const expensive = await req(app, 'POST', '/api/v1/iocs/search', {
    token: keys.readRaw,
    body: { query: 'source contains "x"' }
  });
  assert.equal(expensive.status, 400);
  assert.equal(expensive.json.error.code, 'QUERY_TOO_EXPENSIVE');
});

test('POST export returns bounded JSON and CSV; expensive queries rejected', async () => {
  const keys = makeKeys();
  keys.iocs = sampleIocs();
  const app = makeApp(createPool(keys));
  const json = await req(app, 'POST', '/api/v1/iocs/export', {
    token: keys.readRaw,
    body: { query: 'type equals "domain"', format: 'json' }
  });
  assert.equal(json.status, 200);
  assert.equal(json.json.truncated, false);
  assert.equal(json.json.limit, 10000);
  assert.ok(Array.isArray(json.json.items));
  json.json.items.forEach(assertPublicIocShape);

  const csv = await req(app, 'POST', '/api/v1/iocs/export', {
    token: keys.readRaw,
    body: { query: 'type equals "domain"', format: 'csv' }
  });
  assert.equal(csv.status, 200);
  assert.match(csv.text, /^id,public_id,type,value,status,confidence,created_at\n/);
  assert.match(csv.text, /evil\.example\.com/);

  const expensive = await req(app, 'POST', '/api/v1/iocs/export', {
    token: keys.readRaw,
    body: { query: 'source contains "USOM"', format: 'json' }
  });
  assert.equal(expensive.status, 400);
  assert.equal(expensive.json.error.code, 'QUERY_TOO_EXPENSIVE');
});

test('existing POST create still works after read routes are registered', async () => {
  const keys = makeKeys();
  keys.iocs = [];
  const app = makeApp(createPool(keys));
  const first = await req(app, 'POST', '/api/v1/iocs', {
    token: keys.iocRaw,
    body: { type: 'domain', value: 'still-works.example.com' }
  });
  assert.equal(first.status, 201);
  assert.equal(first.json.created, true);
});
