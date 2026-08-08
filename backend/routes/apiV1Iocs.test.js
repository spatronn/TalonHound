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
  return {
    feedRaw,
    iocRaw,
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
        const row = [store.feed, store.ioc, store.disabled].filter(Boolean)
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
      if (s.includes('FROM ioc_items') && s.includes('observable_type = $1') && s.includes('ORDER BY created_at')) {
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
      if (s.includes('SELECT * FROM ioc_items WHERE id = $1')) {
        const row = iocs.find((r) => Number(r.id) === Number(params[0]));
        return { rows: row ? [row] : [] };
      }
      if (s.includes('FROM ioc_items WHERE id = $1 LIMIT 1')) {
        const row = iocs.find((r) => Number(r.id) === Number(params[0]));
        return { rows: row ? [row] : [] };
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

test('openapi.json documents both endpoints with Bearer + scopes', async () => {
  const doc = buildOpenApiDocument();
  assert.equal(doc.openapi, '3.1.0');
  assert.ok(doc.paths['/api/v1/iocs']?.post);
  assert.ok(doc.paths['/api/v1/iocs/{id}']?.patch);
  assert.ok(doc.components.securitySchemes.ApiKeyBearer);
  assert.deepEqual(doc.paths['/api/v1/iocs'].post['x-required-scopes'], [API_SCOPE.IOC_CREATE]);
  assert.deepEqual(doc.paths['/api/v1/iocs/{id}'].patch['x-required-scopes'], [API_SCOPE.IOC_UPDATE]);

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
