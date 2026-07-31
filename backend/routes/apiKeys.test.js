import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerApiKeyRoutes } from './apiKeys.js';
import { resetApiKeyEncryptionKeyCache } from '../lib/apiKeyEncryption.js';

process.env.API_KEY_ENCRYPTION_KEY = 'a'.repeat(64);
resetApiKeyEncryptionKeyCache();

const ADMIN = { role: 'admin', id: 1, email: 'admin@example.com', username: 'admin@example.com' };
const READONLY = { role: 'readonly', id: 2, email: 'ro@example.com', username: 'ro@example.com' };

function createMockPool(store) {
  let seq = store.length + 1;
  const view = (row) => ({ ...row, has_secret: row.secret_ciphertext != null });
  return {
    async query(sql, params = []) {
      const s = String(sql);

      if (s.includes('INSERT INTO published_feed_access_keys')) {
        const isCreate = params.length === 10;
        const row = {
          id: seq++,
          feed_id: null,
          name: params[0],
          token_hash: params[1],
          key_type: params[2],
          key_prefix: params[3],
          last_four: params[4],
          secret_ciphertext: params[5],
          secret_nonce: params[6],
          secret_tag: params[7],
          enabled: isCreate ? params[8] : true,
          created_by: isCreate ? params[9] : params[8],
          expires_at: null,
          last_used_at: null,
          last_used_ip: null,
          created_at: new Date().toISOString(),
          revoked_at: null,
          feed_name: null,
          feed_ioc_type: null,
          feed_slug: null
        };
        store.push(row);
        return { rows: [{ id: row.id }], rowCount: 1 };
      }

      if (s.includes('SET enabled = FALSE, revoked_at = NOW()')) {
        const row = store.find((r) => r.id === params[0] && !r.revoked_at);
        if (row) { row.enabled = false; row.revoked_at = new Date().toISOString(); }
        return { rows: row ? [{ id: row.id }] : [], rowCount: row ? 1 : 0 };
      }

      if (s.includes('UPDATE published_feed_access_keys') && s.includes('token_hash = $2')) {
        const row = store.find((r) => r.id === params[0]);
        if (row) {
          row.token_hash = params[1];
          row.last_four = params[2];
          row.secret_ciphertext = params[3];
          row.secret_nonce = params[4];
          row.secret_tag = params[5];
        }
        return { rows: [], rowCount: row ? 1 : 0 };
      }

      if (s.includes('UPDATE published_feed_access_keys SET')) {
        // patch: name/enabled — params[0] is id, remaining are the set values in order
        const row = store.find((r) => r.id === params[0] && !r.revoked_at);
        if (row) {
          if (s.includes('name = $')) row.name = params[1];
          if (s.includes('enabled = $')) row.enabled = params[params.length - 1];
        }
        return { rows: [], rowCount: row ? 1 : 0 };
      }

      if (s.includes('FROM published_feed_access_keys') && s.includes('ORDER BY k.created_at DESC')) {
        return { rows: store.map(view), rowCount: store.length };
      }

      if (s.includes('FROM published_feed_access_keys') && s.includes('WHERE k.id = $1')) {
        const row = store.find((r) => r.id === params[0]);
        return { rows: row ? [view(row)] : [], rowCount: row ? 1 : 0 };
      }

      throw new Error('unexpected SQL: ' + s.slice(0, 80));
    }
  };
}

function makeApp(store, getUser) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.user = getUser(); req.authVia = 'cookie'; next(); });
  registerApiKeyRoutes(app, createMockPool(store), { auditSuccess: () => {} });
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
      headers: body ? { 'content-type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined
    });
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { json = null; }
    return { status: res.status, body: json, text, headers: res.headers };
  } finally {
    server.close();
  }
}

test('create Published Feed key returns token + masked, never plaintext in api_key object', async () => {
  const store = [];
  const app = makeApp(store, () => ADMIN);
  const res = await req(app, 'POST', '/api/api-keys', { name: 'Fortigate', key_type: 'published_feed' });
  assert.equal(res.status, 201);
  assert.ok(res.body.token.startsWith('th_pf_'));
  assert.equal(res.body.api_key.revealable, true);
  assert.equal(res.body.api_key.key_type, 'published_feed');
  assert.match(res.body.api_key.masked_key, /^th_pf_•+/);
  // The api_key object must not carry the plaintext secret.
  assert.ok(!JSON.stringify(res.body.api_key).includes(res.body.token));
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('list never returns plaintext and marks revealable', async () => {
  const store = [];
  const app = makeApp(store, () => ADMIN);
  const created = await req(app, 'POST', '/api/api-keys', { name: 'k1', key_type: 'published_feed' });
  const list = await req(app, 'GET', '/api/api-keys');
  assert.equal(list.status, 200);
  assert.ok(!list.text.includes(created.body.token));
  assert.equal(list.body.api_keys[0].revealable, true);
  assert.ok(list.body.api_keys[0].masked_key);
});

test('admin can reveal; readonly is forbidden', async () => {
  const store = [];
  const created = await req(makeApp(store, () => ADMIN), 'POST', '/api/api-keys', { name: 'k', key_type: 'published_feed' });
  const id = created.body.api_key.id;

  const reveal = await req(makeApp(store, () => ADMIN), 'GET', `/api/api-keys/${id}/reveal`);
  assert.equal(reveal.status, 200);
  assert.equal(reveal.body.token, created.body.token);
  assert.equal(reveal.headers.get('cache-control'), 'no-store');

  const forbidden = await req(makeApp(store, () => READONLY), 'GET', `/api/api-keys/${id}/reveal`);
  assert.equal(forbidden.status, 403);
});

test('legacy hash-only key cannot be revealed', async () => {
  const store = [{
    id: 99, feed_id: 5, name: 'legacy', token_hash: 'abc', key_type: 'feed_access',
    key_prefix: null, last_four: null, secret_ciphertext: null, secret_nonce: null,
    secret_tag: null, enabled: true, expires_at: null, last_used_at: null,
    last_used_ip: null, created_at: new Date().toISOString(), revoked_at: null,
    feed_name: 'Old Feed', feed_ioc_type: 'ip', feed_slug: 'old-feed'
  }];
  const res = await req(makeApp(store, () => ADMIN), 'GET', '/api/api-keys/99/reveal');
  assert.equal(res.status, 409);
  assert.match(res.body.message, /cannot be revealed. Rotate/);
});

test('rejects non published_feed key type on create', async () => {
  const res = await req(makeApp([], () => ADMIN), 'POST', '/api/api-keys', { name: 'x', key_type: 'feed_access' });
  assert.equal(res.status, 400);
});
