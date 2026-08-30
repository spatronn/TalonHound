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
        const row = {
          id: seq++,
          feed_id: null,
          name: params[0],
          token_hash: params[1],
          key_type: params[2],
          key_prefix: params[3],
          last_four: params[4],
          scopes: typeof params[5] === 'string' ? JSON.parse(params[5]) : (params[5] || []),
          secret_ciphertext: params[6],
          secret_nonce: params[7],
          secret_tag: params[8],
          enabled: params[9],
          created_by: params[10],
          expires_at: null,
          last_used_at: null,
          last_used_ip: null,
          created_at: new Date().toISOString(),
          revoked_at: null,
          deleted_at: null,
          deleted_by: null,
          feed_name: null,
          feed_ioc_types: null,
          feed_slug: null
        };
        store.push(row);
        return { rows: [{ id: row.id }], rowCount: 1 };
      }

      // Soft-delete
      if (s.includes('UPDATE published_feed_access_keys') && s.includes('deleted_at = NOW()')) {
        const row = store.find((r) => r.id === params[0] && !r.deleted_at);
        if (row) {
          row.enabled = false;
          row.deleted_at = new Date().toISOString();
          row.deleted_by = params[1];
        }
        return { rows: row ? [{ id: row.id }] : [], rowCount: row ? 1 : 0 };
      }

      // In-place secret update (create-time only path uses INSERT; keep for safety)
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

      // patch: name/enabled
      if (s.includes('UPDATE published_feed_access_keys SET')) {
        const row = store.find((r) => r.id === params[0] && !r.deleted_at);
        if (row) {
          if (s.includes('name = $')) row.name = params[1];
          if (s.includes('enabled = $')) row.enabled = params[params.length - 1];
        }
        return { rows: [], rowCount: row ? 1 : 0 };
      }

      if (s.includes('FROM published_feed_access_keys') && s.includes('ORDER BY k.created_at DESC')) {
        const rows = store.filter((r) => !r.deleted_at).map(view);
        return { rows, rowCount: rows.length };
      }

      if (s.includes('FROM published_feed_access_keys') && s.includes('WHERE k.id = $1')) {
        const requireNotDeleted = s.includes('deleted_at IS NULL');
        const row = store.find((r) => r.id === params[0] && (!requireNotDeleted || !r.deleted_at));
        return { rows: row ? [view(row)] : [], rowCount: row ? 1 : 0 };
      }

      throw new Error('unexpected SQL: ' + s.slice(0, 80));
    }
  };
}

function makeApp(store, getUser, auditEvents) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.user = getUser(); req.authVia = 'cookie'; next(); });
  const audit = { auditSuccess: (e) => { auditEvents?.push(e); } };
  registerApiKeyRoutes(app, createMockPool(store), audit);
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

async function createKey(store, name = 'k') {
  const created = await req(makeApp(store, () => ADMIN), 'POST', '/api/api-keys', { name, key_type: 'published_feed' });
  assert.equal(created.status, 201);
  return created;
}

test('create Published Feed key returns token + masked, never plaintext in api_key object', async () => {
  const store = [];
  const app = makeApp(store, () => ADMIN);
  const res = await req(app, 'POST', '/api/api-keys', { name: 'Fortigate', key_type: 'published_feed' });
  assert.equal(res.status, 201);
  assert.ok(res.body.token.startsWith('th_pf_'));
  assert.equal(res.body.api_key.revealable, true);
  assert.equal(res.body.api_key.key_type, 'published_feed');
  assert.deepEqual(res.body.api_key.scopes, ['published_feeds:read']);
  assert.match(res.body.api_key.masked_key, /^th_pf_•+/);
  assert.ok(!JSON.stringify(res.body.api_key).includes(res.body.token));
  assert.equal(res.headers.get('cache-control'), 'no-store');
});

test('list never returns plaintext and marks revealable', async () => {
  const store = [];
  const created = await createKey(store, 'k1');
  const list = await req(makeApp(store, () => ADMIN), 'GET', '/api/api-keys');
  assert.equal(list.status, 200);
  assert.ok(!list.text.includes(created.body.token));
  assert.equal(list.body.api_keys[0].revealable, true);
  assert.ok(list.body.api_keys[0].masked_key);
});

test('admin can reveal; readonly is forbidden', async () => {
  const store = [];
  const created = await createKey(store, 'k');
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
    deleted_at: null, deleted_by: null,
    feed_name: 'Old Feed', feed_ioc_types: ['ip'], feed_slug: 'old-feed'
  }];
  const res = await req(makeApp(store, () => ADMIN), 'GET', '/api/api-keys/99/reveal');
  assert.equal(res.status, 409);
  assert.match(res.body.message, /cannot be revealed/);
});

test('rejects non-creatable key type on create', async () => {
  const res = await req(makeApp([], () => ADMIN), 'POST', '/api/api-keys', { name: 'x', key_type: 'feed_access' });
  assert.equal(res.status, 400);
});

test('create IOC Read key returns th_read_ prefix and read/export scopes', async () => {
  const store = [];
  const res = await req(makeApp(store, () => ADMIN), 'POST', '/api/api-keys', {
    name: 'SIEM',
    access_profile: 'ioc_read'
  });
  assert.equal(res.status, 201);
  assert.ok(res.body.token.startsWith('th_read_'));
  assert.equal(res.body.api_key.key_type, 'ioc_read');
  assert.deepEqual(res.body.api_key.scopes, ['ioc:read', 'ioc:export']);
  assert.equal(res.body.api_key.permission_summary, 'Read + Search + Export IOCs');
  assert.equal(res.body.api_key.revealable, true);
});

test('create Published Feed key includes published_feeds:read scope', async () => {
  const store = [];
  const res = await req(makeApp(store, () => ADMIN), 'POST', '/api/api-keys', {
    name: 'Fortigate',
    key_type: 'published_feed'
  });
  assert.equal(res.status, 201);
  assert.deepEqual(res.body.api_key.scopes, ['published_feeds:read']);
});

test('ACTIVE -> DISABLED then DISABLED -> ACTIVE', async () => {
  const store = [];
  const created = await createKey(store, 'toggle');
  const id = created.body.api_key.id;

  const disable = await req(makeApp(store, () => ADMIN), 'PATCH', `/api/api-keys/${id}`, { enabled: false });
  assert.equal(disable.status, 200);
  assert.equal(disable.body.api_key.status, 'disabled');
  assert.equal(disable.body.api_key.enabled, false);

  const enable = await req(makeApp(store, () => ADMIN), 'PATCH', `/api/api-keys/${id}`, { enabled: true });
  assert.equal(enable.status, 200);
  assert.equal(enable.body.api_key.status, 'active');
  assert.equal(enable.body.api_key.enabled, true);
});

test('enabling an already-enabled key is rejected (state machine)', async () => {
  const store = [];
  const created = await createKey(store, 'noop');
  const id = created.body.api_key.id;
  const res = await req(makeApp(store, () => ADMIN), 'PATCH', `/api/api-keys/${id}`, { enabled: true });
  assert.equal(res.status, 409);
});

test('disabling an expired key is rejected (state machine)', async () => {
  const store = [{
    id: 77, feed_id: null, name: 'expired', token_hash: 'z', key_type: 'published_feed',
    key_prefix: 'th_pf_', last_four: 'wxyz', secret_ciphertext: Buffer.from('x'),
    secret_nonce: Buffer.from('n'), secret_tag: Buffer.from('t'), enabled: true,
    expires_at: new Date(Date.now() - 1000).toISOString(), last_used_at: null, last_used_ip: null,
    created_at: new Date().toISOString(), revoked_at: null, deleted_at: null, deleted_by: null,
    feed_name: null, feed_ioc_types: null, feed_slug: null
  }];
  const res = await req(makeApp(store, () => ADMIN), 'PATCH', '/api/api-keys/77', { enabled: false });
  assert.equal(res.status, 409);
});

test('ACTIVE -> DELETED: soft-deletes, hides from list, blocks reveal, is irreversible', async () => {
  const store = [];
  const auditEvents = [];
  const created = await createKey(store, 'delete-me');
  const id = created.body.api_key.id;

  const del = await req(makeApp(store, () => ADMIN, auditEvents), 'DELETE', `/api/api-keys/${id}`);
  assert.equal(del.status, 200);
  assert.equal(del.body.ok, true);

  // Not in the list anymore.
  const list = await req(makeApp(store, () => ADMIN), 'GET', '/api/api-keys');
  assert.equal(list.body.api_keys.length, 0);

  // Reveal is now 404.
  const reveal = await req(makeApp(store, () => ADMIN), 'GET', `/api/api-keys/${id}/reveal`);
  assert.equal(reveal.status, 404);

  // Deleting again is a 404 (irreversible, idempotent from the client's view).
  const again = await req(makeApp(store, () => ADMIN), 'DELETE', `/api/api-keys/${id}`);
  assert.equal(again.status, 404);

  // Audit metadata carries only safe fields — never the secret.
  const evt = auditEvents.find((e) => e.action === 'api_key.deleted');
  assert.ok(evt);
  // Only safe metadata/snapshot is recorded — never the secret.
  const serialized = JSON.stringify({ metadata: evt.metadata, before: evt.before, after: evt.after });
  assert.ok(!serialized.includes(created.body.token));
  assert.deepEqual(Object.keys(evt.metadata).sort(), ['key_id', 'key_type', 'name']);
});

test('DISABLED -> DELETED', async () => {
  const store = [];
  const created = await createKey(store, 'disabled-delete');
  const id = created.body.api_key.id;
  await req(makeApp(store, () => ADMIN), 'PATCH', `/api/api-keys/${id}`, { enabled: false });
  const del = await req(makeApp(store, () => ADMIN), 'DELETE', `/api/api-keys/${id}`);
  assert.equal(del.status, 200);
});

test('legacy feed_access key supports delete', async () => {
  const store = [{
    id: 42, feed_id: 5, name: 'legacy', token_hash: 'abc', key_type: 'feed_access',
    key_prefix: null, last_four: null, secret_ciphertext: null, secret_nonce: null,
    secret_tag: null, enabled: true, expires_at: null, last_used_at: null,
    last_used_ip: null, created_at: new Date().toISOString(), revoked_at: null,
    deleted_at: null, deleted_by: null, feed_name: 'Old', feed_ioc_types: ['ip'], feed_slug: 'old'
  }];
  const auditEvents = [];
  const del = await req(makeApp(store, () => ADMIN, auditEvents), 'DELETE', '/api/api-keys/42');
  assert.equal(del.status, 200);
  const evt = auditEvents.find((e) => e.action === 'api_key.deleted');
  assert.equal(evt.metadata.key_type, 'feed_access');
});

test('readonly cannot delete or patch', async () => {
  const store = [];
  const created = await createKey(store, 'guarded');
  const id = created.body.api_key.id;
  const del = await req(makeApp(store, () => READONLY), 'DELETE', `/api/api-keys/${id}`);
  assert.equal(del.status, 403);
  const patch = await req(makeApp(store, () => READONLY), 'PATCH', `/api/api-keys/${id}`, { enabled: false });
  assert.equal(patch.status, 403);
});

test('rotate and revoke endpoints no longer exist', async () => {
  const store = [];
  const created = await createKey(store, 'gone');
  const id = created.body.api_key.id;
  const rotate = await req(makeApp(store, () => ADMIN), 'POST', `/api/api-keys/${id}/rotate`, { reason: 'x' });
  assert.equal(rotate.status, 404);
  const revoke = await req(makeApp(store, () => ADMIN), 'POST', `/api/api-keys/${id}/revoke`, { reason: 'x' });
  assert.equal(revoke.status, 404);
});

test('AUTH-07: GET /api/api-keys is admin-only (analyst/readonly forbidden)', async () => {
  const store = [];
  await createKey(store, 'inventory');
  const analyst = { role: 'analyst', id: 3, email: 'a@example.com', username: 'a@example.com' };
  for (const user of [READONLY, analyst]) {
    const list = await req(makeApp(store, () => user), 'GET', '/api/api-keys');
    assert.equal(list.status, 403, `${user.role} must not list API keys`);
    const profiles = await req(makeApp(store, () => user), 'GET', '/api/api-keys/profiles');
    assert.equal(profiles.status, 403, `${user.role} must not list profiles`);
  }
  const adminList = await req(makeApp(store, () => ADMIN), 'GET', '/api/api-keys');
  assert.equal(adminList.status, 200);
  assert.ok(Array.isArray(adminList.body.api_keys));
  assert.equal(adminList.body.api_keys[0].token, undefined);
  assert.equal(adminList.body.api_keys[0].secret, undefined);
});
