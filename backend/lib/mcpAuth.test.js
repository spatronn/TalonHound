import test from 'node:test';
import assert from 'node:assert/strict';
import { hashApiKey, generateApiKeyForProfile } from './publishedFeedApiKey.js';
import { scopesForAccessProfile, ACCESS_PROFILE, API_SCOPE } from './apiKeyProfiles.js';
import { authenticateMcp } from './mcpAuth.js';
import { ROLES } from './rbac.js';

function makeRes() {
  let statusCode = null;
  let body = null;
  const headers = {};
  return {
    get statusCode() { return statusCode; },
    get body() { return body; },
    set(name, value) { headers[name] = value; return this; },
    getHeader(name) { return headers[String(name).toLowerCase()] || headers[name]; },
    status(code) { statusCode = code; return this; },
    json(payload) { body = payload; return this; }
  };
}

function makePool(rowOrFn) {
  return {
    query: async (sql) => {
      if (String(sql).includes('UPDATE published_feed_access_keys')) {
        return { rows: [] };
      }
      if (typeof rowOrFn === 'function') {
        return { rows: rowOrFn(sql) };
      }
      return { rows: rowOrFn ? [rowOrFn] : [] };
    }
  };
}

function baseOwnerRow(overrides = {}) {
  const rawKey = generateApiKeyForProfile(ACCESS_PROFILE.MCP_READ);
  const tokenHash = hashApiKey(rawKey);
  return {
    rawKey,
    row: {
      id: 10,
      name: 'mcp-key',
      token_hash: tokenHash,
      key_type: ACCESS_PROFILE.MCP_READ,
      scopes: scopesForAccessProfile(ACCESS_PROFILE.MCP_READ),
      enabled: true,
      revoked_at: null,
      deleted_at: null,
      expires_at: null,
      owner_user_id: 7,
      owner_id: 7,
      owner_public_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      owner_username: 'analyst@example.com',
      owner_role: ROLES.ANALYST,
      owner_status: 'active',
      ...overrides
    }
  };
}

async function runAuth(pool, authorization) {
  const req = {
    headers: authorization ? { authorization } : {},
    ip: '127.0.0.1'
  };
  const res = makeRes();
  let nextCalled = false;
  await authenticateMcp(pool)(req, res, () => { nextCalled = true; });
  return { req, res, nextCalled };
}

test('authenticateMcp rejects missing bearer', async () => {
  const { res, nextCalled } = await runAuth(makePool(null), null);
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 401);
  assert.equal(res.body?.error?.code, 'INVALID_API_KEY');
});

test('authenticateMcp rejects invalid key', async () => {
  const { res, nextCalled } = await runAuth(
    makePool(null),
    'Bearer th_mcp_not_a_real_key_xxxxxxxxxxxx'
  );
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 401);
});

test('authenticateMcp rejects disabled key', async () => {
  const { rawKey, row } = baseOwnerRow({ enabled: false });
  const { res, nextCalled } = await runAuth(makePool(row), `Bearer ${rawKey}`);
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body?.error?.code, 'API_KEY_DISABLED');
});

test('authenticateMcp rejects key with no owner', async () => {
  const { rawKey, row } = baseOwnerRow({
    owner_user_id: null,
    owner_id: null
  });
  const { res, nextCalled } = await runAuth(makePool(row), `Bearer ${rawKey}`);
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.match(res.body?.error?.message || '', /no accountable owner/i);
});

test('authenticateMcp rejects inactive owner', async () => {
  const { rawKey, row } = baseOwnerRow({ owner_status: 'disabled' });
  const { res, nextCalled } = await runAuth(makePool(row), `Bearer ${rawKey}`);
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
  assert.match(res.body?.error?.message || '', /not active/i);
});

test('authenticateMcp happy path attaches req.user and authVia=mcp', async () => {
  const { rawKey, row } = baseOwnerRow({
    key_type: ACCESS_PROFILE.MCP_ANALYST,
    scopes: scopesForAccessProfile(ACCESS_PROFILE.MCP_ANALYST)
  });
  const { req, res, nextCalled } = await runAuth(makePool(row), `Bearer ${rawKey}`);
  assert.equal(nextCalled, true);
  assert.equal(res.statusCode, null);
  assert.equal(req.authVia, 'mcp');
  assert.equal(req.user?.id, 7);
  assert.equal(req.user?.role, ROLES.ANALYST);
  assert.equal(req.user?.username, 'analyst@example.com');
  assert.equal(req.apiKey?.id, 10);
  assert.ok(req.apiKey.scopes.includes(API_SCOPE.MCP_IOC_CREATE));
  assert.equal(req.mcpAuth?.ownerRole, ROLES.ANALYST);
});
