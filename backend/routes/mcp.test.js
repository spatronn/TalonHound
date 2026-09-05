import test from 'node:test';
import assert from 'node:assert/strict';
import { registerMcpTools } from '../lib/mcpTools.js';
import { createTalonHoundMcpServer } from '../lib/mcpServer.js';
import { authenticateMcp } from '../lib/mcpAuth.js';
import { createSlidingWindowRateLimit } from '../lib/slidingWindowRateLimit.js';
import { hashApiKey, generateApiKeyForProfile } from '../lib/publishedFeedApiKey.js';
import { ACCESS_PROFILE, scopesForAccessProfile } from '../lib/apiKeyProfiles.js';
import { ROLES } from '../lib/rbac.js';
import { API_ERROR_CODE } from '../lib/apiV1Errors.js';
import { MCP_TOOL_SCOPES } from '../lib/mcpPermissions.js';

const EXPECTED_TOOLS = Object.keys(MCP_TOOL_SCOPES).sort();

function makeResRecorder() {
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

async function runAuth(pool, authorization) {
  const req = { headers: authorization ? { authorization } : {}, ip: '127.0.0.1' };
  const res = makeResRecorder();
  let nextCalled = false;
  await authenticateMcp(pool)(req, res, () => { nextCalled = true; });
  return { req, res, nextCalled };
}

test('registerMcpTools registers all authorize-gated tools', () => {
  const names = [];
  const fakeServer = {
    registerTool(name) {
      names.push(name);
    }
  };
  registerMcpTools(fakeServer, {
    pool: { query: async () => ({ rows: [] }) },
    getRequestContext: () => ({ req: null })
  });
  assert.deepEqual(names.sort(), EXPECTED_TOOLS);
});

test('createTalonHoundMcpServer builds a server instance', () => {
  const server = createTalonHoundMcpServer({
    pool: { query: async () => ({ rows: [] }) },
    getRequestContext: () => ({ req: null })
  });
  assert.ok(server);
  assert.equal(typeof server.connect, 'function');
});

test('authenticateMcp rejects unauthenticated, revoked, no-owner, and wrong-scope keys', async () => {
  const emptyPool = { query: async () => ({ rows: [] }) };
  const missing = await runAuth(emptyPool, null);
  assert.equal(missing.nextCalled, false);
  assert.equal(missing.res.statusCode, 401);

  const rawKey = generateApiKeyForProfile(ACCESS_PROFILE.MCP_READ);
  const tokenHash = hashApiKey(rawKey);

  const revokedPool = {
    query: async (sql) => {
      if (String(sql).includes('UPDATE')) return { rows: [] };
      return {
        rows: [{
          id: 1,
          name: 'revoked',
          token_hash: tokenHash,
          key_type: ACCESS_PROFILE.MCP_READ,
          scopes: scopesForAccessProfile(ACCESS_PROFILE.MCP_READ),
          enabled: true,
          revoked_at: new Date().toISOString(),
          deleted_at: null,
          expires_at: null,
          owner_user_id: 1,
          owner_id: 1,
          owner_public_id: '11111111-1111-4111-8111-111111111111',
          owner_username: 'a@x',
          owner_role: ROLES.ANALYST,
          owner_status: 'active'
        }]
      };
    }
  };
  const revoked = await runAuth(revokedPool, `Bearer ${rawKey}`);
  assert.equal(revoked.nextCalled, false);
  assert.equal(revoked.res.statusCode, 401);

  const noOwnerPool = {
    query: async (sql) => {
      if (String(sql).includes('UPDATE')) return { rows: [] };
      return {
        rows: [{
          id: 2,
          name: 'no-owner',
          token_hash: tokenHash,
          key_type: ACCESS_PROFILE.MCP_READ,
          scopes: scopesForAccessProfile(ACCESS_PROFILE.MCP_READ),
          enabled: true,
          revoked_at: null,
          deleted_at: null,
          expires_at: null,
          owner_user_id: null,
          owner_id: null,
          owner_public_id: null,
          owner_username: null,
          owner_role: null,
          owner_status: null
        }]
      };
    }
  };
  const noOwner = await runAuth(noOwnerPool, `Bearer ${rawKey}`);
  assert.equal(noOwner.nextCalled, false);
  assert.equal(noOwner.res.statusCode, 403);

  const wrongScopeKey = generateApiKeyForProfile(ACCESS_PROFILE.PUBLISHED_FEED);
  const wrongHash = hashApiKey(wrongScopeKey);
  const wrongPool = {
    query: async (sql) => {
      if (String(sql).includes('UPDATE')) return { rows: [] };
      return {
        rows: [{
          id: 3,
          name: 'feed-only',
          token_hash: wrongHash,
          key_type: ACCESS_PROFILE.PUBLISHED_FEED,
          scopes: scopesForAccessProfile(ACCESS_PROFILE.PUBLISHED_FEED),
          enabled: true,
          revoked_at: null,
          deleted_at: null,
          expires_at: null,
          owner_user_id: 1,
          owner_id: 1,
          owner_public_id: '11111111-1111-4111-8111-111111111111',
          owner_username: 'a@x',
          owner_role: ROLES.ADMIN,
          owner_status: 'active'
        }]
      };
    }
  };
  const wrong = await runAuth(wrongPool, `Bearer ${wrongScopeKey}`);
  assert.equal(wrong.nextCalled, false);
  assert.equal(wrong.res.statusCode, 403);
  assert.equal(wrong.res.body?.error?.code, API_ERROR_CODE.INSUFFICIENT_SCOPE);
});

test('MCP route rate limiter rejects after window budget is exhausted', () => {
  const limiter = createSlidingWindowRateLimit({ windowMs: 60_000 });
  assert.equal(limiter.check('mcp:all:key:test', 2), true);
  assert.equal(limiter.check('mcp:all:key:test', 2), true);
  assert.equal(limiter.check('mcp:all:key:test', 2), false);
});
