import test from 'node:test';
import assert from 'node:assert/strict';
import {
  API_SCOPE,
  ACCESS_PROFILE,
  scopesForAccessProfile,
  hasApiScope,
  listCreatableAccessProfiles,
  getAccessProfile,
  profileRequiresOwner,
  isMcpAccessProfile
} from './apiKeyProfiles.js';

test('published_feed profile maps to published_feeds:read only', () => {
  assert.deepEqual(scopesForAccessProfile(ACCESS_PROFILE.PUBLISHED_FEED), [API_SCOPE.PUBLISHED_FEEDS_READ]);
  assert.equal(hasApiScope(scopesForAccessProfile('published_feed'), API_SCOPE.IOC_CREATE), false);
});

test('ioc_management profile maps to create+update', () => {
  const scopes = scopesForAccessProfile(ACCESS_PROFILE.IOC_MANAGEMENT);
  assert.deepEqual(scopes, [API_SCOPE.IOC_CREATE, API_SCOPE.IOC_UPDATE]);
  assert.equal(hasApiScope(scopes, API_SCOPE.IOC_CREATE), true);
  assert.equal(hasApiScope(scopes, API_SCOPE.PUBLISHED_FEEDS_READ), false);
});

test('legacy feed_access also maps to feed-read scope', () => {
  assert.deepEqual(scopesForAccessProfile(ACCESS_PROFILE.FEED_ACCESS), [API_SCOPE.PUBLISHED_FEEDS_READ]);
});

test('creatable profiles include REST + MCP presets', () => {
  const ids = listCreatableAccessProfiles().map((p) => p.id).sort();
  assert.deepEqual(ids, [
    'ioc_management',
    'ioc_read',
    'mcp_analyst',
    'mcp_read',
    'published_feed'
  ]);
  assert.equal(getAccessProfile('ioc_management').creatable, true);
  assert.equal(getAccessProfile('mcp_read').creatable, true);
  assert.equal(getAccessProfile('mcp_analyst').creatable, true);
  assert.equal(getAccessProfile('mcp_enrichment'), null, 'MCP Enrichment is no longer a profile');
  assert.equal(getAccessProfile('feed_access').creatable, false);
});

test('ioc_read profile maps to read+export only', () => {
  const scopes = scopesForAccessProfile(ACCESS_PROFILE.IOC_READ);
  assert.deepEqual(scopes, [API_SCOPE.IOC_READ, API_SCOPE.IOC_EXPORT]);
  assert.equal(hasApiScope(scopes, API_SCOPE.IOC_CREATE), false);
  assert.equal(hasApiScope(scopes, API_SCOPE.IOC_UPDATE), false);
});

test('mcp_read scopes are read-only MCP', () => {
  const scopes = scopesForAccessProfile(ACCESS_PROFILE.MCP_READ);
  assert.deepEqual(scopes, [
    API_SCOPE.MCP_IOC_READ,
    API_SCOPE.MCP_SOURCES_READ,
    API_SCOPE.MCP_ENRICHMENT_READ
  ]);
  assert.equal(hasApiScope(scopes, API_SCOPE.MCP_IOC_CREATE), false);
});

test('mcp_analyst scopes include create, enrichment and tags', () => {
  const scopes = scopesForAccessProfile(ACCESS_PROFILE.MCP_ANALYST);
  assert.deepEqual(scopes, [
    API_SCOPE.MCP_IOC_READ,
    API_SCOPE.MCP_IOC_CREATE,
    API_SCOPE.MCP_SOURCES_READ,
    API_SCOPE.MCP_ENRICHMENT_READ,
    API_SCOPE.MCP_ENRICHMENT_WRITE,
    API_SCOPE.MCP_TAGS_WRITE
  ]);
  assert.equal(hasApiScope(scopes, API_SCOPE.MCP_IOC_CREATE), true);
});

test('profileRequiresOwner and isMcpAccessProfile', () => {
  assert.equal(profileRequiresOwner(ACCESS_PROFILE.MCP_READ), true);
  assert.equal(profileRequiresOwner(ACCESS_PROFILE.MCP_ANALYST), true);
  assert.equal(profileRequiresOwner(ACCESS_PROFILE.PUBLISHED_FEED), false);
  assert.equal(profileRequiresOwner(ACCESS_PROFILE.IOC_MANAGEMENT), false);
  assert.equal(isMcpAccessProfile('mcp_read'), true);
  assert.equal(isMcpAccessProfile('mcp_analyst'), true);
  assert.equal(isMcpAccessProfile('ioc_read'), false);
});

test('DB constraints admit every access profile and scope (latest migration defining them)', async () => {
  const { readdirSync, readFileSync } = await import('node:fs');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const { ALL_API_SCOPES, ACCESS_PROFILE } = await import('./apiKeyProfiles.js');
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations');
  const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  const latest = (needle) => {
    let body = null;
    for (const f of files) {
      const sql = readFileSync(path.join(dir, f), 'utf8');
      const idx = sql.lastIndexOf(`ADD CONSTRAINT ${needle}`);
      if (idx !== -1) body = sql.slice(idx, sql.indexOf(';', idx));
    }
    return body;
  };
  const keyTypes = latest('chk_pf_access_keys_key_type');
  const scopes = latest('chk_pf_access_keys_scopes');
  assert.ok(keyTypes && scopes);
  for (const id of Object.values(ACCESS_PROFILE)) assert.ok(keyTypes.includes(`'${id}'`), `key_type ${id} missing from DB constraint`);
  for (const scope of ALL_API_SCOPES) assert.ok(scopes.includes(`"${scope}"`), `scope ${scope} missing from DB constraint`);
});

test('migration 039 backfills the enrichment scopes onto existing MCP Analyst keys only', async () => {
  const { readFileSync } = await import('node:fs');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const sql = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations', '039_mcp_analyst_enrichment_scope.sql'), 'utf8');
  const statements = sql.replace(/--[^\n]*/g, '').split(';').map((x) => x.trim()).filter(Boolean);
  assert.equal(statements.length, 2);
  for (const stmt of statements) {
    assert.match(stmt, /^UPDATE public\.published_feed_access_keys/);
    assert.match(stmt, /WHERE key_type = 'mcp_analyst'/);
    assert.match(stmt, /AND deleted_at IS NULL/);
    assert.match(stmt, /AND NOT \(scopes \? 'mcp:enrichment:(read|write)'\)/, 'idempotent');
    assert.doesNotMatch(stmt, /mcp_read|ioc_read|published_feed'|ioc_management/);
  }
  assert.ok(sql.includes(`'["mcp:enrichment:write"]'`), 'migration must backfill mcp:enrichment:write');
});

test('migration 040 admits mcp:tags:write and backfills it onto live MCP Analyst keys only', async () => {
  const { readFileSync } = await import('node:fs');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const sql = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'migrations', '040_mcp_tags_write_scope.sql'), 'utf8');
  const updates = sql.replace(/--[^\n]*/g, '').split(';').map((x) => x.trim()).filter((x) => x.startsWith('UPDATE'));
  assert.equal(updates.length, 1);
  const [stmt] = updates;
  assert.match(stmt, /^UPDATE public\.published_feed_access_keys/);
  assert.match(stmt, /WHERE key_type = 'mcp_analyst'/);
  assert.match(stmt, /AND deleted_at IS NULL/);
  assert.match(stmt, /AND NOT \(scopes \? 'mcp:tags:write'\)/, 'idempotent');
  assert.doesNotMatch(stmt, /mcp_read|ioc_read|published_feed'|ioc_management/);
  // Every scope the profile carries beyond the pre-040 MCP Analyst set is backfilled (039 + 040).
  const pre039 = ['mcp:ioc:read', 'mcp:ioc:create', 'mcp:sources:read', 'mcp:enrichment:read'];
  const added = scopesForAccessProfile('mcp_analyst').filter((x) => !pre039.includes(x));
  assert.deepEqual(added, ['mcp:enrichment:write', 'mcp:tags:write']);
  assert.ok(sql.includes(`'["mcp:tags:write"]'`), 'migration must backfill mcp:tags:write');
});
