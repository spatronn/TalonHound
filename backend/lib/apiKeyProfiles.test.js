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

test('mcp_analyst scopes include create', () => {
  const scopes = scopesForAccessProfile(ACCESS_PROFILE.MCP_ANALYST);
  assert.deepEqual(scopes, [
    API_SCOPE.MCP_IOC_READ,
    API_SCOPE.MCP_IOC_CREATE,
    API_SCOPE.MCP_SOURCES_READ,
    API_SCOPE.MCP_ENRICHMENT_READ
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
