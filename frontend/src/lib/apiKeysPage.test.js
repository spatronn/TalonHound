import test from 'node:test';
import assert from 'node:assert/strict';
import {
  API_KEYS_PAGE_DESCRIPTION,
  ACCESS_PROFILE_OPTIONS,
  apiKeyCreatePayload,
  accessProfilePermissionSummary,
  accessProfileLabel,
  API_DOCS_PATH,
  MCP_ENDPOINT_PATH,
  MCP_HELP_TEXT
} from './apiKeysPage.js';

test('page description is generic (not Published Feed-only)', () => {
  assert.match(API_KEYS_PAGE_DESCRIPTION, /programmatic access/i);
  assert.doesNotMatch(API_KEYS_PAGE_DESCRIPTION, /Published Feed keys let/i);
});

test('five fixed access profiles are exposed including MCP', () => {
  assert.equal(ACCESS_PROFILE_OPTIONS.length, 5);
  assert.deepEqual(
    ACCESS_PROFILE_OPTIONS.map((o) => o.id).sort(),
    ['ioc_management', 'ioc_read', 'mcp_analyst', 'mcp_read', 'published_feed']
  );
  const mcpRead = ACCESS_PROFILE_OPTIONS.find((o) => o.id === 'mcp_read');
  assert.match(mcpRead.description, /owner/i);
  assert.match(mcpRead.description, /MCP/i);
  const mcpAnalyst = ACCESS_PROFILE_OPTIONS.find((o) => o.id === 'mcp_analyst');
  assert.match(mcpAnalyst.description, /import/i);
  assert.match(mcpAnalyst.description, /owner/i);
});

test('create payload maps profile selection correctly', () => {
  const pf = apiKeyCreatePayload({ name: 'fw-1', accessProfile: 'published_feed' });
  assert.equal(pf.ok, true);
  assert.equal(pf.body.access_profile, 'published_feed');
  assert.equal(pf.body.key_type, 'published_feed');
  assert.equal(pf.body.owner_user_id, undefined);

  const ioc = apiKeyCreatePayload({ name: 'bot', accessProfile: 'ioc_management' });
  assert.equal(ioc.ok, true);
  assert.equal(ioc.body.access_profile, 'ioc_management');

  const read = apiKeyCreatePayload({ name: 'siem', accessProfile: 'ioc_read' });
  assert.equal(read.ok, true);
  assert.equal(read.body.access_profile, 'ioc_read');

  const bad = apiKeyCreatePayload({ name: '', accessProfile: 'published_feed' });
  assert.equal(bad.ok, false);
});

test('MCP create payload requires owner binding', () => {
  const missing = apiKeyCreatePayload({ name: 'mcp-1', accessProfile: 'mcp_read' });
  assert.equal(missing.ok, false);
  assert.ok(missing.errors.includes('owner'));

  const byId = apiKeyCreatePayload({
    name: 'mcp-1',
    accessProfile: 'mcp_read',
    ownerUserId: 42
  });
  assert.equal(byId.ok, true);
  assert.equal(byId.body.owner_user_id, 42);
  assert.equal(byId.body.access_profile, 'mcp_read');

  const byPublic = apiKeyCreatePayload({
    name: 'mcp-2',
    accessProfile: 'mcp_analyst',
    ownerPublicId: '11111111-1111-4111-8111-111111111111'
  });
  assert.equal(byPublic.ok, true);
  assert.equal(byPublic.body.owner_public_id, '11111111-1111-4111-8111-111111111111');
  assert.equal(byPublic.body.access_profile, 'mcp_analyst');
});

test('table labels and permission summaries', () => {
  assert.equal(accessProfileLabel('published_feed'), 'Published Feed');
  assert.equal(accessProfileLabel('ioc_management'), 'IOC Management');
  assert.equal(accessProfilePermissionSummary('published_feed'), 'Read feeds');
  assert.equal(accessProfilePermissionSummary('ioc_management'), 'Create + Update IOCs');
  assert.equal(accessProfileLabel('ioc_read'), 'IOC Read');
  assert.equal(accessProfilePermissionSummary('ioc_read'), 'Read + Search + Export IOCs');
  assert.equal(accessProfileLabel('mcp_read'), 'MCP Read');
  assert.equal(accessProfileLabel('mcp_analyst'), 'MCP Analyst');
  assert.equal(API_DOCS_PATH, '/api/docs');
  assert.equal(MCP_ENDPOINT_PATH, '/mcp');
  assert.match(MCP_HELP_TEXT, /\/mcp/);
});
