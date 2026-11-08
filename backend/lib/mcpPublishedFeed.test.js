import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { authorizeMcpTool, MCP_TOOL_SCOPES } from './mcpPermissions.js';
import { ACCESS_PROFILE, API_SCOPE, scopesForAccessProfile } from './apiKeyProfiles.js';
import { mcpCreatePublishedFeed, mcpUpdatePublishedFeed } from './mcpPublishedFeedService.js';

const READ_SCOPES = scopesForAccessProfile(ACCESS_PROFILE.MCP_READ);
const ANALYST_SCOPES = scopesForAccessProfile(ACCESS_PROFILE.MCP_ANALYST);

describe('MCP Published Feed scopes', () => {
  it('profiles carry published feed scopes', () => {
    assert.ok(READ_SCOPES.includes(API_SCOPE.MCP_PUBLISHED_FEEDS_READ));
    assert.ok(!READ_SCOPES.includes(API_SCOPE.MCP_PUBLISHED_FEEDS_WRITE));
    assert.ok(ANALYST_SCOPES.includes(API_SCOPE.MCP_PUBLISHED_FEEDS_READ));
    assert.ok(ANALYST_SCOPES.includes(API_SCOPE.MCP_PUBLISHED_FEEDS_WRITE));
  });

  it('read tools need mcp:published_feeds:read', () => {
    for (const name of [
      'list_published_feeds',
      'get_published_feed',
      'preview_published_feed',
      'get_published_feed_membership'
    ]) {
      assert.deepEqual(MCP_TOOL_SCOPES[name], [API_SCOPE.MCP_PUBLISHED_FEEDS_READ]);
      assert.equal(authorizeMcpTool(name, { scopes: READ_SCOPES, ownerRole: 'readonly' }).ok, true);
      assert.equal(
        authorizeMcpTool(name, { scopes: [API_SCOPE.MCP_IOC_READ], ownerRole: 'admin' }).code,
        'MISSING_SCOPE'
      );
    }
  });

  it('write tools need write scope + ADMIN owner', () => {
    for (const name of ['create_published_feed', 'update_published_feed', 'regenerate_published_feed']) {
      assert.deepEqual(MCP_TOOL_SCOPES[name], [API_SCOPE.MCP_PUBLISHED_FEEDS_WRITE]);
      assert.equal(authorizeMcpTool(name, { scopes: ANALYST_SCOPES, ownerRole: 'admin' }).ok, true);
      assert.equal(
        authorizeMcpTool(name, { scopes: ANALYST_SCOPES, ownerRole: 'analyst' }).code,
        'RBAC_DENIED'
      );
      assert.equal(
        authorizeMcpTool(name, {
          scopes: [API_SCOPE.MCP_PUBLISHED_FEEDS_READ],
          ownerRole: 'admin'
        }).code,
        'MISSING_SCOPE'
      );
    }
  });
});

describe('MCP Published Feed dry_run', () => {
  it('create_published_feed dry_run does not insert', async () => {
    let connected = false;
    const pool = {
      connect: async () => {
        connected = true;
        throw new Error('should not connect on dry_run');
      },
      query: async () => ({ rows: [] })
    };
    const out = await mcpCreatePublishedFeed(pool, {
      name: 'Dry',
      filter_mode: 'basic',
      ioc_types: ['ip'],
      formats: ['txt'],
      dry_run: true
    }, {});
    assert.equal(out.error, undefined);
    assert.equal(out.body.dry_run, true);
    assert.equal(connected, false);
  });

  it('update_published_feed dry_run returns would_update', async () => {
    const pool = {
      query: async (sql) => {
        if (String(sql).startsWith('SELECT * FROM published_feeds')) {
          return {
            rows: [{
              id: 3,
              name: 'Existing',
              filter_mode: 'basic',
              ioc_types: JSON.stringify(['ip']),
              formats: JSON.stringify(['txt']),
              time_window: 'all',
              refresh_interval_minutes: 15,
              enabled: true
            }]
          };
        }
        throw new Error(`unexpected query: ${sql}`);
      },
      connect: async () => {
        throw new Error('should not connect on dry_run');
      }
    };
    const out = await mcpUpdatePublishedFeed(pool, {
      id: 3,
      name: 'Renamed',
      dry_run: true
    }, {});
    assert.equal(out.error, undefined);
    assert.equal(out.body.dry_run, true);
    assert.equal(out.body.would_update.id, 3);
  });
});
