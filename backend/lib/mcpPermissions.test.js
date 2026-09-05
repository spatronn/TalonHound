import test from 'node:test';
import assert from 'node:assert/strict';
import { API_SCOPE } from './apiKeyProfiles.js';
import { ROLES } from './rbac.js';
import {
  authorizeMcpTool,
  effectiveMcpCapabilities,
  MCP_TOOL_SCOPES
} from './mcpPermissions.js';

const READ_SCOPES = [
  API_SCOPE.MCP_IOC_READ,
  API_SCOPE.MCP_SOURCES_READ,
  API_SCOPE.MCP_ENRICHMENT_READ
];

const ANALYST_SCOPES = [
  ...READ_SCOPES,
  API_SCOPE.MCP_IOC_CREATE
];

test('MCP_TOOL_SCOPES covers expected tools', () => {
  assert.ok(MCP_TOOL_SCOPES.lookup_ioc);
  assert.ok(MCP_TOOL_SCOPES.import_iocs);
  assert.ok(MCP_TOOL_SCOPES.list_ioc_sources);
});

test('read token cannot import', () => {
  const gate = authorizeMcpTool('import_iocs', {
    scopes: READ_SCOPES,
    ownerRole: ROLES.ANALYST
  });
  assert.equal(gate.ok, false);
  assert.equal(gate.code, 'MISSING_SCOPE');
  assert.match(gate.message, /mcp:ioc:create/i);
});

test('create scope + readonly owner cannot import', () => {
  const caps = effectiveMcpCapabilities({ scopes: ANALYST_SCOPES, ownerRole: ROLES.READONLY });
  assert.equal(caps.ioc_create, false);
  assert.equal(caps.owner_readonly, true);

  const gate = authorizeMcpTool('import_iocs', {
    scopes: ANALYST_SCOPES,
    ownerRole: ROLES.READONLY
  });
  assert.equal(gate.ok, false);
  assert.equal(gate.code, 'RBAC_DENIED');
  assert.match(gate.message, /not permitted to create/i);
});

test('create scope + analyst can import', () => {
  const gate = authorizeMcpTool('import_iocs', {
    scopes: ANALYST_SCOPES,
    ownerRole: ROLES.ANALYST
  });
  assert.equal(gate.ok, true);
});

test('admin without create scope cannot import', () => {
  const gate = authorizeMcpTool('import_iocs', {
    scopes: READ_SCOPES,
    ownerRole: ROLES.ADMIN
  });
  assert.equal(gate.ok, false);
  assert.equal(gate.code, 'MISSING_SCOPE');
});

test('missing scope messages for read tools', () => {
  const gate = authorizeMcpTool('lookup_ioc', {
    scopes: [],
    ownerRole: ROLES.ANALYST
  });
  assert.equal(gate.ok, false);
  assert.equal(gate.code, 'MISSING_SCOPE');
  assert.match(gate.message, /mcp:ioc:read/);

  const sources = authorizeMcpTool('list_ioc_sources', {
    scopes: [API_SCOPE.MCP_IOC_READ],
    ownerRole: ROLES.ANALYST
  });
  assert.equal(sources.ok, false);
  assert.equal(sources.code, 'MISSING_SCOPE');
  assert.match(sources.message, /mcp:sources:read/);
});

test('unknown tool is rejected', () => {
  const gate = authorizeMcpTool('delete_everything', {
    scopes: ANALYST_SCOPES,
    ownerRole: ROLES.ADMIN
  });
  assert.equal(gate.ok, false);
  assert.equal(gate.code, 'UNKNOWN_TOOL');
});
