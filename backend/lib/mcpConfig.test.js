import test from 'node:test';
import assert from 'node:assert/strict';
import { MCP_DEFAULTS, getMcpConfig, isMcpEnabled } from './mcpConfig.js';

test('isMcpEnabled defaults to true', () => {
  assert.equal(isMcpEnabled({}), true);
  assert.equal(isMcpEnabled({ MCP_ENABLED: '' }), true);
});

test('isMcpEnabled respects disable/enable env', () => {
  assert.equal(isMcpEnabled({ MCP_ENABLED: '0' }), false);
  assert.equal(isMcpEnabled({ MCP_ENABLED: 'false' }), false);
  assert.equal(isMcpEnabled({ MCP_ENABLED: 'off' }), false);
  assert.equal(isMcpEnabled({ MCP_ENABLED: '1' }), true);
  assert.equal(isMcpEnabled({ MCP_ENABLED: 'true' }), true);
  assert.equal(isMcpEnabled({ MCP_ENABLED: 'yes' }), true);
});

test('getMcpConfig returns secure defaults', () => {
  const cfg = getMcpConfig({});
  assert.equal(cfg.enabled, MCP_DEFAULTS.ENABLED);
  assert.equal(cfg.bulkLookupMax, MCP_DEFAULTS.BULK_LOOKUP_MAX);
  assert.equal(cfg.importMax, MCP_DEFAULTS.IMPORT_MAX);
  assert.equal(cfg.searchPageMax, MCP_DEFAULTS.SEARCH_PAGE_MAX);
  assert.equal(cfg.valueMaxChars, MCP_DEFAULTS.VALUE_MAX_CHARS);
  assert.equal(cfg.rateLimitPerMin, MCP_DEFAULTS.RATE_LIMIT_PER_MIN);
  assert.equal(cfg.rateLimitImportPerMin, MCP_DEFAULTS.RATE_LIMIT_IMPORT_PER_MIN);
  assert.equal(cfg.rateLimitSearchPerMin, MCP_DEFAULTS.RATE_LIMIT_SEARCH_PER_MIN);
  assert.equal(cfg.rateLimitBulkPerMin, MCP_DEFAULTS.RATE_LIMIT_BULK_PER_MIN);
});

test('getMcpConfig applies env overrides with clamping', () => {
  const cfg = getMcpConfig({
    MCP_ENABLED: 'false',
    MCP_BULK_LOOKUP_MAX: '250',
    MCP_IMPORT_MAX: '10',
    MCP_SEARCH_PAGE_MAX: '80',
    MCP_VALUE_MAX_CHARS: '512',
    MCP_RATE_LIMIT_PER_MIN: '200',
    MCP_RATE_LIMIT_IMPORT_PER_MIN: '5',
    MCP_RATE_LIMIT_SEARCH_PER_MIN: '40',
    MCP_RATE_LIMIT_BULK_PER_MIN: '45'
  });
  assert.equal(cfg.enabled, false);
  assert.equal(cfg.bulkLookupMax, 250);
  assert.equal(cfg.importMax, 10);
  assert.equal(cfg.searchPageMax, 80);
  assert.equal(cfg.valueMaxChars, 512);
  assert.equal(cfg.rateLimitPerMin, 200);
  assert.equal(cfg.rateLimitImportPerMin, 5);
  assert.equal(cfg.rateLimitSearchPerMin, 40);
  assert.equal(cfg.rateLimitBulkPerMin, 45);

  const clamped = getMcpConfig({
    MCP_BULK_LOOKUP_MAX: '9999',
    MCP_SEARCH_PAGE_MAX: '0',
    MCP_VALUE_MAX_CHARS: '10'
  });
  assert.equal(clamped.bulkLookupMax, 500);
  assert.equal(clamped.searchPageMax, 1);
  assert.equal(clamped.valueMaxChars, 64);
});
