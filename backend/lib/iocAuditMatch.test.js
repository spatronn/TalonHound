import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildIocAuditMatchContext, buildIocAuditLogsWhere } from './iocAuditMatch.js';

test('URL IOC match context includes root domain and host', () => {
  const ctx = buildIocAuditMatchContext({
    id: 42,
    public_id: '11111111-1111-4111-8111-111111111111',
    observable: 'https://netflix-accounts.info/auth/login.php',
    observable_type: 'url'
  });
  assert.equal(ctx.rootDomain, 'netflix-accounts.info');
  assert.ok(ctx.entityIds.includes('netflix-accounts.info'));
  assert.ok(ctx.entityIds.includes('42'));
  assert.ok(ctx.entityDisplays.includes('https://netflix-accounts.info/auth/login.php'));
});

test('buildIocAuditLogsWhere includes enrichment root_domain match', () => {
  const ctx = buildIocAuditMatchContext({
    id: 7,
    observable: 'ravonella.com',
    observable_type: 'domain'
  });
  const { whereSql, params } = buildIocAuditLogsWhere(ctx);
  assert.match(whereSql, /entity_type = 'enrichment'/);
  assert.ok(params[0].includes('ravonella.com'));
});
