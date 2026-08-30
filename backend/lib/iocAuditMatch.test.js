import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildIocAuditMatchContext, buildIocAuditLogsWhere } from './iocAuditMatch.js';
import { buildEnrichmentAuditScope } from './enrichmentAuditScope.js';

test('URL IOC match context does not include shared host or root domain', () => {
  const ctx = buildIocAuditMatchContext({
    id: 42,
    public_id: '11111111-1111-4111-8111-111111111111',
    observable: 'https://raw.githubusercontent.com/a/project/file1.zip',
    observable_type: 'url'
  });
  assert.equal(ctx.rootDomain, null);
  assert.equal(ctx.normalizedHost, null);
  assert.ok(!ctx.entityIds.includes('githubusercontent.com'));
  assert.ok(!ctx.entityIds.includes('raw.githubusercontent.com'));
  assert.ok(ctx.entityIds.includes('42'));
  assert.ok(ctx.entityIds.includes('11111111-1111-4111-8111-111111111111'));
  assert.ok(ctx.entityDisplays.includes('https://raw.githubusercontent.com/a/project/file1.zip'));
  assert.ok(ctx.exactObservables.includes('https://raw.githubusercontent.com/a/project/file1.zip'));
});

test('domain IOC still matches its own domain value as entity id', () => {
  const ctx = buildIocAuditMatchContext({
    id: 7,
    observable: 'ravonella.com',
    observable_type: 'domain'
  });
  assert.ok(ctx.entityIds.includes('ravonella.com'));
  assert.ok(ctx.exactObservables.includes('ravonella.com'));
});

test('enrichment WHERE prefers subject_ioc_id and excludes root_domain match', () => {
  const ctx = buildIocAuditMatchContext({
    id: 7,
    observable: 'https://raw.githubusercontent.com/a/project/file1.zip',
    observable_type: 'url'
  });
  const { whereSql, params } = buildIocAuditLogsWhere(ctx);
  assert.match(whereSql, /subject_ioc_id/);
  assert.match(whereSql, /metadata->>'ioc_id'/);
  assert.match(whereSql, /entity_type = 'ioc'/);
  assert.doesNotMatch(whereSql, /metadata->>'root_domain'/);
  assert.doesNotMatch(whereSql, /metadata->>'ip'/);
  assert.equal(params[2], '7');
  assert.ok(params[3].includes('https://raw.githubusercontent.com/a/project/file1.zip'));
  assert.ok(!params[0].includes('githubusercontent.com'));
  assert.ok(!params[0].includes('raw.githubusercontent.com'));
});

test('two URL IOCs sharing hostname produce disjoint enrichment match keys', () => {
  const a = buildIocAuditMatchContext({
    id: 101,
    public_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    observable: 'https://raw.githubusercontent.com/zhengzhangqian888/construction-company/main/assets/company_construction_v3.1-alpha.2.zip',
    observable_type: 'url'
  });
  const b = buildIocAuditMatchContext({
    id: 202,
    public_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    observable: 'https://raw.githubusercontent.com/Hugo564/Hack-for-green/main/docs/Hack-for-green-2.2.zip',
    observable_type: 'url'
  });

  const shared = a.entityIds.filter((id) => b.entityIds.includes(id));
  assert.deepEqual(shared, []);

  const sharedDisplays = a.exactObservables.filter((v) => b.exactObservables.includes(v));
  assert.deepEqual(sharedDisplays, []);

  const whereA = buildIocAuditLogsWhere(a);
  const whereB = buildIocAuditLogsWhere(b);
  assert.equal(whereA.params[2], '101');
  assert.equal(whereB.params[2], '202');
  assert.notEqual(whereA.params[3][0], whereB.params[3][0]);
});

test('buildEnrichmentAuditScope separates subject IOC from technical target', () => {
  const scope = buildEnrichmentAuditScope({
    subject: {
      id: 12345,
      public_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      observable: 'https://raw.githubusercontent.com/a/file.zip',
      observable_type: 'url'
    },
    targetType: 'domain',
    targetValue: 'githubusercontent.com',
    provider: 'rdap',
    extraMetadata: { force: true, root_domain: 'githubusercontent.com' }
  });

  assert.equal(scope.entityId, 'cccccccc-cccc-4ccc-8ccc-cccccccccccc');
  assert.equal(scope.entityDisplay, 'https://raw.githubusercontent.com/a/file.zip');
  assert.equal(scope.subjectIocId, 12345);
  assert.equal(scope.targetValue, 'githubusercontent.com');
  assert.equal(scope.metadata.subject_ioc_id, '12345');
  assert.equal(scope.metadata.ioc_id, '12345');
  assert.equal(scope.metadata.target_value, 'githubusercontent.com');
  assert.equal(scope.metadata.root_domain, 'githubusercontent.com');
});

test('legacy enrichment fallback matches only exact original_value not host', () => {
  const ctx = buildIocAuditMatchContext({
    id: 1,
    observable: 'https://raw.githubusercontent.com/a/file1.zip',
    observable_type: 'url'
  });
  const { whereSql } = buildIocAuditLogsWhere(ctx);
  // Host-only entity_display would not be in $4 exactObservables for URL IOC-2
  assert.match(whereSql, /original_value/);
  assert.ok(ctx.exactObservables.every((v) => v.includes('/a/file1.zip')));
});
