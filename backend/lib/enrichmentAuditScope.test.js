import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildEnrichmentAuditScope } from './enrichmentAuditScope.js';

test('resolveSubjectIocFromRequest is exported as async resolver module surface', async () => {
  const mod = await import('./enrichmentAuditScope.js');
  assert.equal(typeof mod.resolveSubjectIocFromRequest, 'function');
});

test('DNSMania-style scope uses hostname target and URL subject', () => {
  const scope = buildEnrichmentAuditScope({
    subjectIocId: 99,
    subjectIocType: 'url',
    subjectIocValue: 'https://raw.githubusercontent.com/b/project/file2.zip',
    targetType: 'domain',
    targetValue: 'raw.githubusercontent.com',
    provider: 'dnsmania'
  });
  assert.equal(scope.entityDisplay, 'https://raw.githubusercontent.com/b/project/file2.zip');
  assert.equal(scope.targetValue, 'raw.githubusercontent.com');
  assert.equal(scope.metadata.lookup_value, undefined);
});
