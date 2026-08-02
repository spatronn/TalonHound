import test from 'node:test';
import assert from 'node:assert/strict';
import { feedFieldDomIds, mergeAriaDescribedBy } from './feedFormField.js';

test('feedFieldDomIds derives helper and error ids', () => {
  assert.deepEqual(feedFieldDomIds(':r1:'), {
    fieldId: ':r1:',
    helperId: ':r1:-helper',
    errorId: ':r1:-error'
  });
});

test('mergeAriaDescribedBy joins existing + helper + error', () => {
  assert.equal(
    mergeAriaDescribedBy({ existing: 'hint', helperId: 'h', errorId: 'e' }),
    'hint h e'
  );
  assert.equal(mergeAriaDescribedBy({}), undefined);
  assert.equal(mergeAriaDescribedBy({ helperId: 'h' }), 'h');
});
