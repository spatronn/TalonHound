import test from 'node:test';
import assert from 'node:assert/strict';
import { savedSearchCreatePayload, savedSearchErrorMessage } from './iocSavedSearches.js';

test('savedSearchCreatePayload requires name and query', () => {
  assert.equal(savedSearchCreatePayload({ name: '', query: 'type equals "ip"' }).ok, false);
  assert.equal(savedSearchCreatePayload({ name: 'x', query: '  ' }).ok, false);
  const ok = savedSearchCreatePayload({ name: ' Mirai ', query: 'type equals "domain"', description: ' weekly ' });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.body, { name: 'Mirai', query: 'type equals "domain"', description: 'weekly' });
});

test('savedSearchErrorMessage maps duplicate code', () => {
  assert.equal(
    savedSearchErrorMessage({ code: 'SAVED_SEARCH_NAME_DUPLICATE', message: 'x' }),
    'A saved search with this name already exists.'
  );
  assert.equal(savedSearchErrorMessage({ message: 'nope' }), 'nope');
});
