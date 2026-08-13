import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseSavedSearchWrite,
  SAVED_SEARCH_NAME_MAX
} from './iocSavedSearchStore.js';

test('parseSavedSearchWrite accepts a valid DSL query', () => {
  const r = parseSavedSearchWrite({
    name: '  Mirai domains  ',
    query: 'type equals "domain" AND tag contains "mirai"',
    description: ' weekly '
  });
  assert.equal(r.ok, true);
  assert.equal(r.name, 'Mirai domains');
  assert.equal(r.description, 'weekly');
  assert.ok(r.parsed.normalizedQuery);
});

test('parseSavedSearchWrite rejects empty name and invalid DSL', () => {
  const empty = parseSavedSearchWrite({ name: '  ', query: 'type equals "domain"' });
  assert.equal(empty.ok, false);
  assert.ok(empty.errors.includes('name'));

  const dsl = parseSavedSearchWrite({ name: 'x', query: 'severity equals "high"' });
  assert.equal(dsl.ok, false);
  assert.ok(dsl.dslError);

  const long = parseSavedSearchWrite({ name: 'n'.repeat(SAVED_SEARCH_NAME_MAX + 1), query: 'type equals "domain"' });
  assert.equal(long.ok, false);
});

test('parseSavedSearchWrite can omit name or query when not required', () => {
  const rename = parseSavedSearchWrite({ name: 'New name' }, { requireQuery: false, requireName: true });
  assert.equal(rename.ok, true);
  assert.equal(rename.name, 'New name');
  assert.equal(rename.parsed, null);

  const requery = parseSavedSearchWrite({ query: 'type equals "ip"' }, { requireQuery: true, requireName: false });
  assert.equal(requery.ok, true);
  assert.ok(requery.parsed);
});
