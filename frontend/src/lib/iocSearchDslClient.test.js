import test from 'node:test';
import assert from 'node:assert/strict';
import {
  conditionToDsl,
  buildDslFromConditions,
  defaultOperatorFor,
  newCondition,
  chipLabel,
  FIELD_BY_NAME
} from './iocSearchDslClient.js';

test('scalar text condition', () => {
  assert.equal(conditionToDsl({ field: 'ioc', operator: 'contains', value: 'example.com' }), 'ioc contains "example.com"');
});

test('value with quotes is escaped', () => {
  assert.equal(conditionToDsl({ field: 'source', operator: 'equals', value: 'a "b" c' }), 'source equals "a \\"b\\" c"');
});

test('in list condition', () => {
  assert.equal(conditionToDsl({ field: 'type', operator: 'in', value: 'domain, url' }), 'type in ("domain", "url")');
});

test('between date condition', () => {
  assert.equal(
    conditionToDsl({ field: 'first_seen', operator: 'between', value: '2026-07-01', value2: '2026-07-22' }),
    'first_seen between "2026-07-01" AND "2026-07-22"'
  );
});

test('incomplete conditions produce empty string', () => {
  assert.equal(conditionToDsl({ field: 'ioc', operator: 'contains', value: '' }), '');
  assert.equal(conditionToDsl({ field: 'first_seen', operator: 'between', value: '2026-07-01', value2: '' }), '');
  assert.equal(conditionToDsl({ field: 'type', operator: 'in', value: '   ' }), '');
});

test('Match All joins with AND', () => {
  const dsl = buildDslFromConditions('all', [
    { field: 'ioc', operator: 'contains', value: 'example' },
    { field: 'tag', operator: 'contains', value: 'mirai' }
  ]);
  assert.equal(dsl, 'ioc contains "example" AND tag contains "mirai"');
});

test('Match Any joins with OR', () => {
  const dsl = buildDslFromConditions('any', [
    { field: 'source', operator: 'equals', value: 'USOM' },
    { field: 'source', operator: 'equals', value: 'URLHaus' }
  ]);
  assert.equal(dsl, 'source equals "USOM" OR source equals "URLHaus"');
});

test('empty conditions dropped from generated DSL', () => {
  const dsl = buildDslFromConditions('all', [
    { field: 'ioc', operator: 'contains', value: 'example' },
    { field: 'tag', operator: 'contains', value: '' }
  ]);
  assert.equal(dsl, 'ioc contains "example"');
});

test('generated DSL matches the documented example', () => {
  const dsl = buildDslFromConditions('all', [
    { field: 'type', operator: 'in', value: 'domain, url' },
    { field: 'status', operator: 'equals', value: 'active' }
  ]);
  assert.equal(dsl, 'type in ("domain", "url") AND status equals "active"');
});

test('defaultOperatorFor by kind', () => {
  assert.equal(defaultOperatorFor('ioc'), 'contains');
  assert.equal(defaultOperatorFor('status'), 'equals');
  assert.equal(defaultOperatorFor('first_seen'), 'after');
});

test('newCondition seeds a sensible default operator', () => {
  assert.deepEqual(newCondition('tag'), { field: 'tag', operator: 'contains', value: '', value2: '' });
});

test('chipLabel formats API condition summaries', () => {
  assert.equal(chipLabel({ field: 'ioc', operator: 'contains', values: ['example.com'] }), 'IOC contains: example.com');
  assert.equal(chipLabel({ field: 'status', operator: 'equals', values: ['active'] }), 'Status equals: active');
  assert.equal(chipLabel({ field: 'first_seen', operator: 'between', dates: ['2026-07-01', '2026-07-22'] }), 'First seen in source between: 2026-07-01 – 2026-07-22');
});

test('source field hint documents display name + canonical search', () => {
  const hint = FIELD_BY_NAME.source?.hint || '';
  assert.match(hint, /display name/i);
  assert.match(hint, /USOM:TR-CERT/);
});
