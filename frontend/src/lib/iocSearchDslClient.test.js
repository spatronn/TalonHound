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

test('md5/sha1/sha256 are registered hash fields with equals only', () => {
  for (const name of ['md5', 'sha1', 'sha256']) {
    const f = FIELD_BY_NAME[name];
    assert.ok(f, `${name} field must be registered`);
    assert.equal(f.kind, 'hash');
    assert.deepEqual(f.operators, ['equals'], `${name} must offer only equals`);
    assert.equal(defaultOperatorFor(name), 'equals');
  }
});

test('hash conditions generate the exact equals DSL syntax', () => {
  assert.equal(
    conditionToDsl({ field: 'md5', operator: 'equals', value: '20945449fd11203d79ea5d0d29bf1e22' }),
    'md5 equals "20945449fd11203d79ea5d0d29bf1e22"'
  );
  assert.equal(
    conditionToDsl({ field: 'sha1', operator: 'equals', value: '0017b2e0d74be3c58ab319c29a84de9f3e3bedee' }),
    'sha1 equals "0017b2e0d74be3c58ab319c29a84de9f3e3bedee"'
  );
  assert.equal(
    conditionToDsl({ field: 'sha256', operator: 'equals', value: 'dd55cbafbf914c8bb7eee34acfc65876d96b21de2ba8f320737cf8d280a347e6' }),
    'sha256 equals "dd55cbafbf914c8bb7eee34acfc65876d96b21de2ba8f320737cf8d280a347e6"'
  );
});

test('newCondition for a hash field seeds equals', () => {
  assert.deepEqual(newCondition('sha256'), { field: 'sha256', operator: 'equals', value: '', value2: '' });
});

test('Type dropdown no longer offers imphash/tlsh/ssdeep (not IOC types)', () => {
  const typeValues = FIELD_BY_NAME.type.values;
  for (const bad of ['imphash', 'tlsh', 'ssdeep']) {
    assert.ok(!typeValues.includes(bad), `type must not offer ${bad}`);
  }
  // real IOC identity types remain
  assert.deepEqual(typeValues, ['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256']);
});

test('imphash/tlsh/ssdeep are registered attr fields with equals only', () => {
  for (const name of ['imphash', 'tlsh', 'ssdeep']) {
    const f = FIELD_BY_NAME[name];
    assert.ok(f, `${name} field must be registered`);
    assert.equal(f.kind, 'attr');
    assert.deepEqual(f.operators, ['equals'], `${name} must offer only equals`);
    assert.equal(defaultOperatorFor(name), 'equals');
  }
});

test('attr conditions generate the exact equals DSL syntax (ssdeep quoted with colons)', () => {
  assert.equal(
    conditionToDsl({ field: 'imphash', operator: 'equals', value: 'f34d5f2d4577ed6d9ceec516c1f5a744' }),
    'imphash equals "f34d5f2d4577ed6d9ceec516c1f5a744"'
  );
  assert.equal(
    conditionToDsl({ field: 'ssdeep', operator: 'equals', value: '3072:Etd/dEZOS3hE0:M4OS3C3yj' }),
    'ssdeep equals "3072:Etd/dEZOS3hE0:M4OS3C3yj"'
  );
});
