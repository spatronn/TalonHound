import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSearchQuery, renderNormalizedQuery, flattenConditions } from './index.js';
import { parseDsl } from './parser.js';
import { DslError } from './errors.js';

function parse(q) {
  return parseSearchQuery(q).ast;
}

function expectError(q, code) {
  assert.throws(
    () => parseSearchQuery(q),
    (err) => {
      assert.ok(err instanceof DslError, `expected DslError, got ${err}`);
      if (code) assert.equal(err.code, code, `expected code ${code}, got ${err.code} (${err.message})`);
      return true;
    }
  );
}

test('simple condition', () => {
  const ast = parse('ioc contains "example.com"');
  assert.equal(ast.type, 'condition');
  assert.equal(ast.field, 'ioc');
  assert.equal(ast.operator, 'contains');
  assert.deepEqual(ast.values, ['example.com']);
});

test('AND combination', () => {
  const ast = parse('ioc contains "example" AND tag contains "mirai"');
  assert.equal(ast.type, 'and');
  assert.equal(ast.children.length, 2);
  assert.equal(ast.children[0].field, 'ioc');
  assert.equal(ast.children[1].field, 'tag');
});

test('OR combination', () => {
  const ast = parse('source equals "USOM" OR source equals "URLHaus"');
  assert.equal(ast.type, 'or');
  assert.equal(ast.children.length, 2);
});

test('NOT unary', () => {
  const ast = parse('NOT tag equals "benign"');
  assert.equal(ast.type, 'not');
  assert.equal(ast.child.field, 'tag');
});

test('nested parenthesis and precedence', () => {
  // AND binds tighter than OR: a OR b AND c === a OR (b AND c)
  const ast = parse('ioc contains "a" OR ioc contains "b" AND tag equals "x"');
  assert.equal(ast.type, 'or');
  assert.equal(ast.children[1].type, 'and');
});

test('explicit parentheses override precedence', () => {
  const ast = parse('(ioc contains "a" OR ioc contains "b") AND tag equals "x"');
  assert.equal(ast.type, 'and');
  assert.equal(ast.children[0].type, 'or');
});

test('case-insensitive fields and keywords, canonical AST', () => {
  const ast = parse('IOC CONTAINS "x" and TAG Equals "y"');
  assert.equal(ast.type, 'and');
  assert.equal(ast.children[0].field, 'ioc');
  assert.equal(ast.children[0].operator, 'contains');
  assert.equal(ast.children[1].operator, 'equals');
});

test('escaped quote inside value', () => {
  const ast = parse('source equals "acme \\"quoted\\" src"');
  assert.deepEqual(ast.values, ['acme "quoted" src']);
});

test('IN list', () => {
  const ast = parse('type in ("domain", "url")');
  assert.equal(ast.operator, 'in');
  assert.deepEqual(ast.values, ['domain', 'url']);
});

test('NOT_IN list on source', () => {
  const ast = parse('source not_in ("USOM", "URLHaus")');
  assert.equal(ast.operator, 'not_in');
  assert.deepEqual(ast.values, ['USOM', 'URLHaus']);
});

test('date before / after', () => {
  const before = parse('last_changed before "2026-07-22"');
  assert.equal(before.kind, 'date');
  assert.equal(before.dates[0].display, '2026-07-22');
  const after = parse('first_seen after "2026-07-01 18:00:00"');
  assert.equal(after.dates[0].display, '2026-07-01 18:00:00');
});

test('date between', () => {
  const ast = parse('first_seen between "2026-07-01" AND "2026-07-22"');
  assert.equal(ast.operator, 'between');
  assert.equal(ast.dates.length, 2);
});

test('ISO-8601 with timezone is accepted and flagged', () => {
  const ast = parse('created_at after "2026-07-01T18:00:00Z"');
  assert.equal(ast.dates[0].hasTimezone, true);
});

test('invalid field', () => expectError('severity equals "high"', 'unknown_field'));

test('invalid operator for field', () =>
  expectError('status contains "active"', 'unsupported_operator'));

test('invalid enum value', () => expectError('type equals "banana"', 'invalid_enum_value'));

test('invalid date', () => expectError('first_seen after "22/07/2026"', 'invalid_date'));

test('empty value rejected', () => expectError('ioc contains ""', 'empty_value'));

test('wildcard-only value rejected', () => expectError('ioc contains "%"', 'empty_value'));

test('broad but valid single-char value allowed', () => {
  const ast = parse('ioc contains "a"');
  assert.deepEqual(ast.values, ['a']);
});

test('unclosed quote', () => expectError('ioc contains "example', 'unclosed_quote'));

test('unclosed parenthesis', () =>
  expectError('(ioc contains "a" AND tag equals "b"', 'unclosed_parenthesis'));

test('missing quoted value after equals', () =>
  expectError('status equals active', 'expected_value'));

test('plain text without operator is rejected (no free-text fallback)', () =>
  expectError('example.com'));

test('query length limit', () => {
  const limits = { maxQueryLength: 4000, maxConditions: 30, maxParenthesesDepth: 8, maxInItems: 100 };
  const huge = 'ioc contains "' + 'a'.repeat(5000) + '"';
  assert.throws(
    () => parseSearchQuery(huge, { limits }),
    (err) => err instanceof DslError && err.code === 'max_length_exceeded'
  );
});

test('condition count limit', () => {
  const parts = [];
  for (let i = 0; i < 31; i += 1) parts.push('ioc contains "x"');
  expectError(parts.join(' AND '), 'max_conditions_exceeded');
});

test('parenthesis depth limit', () => {
  const limits = { maxQueryLength: 4000, maxConditions: 30, maxParenthesesDepth: 3, maxInItems: 100 };
  const q = '((((ioc contains "a"))))';
  assert.throws(
    () => parseSearchQuery(q, { limits }),
    (err) => err instanceof DslError && err.code === 'max_depth_exceeded'
  );
});

test('IN item count limit', () => {
  const limits = { maxQueryLength: 40000, maxConditions: 30, maxParenthesesDepth: 8, maxInItems: 3 };
  const q = 'type in ("ip", "ipv6", "domain", "url")';
  assert.throws(
    () => parseSearchQuery(q, { limits }),
    (err) => err instanceof DslError && err.code === 'max_in_items_exceeded'
  );
});

test('SQL injection payload stays a plain value in the AST', () => {
  const ast = parse('ioc contains "\'; DROP TABLE ioc_items; --"');
  assert.deepEqual(ast.values, ["'; DROP TABLE ioc_items; --"]);
});

test('normalized query round-trips and re-parses', () => {
  const input = '(ioc contains "example" OR ioc contains "microsoft") AND tag equals "phishing"';
  const { normalizedQuery, ast } = parseSearchQuery(input);
  // Re-parsing the normalized form yields an equivalent structure.
  const reparsed = parseDsl(normalizedQuery);
  assert.equal(reparsed.type, 'and');
  assert.equal(reparsed.children[0].type, 'or');
  assert.equal(renderNormalizedQuery(reparsed), normalizedQuery);
});

test('flattenConditions lists leaf predicates', () => {
  const { ast } = parseSearchQuery('ioc contains "a" AND (tag equals "x" OR status equals "active")');
  const flat = flattenConditions(ast);
  assert.equal(flat.length, 3);
  assert.deepEqual(flat.map((c) => c.field), ['ioc', 'tag', 'status']);
});
