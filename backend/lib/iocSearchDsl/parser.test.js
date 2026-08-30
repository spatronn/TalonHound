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

test('md5/sha1/sha256 equals parse to normalized hash values', () => {
  const md5 = parse('md5 equals "20945449fd11203d79ea5d0d29bf1e22"');
  assert.equal(md5.field, 'md5');
  assert.equal(md5.kind, 'hash');
  assert.equal(md5.operator, 'equals');
  assert.deepEqual(md5.values, ['20945449fd11203d79ea5d0d29bf1e22']);

  const sha1 = parse('sha1 equals "0017b2e0d74be3c58ab319c29a84de9f3e3bedee"');
  assert.deepEqual(sha1.values, ['0017b2e0d74be3c58ab319c29a84de9f3e3bedee']);

  const sha256 = parse('sha256 equals "dd55cbafbf914c8bb7eee34acfc65876d96b21de2ba8f320737cf8d280a347e6"');
  assert.deepEqual(sha256.values, ['dd55cbafbf914c8bb7eee34acfc65876d96b21de2ba8f320737cf8d280a347e6']);
});

test('hash values are trimmed and lowercased', () => {
  const ast = parse('md5 equals "  20945449FD11203D79EA5D0D29BF1E22  "');
  assert.deepEqual(ast.values, ['20945449fd11203d79ea5d0d29bf1e22']);
});

test('hash normalized query re-parses to the same normalized (lowercased) form', () => {
  const { normalizedQuery } = parseSearchQuery('SHA256 equals "DD55CBAFBF914C8BB7EEE34ACFC65876D96B21DE2BA8F320737CF8D280A347E6"');
  assert.equal(
    normalizedQuery,
    'sha256 equals "dd55cbafbf914c8bb7eee34acfc65876d96b21de2ba8f320737cf8d280a347e6"'
  );
  const reparsed = parseDsl(normalizedQuery);
  assert.equal(reparsed.field, 'sha256');
  assert.deepEqual(reparsed.values, ['dd55cbafbf914c8bb7eee34acfc65876d96b21de2ba8f320737cf8d280a347e6']);
});

test('wrong-length hash is rejected (never silently downgraded)', () => {
  expectError('md5 equals "20945449fd11203d79ea5d0d29bf1e2"', 'invalid_hash_value'); // 31 chars
  expectError('sha1 equals "0017b2e0d74be3c58ab319c29a84de9f3e3bede"', 'invalid_hash_value'); // 39
  expectError('sha256 equals "dd55cbafbf914c8bb7eee34acfc65876d96b21de2ba8f320737cf8d280a347"', 'invalid_hash_value'); // 62
});

test('non-hex hash value is rejected', () =>
  expectError('md5 equals "zz945449fd11203d79ea5d0d29bf1e22"', 'invalid_hash_value'));

test('md5/sha1/sha256 accept only equals — contains and others rejected', () => {
  expectError('md5 contains "20945449fd11203d79ea5d0d29bf1e22"', 'unsupported_operator');
  expectError('sha1 contains "0017b2e0d74be3c58ab319c29a84de9f3e3bedee"', 'unsupported_operator');
  expectError('sha256 contains "dd55cbafbf914c8bb7eee34acfc65876d96b21de2ba8f320737cf8d280a347e6"', 'unsupported_operator');
  expectError('md5 not_equals "20945449fd11203d79ea5d0d29bf1e22"', 'unsupported_operator');
  expectError('sha256 starts_with "dd55"', 'unsupported_operator');
});

test('type no longer accepts imphash/tlsh/ssdeep (not IOC identity types)', () => {
  expectError('type equals "imphash"', 'invalid_enum_value');
  expectError('type equals "tlsh"', 'invalid_enum_value');
  expectError('type equals "ssdeep"', 'invalid_enum_value');
  expectError('type in ("md5", "imphash")', 'invalid_enum_value');
});

test('type still accepts real IOC identity types', () => {
  for (const t of ['ip', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256']) {
    const ast = parse(`type equals "${t}"`);
    assert.deepEqual(ast.values, [t]);
  }
});

test('imphash/tlsh/ssdeep equals parse as attr conditions', () => {
  const imphash = parse('imphash equals "f34d5f2d4577ed6d9ceec516c1f5a744"');
  assert.equal(imphash.field, 'imphash');
  assert.equal(imphash.kind, 'attr');
  assert.equal(imphash.operator, 'equals');
  assert.deepEqual(imphash.values, ['f34d5f2d4577ed6d9ceec516c1f5a744']);

  const tlsh = parse('tlsh equals "T14041FFD512BD02757EE6ADA7F1A6D584B1846BB719C5AE3C5CD8BCF4814CE082083A93"');
  assert.equal(tlsh.kind, 'attr');
  // tlsh is lowercased (case-insensitive hex digest)
  assert.deepEqual(tlsh.values, ['t14041ffd512bd02757ee6ada7f1a6d584b1846bb719c5ae3c5cd8bcf4814ce082083a93']);

  const ssdeep = parse('ssdeep equals "3072:Etd/dEZOS3hE0E9rycyje/d9gu+Q9sF7Nq40ln:M4OS3C3yjud9guh9Gq40ln"');
  assert.equal(ssdeep.kind, 'attr');
});

test('imphash is lowercased; tlsh accepts bare 70-hex form', () => {
  const imphash = parse('imphash equals "  F34D5F2D4577ED6D9CEEC516C1F5A744  "');
  assert.deepEqual(imphash.values, ['f34d5f2d4577ed6d9ceec516c1f5a744']);
  // 70 hex with no T1 prefix is a valid TLSH form
  const bare = parse('tlsh equals "4041FFD512BD02757EE6ADA7F1A6D584B1846BB719C5AE3C5CD8BCF4814CE082083A93"');
  assert.equal(bare.values[0].length, 70);
});

test('ssdeep is case-SENSITIVE (base64) — case is preserved, not folded', () => {
  const v = '3072:Etd/dEZOS3hE0E9rycyje/d9gu+Q9sF7Nq40ln:M4OS3C3yjud9guh9Gq40ln';
  const ast = parse(`ssdeep equals "${v}"`);
  assert.deepEqual(ast.values, [v]); // unchanged: '+' and mixed case preserved
});

test('ssdeep with colons and plus parses (tokenizer treats quoted value as opaque)', () => {
  const ast = parse('ssdeep equals "24:vIaOIwOOvIocvI5Fy3Ijq7JICeI08F0j1IkSIo6IrYI5+V:vcxlCY+5VE9SwrX"');
  assert.equal(ast.field, 'ssdeep');
  assert.match(ast.values[0], /:.*:.*/);
  assert.match(ast.values[0], /\+/);
});

test('invalid attr formats are rejected (not silently downgraded)', () => {
  expectError('imphash equals "f34d5f2d4577ed6d9ceec516c1f5a74"', 'invalid_attr_value');  // 31 hex
  expectError('imphash equals "z34d5f2d4577ed6d9ceec516c1f5a744"', 'invalid_attr_value'); // non-hex
  expectError('tlsh equals "TNULL"', 'invalid_attr_value');                                // garbage sentinel
  expectError('tlsh equals "T1zz41FFD512BD02757EE6ADA7F1A6D584B1846BB719C5AE3C5CD8BCF4814CE082083A93"', 'invalid_attr_value');
  expectError('ssdeep equals "notanssdeep"', 'invalid_attr_value');                        // no blocksize:chunk:chunk
  expectError('ssdeep equals "3::"', 'invalid_attr_value');                                // empty chunks
});

test('imphash/tlsh/ssdeep accept only equals — contains and others rejected', () => {
  expectError('imphash contains "f34d5f2d4577ed6d9ceec516c1f5a744"', 'unsupported_operator');
  expectError('tlsh contains "T14041FFD512BD02757EE6ADA7F1A6D584B1846BB719C5AE3C5CD8BCF4814CE082083A93"', 'unsupported_operator');
  expectError('ssdeep contains "3072:Etd:M4OS"', 'unsupported_operator');
  expectError('ssdeep starts_with "3072:"', 'unsupported_operator');
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
