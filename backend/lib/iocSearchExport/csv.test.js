import test from 'node:test';
import assert from 'node:assert/strict';
import { csvCell, csvRow, csvTimestamp } from './csv.js';
import { sanitizeColumns, headerRow, formatRecord, DEFAULT_EXPORT_COLUMNS } from './columns.js';

test('plain values pass through', () => {
  assert.equal(csvCell('example.com'), 'example.com');
  assert.equal(csvCell('domain'), 'domain');
});

test('values with comma/quote/newline are RFC-4180 quoted', () => {
  assert.equal(csvCell('a,b'), '"a,b"');
  assert.equal(csvCell('he said "hi"'), '"he said ""hi"""');
  assert.equal(csvCell('line1\nline2'), '"line1\nline2"');
});

test('formula-injection: leading = + - @ are neutralized with a quote', () => {
  assert.equal(csvCell('=SUM(A1:A2)'), "'=SUM(A1:A2)");
  assert.equal(csvCell('+1234'), "'+1234");
  assert.equal(csvCell('-1+1'), "'-1+1");
  assert.equal(csvCell('@cmd'), "'@cmd");
});

test('formula-injection combined with quoting stays inside the quotes', () => {
  // Leading '=' AND a comma -> neutralized then quoted.
  assert.equal(csvCell('=1,2'), '"\'=1,2"');
});

test('leading tab formula trigger is neutralized (tab alone needs no RFC quoting)', () => {
  assert.equal(csvCell('\t=1'), "'\t=1");
});

test('leading CR formula trigger is neutralized and RFC-quoted', () => {
  assert.equal(csvCell('\r=1'), '"\'\r=1"');
});

test('null/undefined become empty', () => {
  assert.equal(csvCell(null), '');
  assert.equal(csvCell(undefined), '');
});

test('csvRow joins cells', () => {
  assert.equal(csvRow(['a', 'b,c', '=x']), "a,\"b,c\",'=x");
});

test('csvTimestamp formats ISO or empty', () => {
  assert.equal(csvTimestamp(null), '');
  assert.equal(csvTimestamp('2026-07-22T10:00:00Z'), '2026-07-22T10:00:00.000Z');
  assert.equal(csvTimestamp('not-a-date'), '');
});

test('sanitizeColumns falls back to defaults on empty/invalid', () => {
  assert.deepEqual(sanitizeColumns([]), [...DEFAULT_EXPORT_COLUMNS]);
  assert.deepEqual(sanitizeColumns(['nope', 'bad']), [...DEFAULT_EXPORT_COLUMNS]);
});

test('sanitizeColumns keeps valid columns in order, drops dupes/unknown', () => {
  assert.deepEqual(
    sanitizeColumns(['status', 'ioc', 'status', 'evil', 'tags']),
    ['status', 'ioc', 'tags']
  );
});

test('updated_at is not a valid export column', () => {
  assert.deepEqual(sanitizeColumns(['updated_at']), [...DEFAULT_EXPORT_COLUMNS]);
});

test('headerRow and formatRecord align with columns', () => {
  const cols = ['ioc', 'tags', 'last_changed_in_source'];
  assert.deepEqual(headerRow(cols), ['IOC', 'Tags', 'Last changed in source']);
  const rec = {
    observable: 'evil.com',
    tags: ['mirai', 'botnet'],
    last_changed_in_source: '2026-07-01T00:00:00Z'
  };
  assert.deepEqual(formatRecord(rec, cols), ['evil.com', 'mirai|botnet', '2026-07-01T00:00:00.000Z']);
});
