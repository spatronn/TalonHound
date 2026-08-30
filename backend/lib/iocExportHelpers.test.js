import assert from 'node:assert/strict';
import { test } from 'node:test';
import { IOC_EXPORT_MAX_LIMIT, parseIocExportQuery, csvEscape } from './iocExportHelpers.js';

test('parseIocExportQuery validates format and caps limit', () => {
  const bad = parseIocExportQuery({ format: 'xml' });
  assert.equal(bad.ok, false);
  const ok = parseIocExportQuery({ format: 'csv', limit: '99999' });
  assert.equal(ok.ok, true);
  assert.equal(ok.pageSize, IOC_EXPORT_MAX_LIMIT);
  assert.ok(ok.pageSize <= IOC_EXPORT_MAX_LIMIT, 'legacy export row limit is hard-capped');
});

// Legacy synchronous export shares this escaper; it must neutralize CSV formula
// injection just like the async export worker's csvCell.
test('legacy csvEscape neutralizes formula-injection triggers', () => {
  assert.equal(csvEscape('=SUM(A1:A2)'), "'=SUM(A1:A2)");
  assert.equal(csvEscape('+1'), "'+1");
  assert.equal(csvEscape('-1+1'), "'-1+1");
  assert.equal(csvEscape('@x'), "'@x");
  assert.equal(csvEscape('example.com'), 'example.com');
  assert.equal(csvEscape('a,b'), '"a,b"');
  assert.equal(csvEscape('=1,2'), '"\'=1,2"');
});

test('parseIocExportQuery maps file_hash alias', () => {
  const ok = parseIocExportQuery({ type: 'sha256' });
  assert.equal(ok.ok, true);
  assert.equal(ok.filters.type, 'file_hash');
});

test('parseIocExportQuery defaults exclude expired and suppressed', () => {
  const ok = parseIocExportQuery({});
  assert.equal(ok.filters.include_expired, false);
  assert.equal(ok.filters.include_suppressed, false);
});
