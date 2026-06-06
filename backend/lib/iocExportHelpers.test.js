import assert from 'node:assert/strict';
import { test } from 'node:test';
import { IOC_EXPORT_MAX_LIMIT, parseIocExportQuery } from './iocExportHelpers.js';

test('parseIocExportQuery validates format and caps limit', () => {
  const bad = parseIocExportQuery({ format: 'xml' });
  assert.equal(bad.ok, false);
  const ok = parseIocExportQuery({ format: 'csv', limit: '99999' });
  assert.equal(ok.ok, true);
  assert.equal(ok.pageSize, IOC_EXPORT_MAX_LIMIT);
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
