import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { resolveExportFilePath } from './exportConfig.js';

const DIR = path.resolve('/data/ioc-search-exports');

test('resolves a plain filename inside the storage dir', () => {
  const p = resolveExportFilePath(DIR, 'abc.csv');
  assert.equal(p, path.join(DIR, 'abc.csv'));
});

test('rejects path traversal attempts', () => {
  assert.throws(() => resolveExportFilePath(DIR, '../../etc/passwd'));
  assert.throws(() => resolveExportFilePath(DIR, '../secret.csv'));
});

test('an absolute path outside the dir is rejected', () => {
  assert.throws(() => resolveExportFilePath(DIR, '/etc/passwd'));
});

test('a nested subpath that stays inside is allowed', () => {
  const p = resolveExportFilePath(DIR, 'sub/child.csv');
  assert.ok(p.startsWith(DIR + path.sep));
});
