import test from 'node:test';
import assert from 'node:assert/strict';
import { buildKnownHashDisplayRows } from './knownHashRows.js';

const SHA256 = '1b39f9b2b96a6586c4a11ab2fdbff8fdf16ba5a0ac7603149023d73f33b84498';
const SHA1 = '366e435a1ea0f597deb6ebe7c0c5acdb6e8b33eb';
const MD5 = 'c92e2655d115368f92e7b7de5803b7bc';

test('T8 Known Hashes shows MD5+SHA1+SHA256 when artifact has all three', () => {
  const rows = buildKnownHashDisplayRows({
    known_hashes: [
      { hash_type: 'sha256', value: SHA256, is_primary: true },
      { hash_type: 'sha1', value: SHA1, is_primary: false },
      { hash_type: 'md5', value: MD5, is_primary: false }
    ]
  }, {});
  assert.deepEqual(rows.map((r) => r.hash_type), ['sha256', 'sha1', 'md5']);
  assert.equal(rows.find((r) => r.hash_type === 'md5').value, MD5);
  assert.equal(rows.find((r) => r.is_primary).hash_type, 'sha256');
});

test('T8 additive: VT-promoted MD5 appears even when artifact known_hashes lacks it', () => {
  const rows = buildKnownHashDisplayRows({
    known_hashes: [
      { hash_type: 'sha256', value: SHA256, is_primary: true },
      { hash_type: 'sha1', value: SHA1, is_primary: false }
    ]
  }, { md5: MD5, sha1: SHA1, sha256: SHA256 });
  assert.deepEqual(rows.map((r) => r.hash_type), ['sha256', 'sha1', 'md5']);
  assert.equal(rows.find((r) => r.hash_type === 'md5').value, MD5);
});

test('T5 partial file_information does not invent MD5', () => {
  const rows = buildKnownHashDisplayRows({
    known_hashes: [
      { hash_type: 'sha256', value: SHA256, is_primary: true },
      { hash_type: 'sha1', value: SHA1, is_primary: false }
    ]
  }, { sha1: SHA1, sha256: SHA256 });
  assert.deepEqual(rows.map((r) => r.hash_type), ['sha256', 'sha1']);
});

test('fallback without artifact uses file_information hashes', () => {
  const rows = buildKnownHashDisplayRows(null, { md5: MD5, sha1: SHA1, sha256: SHA256 });
  assert.deepEqual(rows.map((r) => r.hash_type), ['sha256', 'sha1', 'md5']);
  assert.equal(rows.find((r) => r.is_primary).hash_type, 'sha256');
});
