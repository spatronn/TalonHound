import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseSyncCursors,
  serializeSyncCursors,
  hasPendingLookupChanges,
  IOC_LOOKUP_SYNC_PARTITIONS
} from './iocLookupSync.js';

test('parseSyncCursors legacy numeric applies to all partitions', () => {
  const cursors = parseSyncCursors('12345');
  for (const p of IOC_LOOKUP_SYNC_PARTITIONS) {
    assert.equal(cursors[p.key], 12345);
  }
});

test('parseSyncCursors JSON per-partition', () => {
  const cursors = parseSyncCursors('{"ip":10,"domain":20,"url":30,"sha256":5}');
  assert.equal(cursors.ip, 10);
  assert.equal(cursors.domain, 20);
  assert.equal(cursors.url, 30);
  assert.equal(cursors.sha256, 5);
});

test('serializeSyncCursors roundtrip', () => {
  const raw = serializeSyncCursors({ ip: 1, domain: 2, url: 3, sha256: 4 });
  const parsed = parseSyncCursors(raw);
  assert.deepEqual(parsed, { ip: 1, domain: 2, url: 3, sha256: 4 });
});

test('hasPendingLookupChanges detects partition max id ahead of cursor', () => {
  assert.equal(
    hasPendingLookupChanges({ ip: 100, domain: 50, url: 40, sha256: 10 }, { ip: 99, domain: 50, url: 40, sha256: 10 }),
    true
  );
  assert.equal(
    hasPendingLookupChanges({ ip: 100, domain: 50, url: 40, sha256: 10 }, { ip: 100, domain: 50, url: 40, sha256: 10 }),
    false
  );
});
