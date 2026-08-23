import test from 'node:test';
import assert from 'node:assert/strict';
import { acquireFeedSyncLock } from './feedSyncLock.js';

function mockLockPool() {
  const held = new Set();
  return {
    async connect() {
      return {
        async query(sql, params) {
          const text = String(sql);
          if (text.includes('pg_try_advisory_lock')) {
            const name = String(params[0]);
            if (held.has(name)) return { rows: [{ ok: false }] };
            held.add(name);
            return { rows: [{ ok: true }] };
          }
          if (text.includes('pg_advisory_unlock')) {
            held.delete(String(params[0]));
            return { rows: [{ ok: true }] };
          }
          return { rows: [] };
        },
        release() {}
      };
    }
  };
}

test('same feed cannot hold two overlapping locks; different feeds can', async () => {
  const pool = mockLockPool();
  const first = await acquireFeedSyncLock(pool, 'ctf-one');
  const duplicate = await acquireFeedSyncLock(pool, 'ctf-one');
  const other = await acquireFeedSyncLock(pool, 'ctf-two');
  assert.equal(first.acquired, true);
  assert.equal(duplicate.acquired, false);
  assert.equal(other.acquired, true);
  await first.release();
  const afterRelease = await acquireFeedSyncLock(pool, 'ctf-one');
  assert.equal(afterRelease.acquired, true);
  await other.release();
  await afterRelease.release();
});
