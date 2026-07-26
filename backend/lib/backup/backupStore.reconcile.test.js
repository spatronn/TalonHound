import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { failOrphanQueued, countBlockingBackups } from './backupStore.js';

function mockPool(handlers) {
  return {
    async query(sql, params = []) {
      for (const h of handlers) {
        const out = h(String(sql), params);
        if (out) return out;
      }
      return { rows: [], rowCount: 0 };
    }
  };
}

describe('backupStore reconcile helpers', () => {
  it('failOrphanQueued updates queued rows without job_id', async () => {
    let updated = null;
    const db = mockPool([
      (sql, params) => {
        if (sql.includes('ENQUEUE_FAILED') || sql.includes('job_id IS NULL')) {
          updated = { id: 'r1', backup_id: 'b1', status: 'failed', error_code: 'ENQUEUE_FAILED' };
          assert.equal(params[0], '5');
          return { rows: [updated], rowCount: 1 };
        }
        return null;
      }
    ]);
    const rows = await failOrphanQueued(db, 5);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].error_code, 'ENQUEUE_FAILED');
  });

  it('countBlockingBackups passes orphan window', async () => {
    const db = mockPool([
      (sql, params) => {
        if (sql.includes('blocking') || sql.includes("status IN ('running', 'verifying')")) {
          assert.equal(params[0], '5');
          return { rows: [{ n: 0 }], rowCount: 1 };
        }
        return null;
      }
    ]);
    const n = await countBlockingBackups(db, 5);
    assert.equal(n, 0);
  });
});
