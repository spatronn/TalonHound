import test from 'node:test';
import assert from 'node:assert/strict';
import {
  findStaleMetadata,
  deleteMetadataRow,
  markExpired,
  findExpiredReady
} from './exportStore.js';

function createMemoryDb(rows) {
  return {
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('status = \'ready\' AND expires_at')) {
        const limit = params[0];
        const now = Date.now();
        const matched = rows
          .filter((r) => r.status === 'ready' && r.expires_at && new Date(r.expires_at).getTime() <= now)
          .slice(0, limit);
        return { rows: matched };
      }
      if (s.includes("status IN ('expired', 'failed', 'cancelled')") && s.includes('SELECT')) {
        const days = params[0];
        const limit = params[1];
        const cutoff = Date.now() - days * 86400000;
        const matched = rows
          .filter((r) => ['expired', 'failed', 'cancelled'].includes(r.status))
          .filter((r) => new Date(r.updated_at || r.created_at).getTime() <= cutoff)
          .slice(0, limit);
        return { rows: matched };
      }
      if (s.includes('DELETE FROM ioc_search_exports')) {
        const id = params[0];
        const idx = rows.findIndex(
          (r) => r.id === id && ['expired', 'failed', 'cancelled'].includes(r.status)
        );
        if (idx < 0) return { rows: [] };
        const [gone] = rows.splice(idx, 1);
        return { rows: [gone] };
      }
      if (s.includes("SET status = 'expired'")) {
        const id = params[0];
        const row = rows.find((r) => r.id === id);
        if (!row || !['ready', 'expired'].includes(row.status)) return { rows: [] };
        row.status = 'expired';
        row.storage_path = null;
        return { rows: [row] };
      }
      return { rows: [] };
    }
  };
}

test('findExpiredReady + markExpired are idempotent for already-expired rows', async () => {
  const rows = [
    {
      id: 'a',
      status: 'ready',
      expires_at: new Date(Date.now() - 1000).toISOString(),
      storage_path: 'a.csv',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    }
  ];
  const db = createMemoryDb(rows);
  const found = await findExpiredReady(db, 10);
  assert.equal(found.length, 1);
  const marked = await markExpired(db, 'a');
  assert.equal(marked.status, 'expired');
  const markedAgain = await markExpired(db, 'a');
  assert.equal(markedAgain.status, 'expired');
});

test('metadata cleanup deletes only stale terminal rows and is idempotent', async () => {
  const old = new Date(Date.now() - 10 * 86400000).toISOString();
  const recent = new Date().toISOString();
  const rows = [
    { id: 'old-failed', status: 'failed', updated_at: old, created_at: old },
    { id: 'recent-failed', status: 'failed', updated_at: recent, created_at: recent },
    { id: 'ready', status: 'ready', updated_at: old, created_at: old, expires_at: recent }
  ];
  const db = createMemoryDb(rows);
  const stale = await findStaleMetadata(db, { olderThanDays: 7, limit: 50 });
  assert.equal(stale.length, 1);
  assert.equal(stale[0].id, 'old-failed');

  const deleted = await deleteMetadataRow(db, 'old-failed');
  assert.equal(deleted.id, 'old-failed');
  const deletedAgain = await deleteMetadataRow(db, 'old-failed');
  assert.equal(deletedAgain, null);

  // Ready rows are never deleted by metadata cleanup.
  const noReady = await deleteMetadataRow(db, 'ready');
  assert.equal(noReady, null);
  assert.ok(rows.some((r) => r.id === 'ready'));
});
