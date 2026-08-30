import test from 'node:test';
import assert from 'node:assert/strict';
import { createManualSuppression, parseSuppressionExpiration } from './manualSuppressionCreate.js';

function makePoolMock({ existingActive = false, insertRow = null, iocRows = [] } = {}) {
  const queries = [];
  const query = async (sql, params = []) => {
    queries.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params: [...(params || [])] });
    const norm = String(sql).replace(/\s+/g, ' ').trim();
    if (norm.startsWith('BEGIN') || norm.startsWith('COMMIT') || norm.startsWith('ROLLBACK')) return { rows: [] };
    if (norm.includes('SELECT id FROM ioc_suppressions')) {
      return existingActive ? { rows: [{ id: 1 }], rowCount: 1 } : { rows: [], rowCount: 0 };
    }
    if (norm.includes('INSERT INTO ioc_suppressions')) {
      const row = insertRow || {
        id: 42, ioc_value: params[0], ioc_type: params[1], scope: 'global',
        source_name: null, reason: params[2], created_by: params[3],
        expires_at: params[4], active: true
      };
      return { rows: [row], rowCount: 1 };
    }
    if (norm.includes('FROM ioc_items')) {
      return { rows: iocRows, rowCount: iocRows.length };
    }
    throw new Error(`Unexpected query: ${norm.slice(0, 120)}`);
  };
  return { queries, query, connect: async () => ({ query, release: () => {} }) };
}

test('A: creates suppression when IOC does not exist in ioc_items', async () => {
  const pool = makePoolMock({ existingActive: false, iocRows: [] });
  const res = await createManualSuppression(pool, {
    ioc_value: '1.1.1.1',
    reason: 'known good resolver'
  });
  assert.equal(res.status, 201);
  assert.equal(res.body.status, 'suppressed');
  assert.equal(res.body.suppression.ioc_value, '1.1.1.1');
  assert.equal(res.body.suppression.ioc_type, 'ip');
  assert.equal(res.body.suppression.scope, 'global');
  // committed, not rolled back
  assert.ok(pool.queries.some((q) => q.sql.startsWith('COMMIT')));
  assert.ok(!pool.queries.some((q) => q.sql.startsWith('ROLLBACK')));
});

test('B: rejects a second active suppression for the same IOC', async () => {
  const pool = makePoolMock({ existingActive: true });
  const res = await createManualSuppression(pool, {
    ioc_value: '1.1.1.1',
    reason: 'duplicate attempt'
  });
  assert.equal(res.status, 409);
  assert.match(res.body.message, /already exists/i);
  assert.ok(pool.queries.some((q) => q.sql.startsWith('ROLLBACK')));
  assert.ok(!pool.queries.some((q) => q.sql.includes('INSERT INTO ioc_suppressions')));
});

test('B2: race unique violation (23505) surfaces as duplicate 409', async () => {
  const pool = makePoolMock({ existingActive: false });
  const origQuery = pool.query;
  pool.connect = async () => ({
    query: async (sql, params) => {
      if (String(sql).includes('INSERT INTO ioc_suppressions')) {
        const e = new Error('duplicate key'); e.code = '23505'; throw e;
      }
      return origQuery(sql, params);
    },
    release: () => {}
  });
  const res = await createManualSuppression(pool, { ioc_value: '8.8.8.8', reason: 'race' });
  assert.equal(res.status, 409);
  assert.match(res.body.message, /already exists/i);
});

test('rejects missing/short reason', async () => {
  const pool = makePoolMock();
  const res = await createManualSuppression(pool, { ioc_value: '1.1.1.1', reason: 'x' });
  assert.equal(res.status, 400);
  assert.match(res.body.message, /reason/i);
});

test('rejects invalid value', async () => {
  const pool = makePoolMock();
  const res = await createManualSuppression(pool, { ioc_value: 'not a value!!', reason: 'valid reason' });
  assert.equal(res.status, 400);
});

test('recomputes IOC status when the indicator already exists', async () => {
  const pool = makePoolMock({ iocRows: [{ id: 7, observable_type: 'ip' }] });
  const res = await createManualSuppression(pool, { ioc_value: '1.1.1.1', reason: 'now suppress existing' });
  assert.equal(res.status, 201);
  // recompute reads ioc_items row (id/observable_type/status...) for id 7
  assert.ok(pool.queries.some((q) => q.sql.includes('FROM ioc_items') && q.params.includes(7)));
});

test('parseSuppressionExpiration handles never/future/past', () => {
  assert.deepEqual(parseSuppressionExpiration('never'), { ok: true, expiresAt: null });
  assert.deepEqual(parseSuppressionExpiration(''), { ok: true, expiresAt: null });
  assert.deepEqual(parseSuppressionExpiration(null), { ok: true, expiresAt: null });
  const now = new Date('2026-01-01T00:00:00Z');
  assert.equal(parseSuppressionExpiration('2026-06-01T00:00:00Z', now).ok, true);
  assert.equal(parseSuppressionExpiration('2025-06-01T00:00:00Z', now).ok, false);
  assert.equal(parseSuppressionExpiration('garbage', now).ok, false);
});
