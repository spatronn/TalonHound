import test from 'node:test';
import assert from 'node:assert/strict';
import { recomputeIocGlobalStatus } from './iocExpiration.js';

/**
 * Lifecycle-level tests for how an active suppression drives the effective
 * ioc_items.status via recomputeIocGlobalStatus. Covers scenarios C/F/G:
 *   C: active suppression wins even with an active feed membership → 'suppressed'
 *   F: no suppression + active membership → 'active' (reactivatable on removal)
 *   G: no suppression + no active membership → 'expired'
 */
function makeRecomputeClient({ iocRow, suppressed, memberships, minExp = null }) {
  const updates = [];
  return {
    updates,
    async query(sql, params = []) {
      const s = String(sql).replace(/\s+/g, ' ').trim();
      if (s.includes('FROM ioc_items') && s.includes('WHERE id = $1 AND observable_type = $2')) {
        return { rows: [iocRow], rowCount: 1 };
      }
      if (s.includes('SELECT 1 FROM ioc_suppressions')) {
        return { rows: suppressed ? [{ '?column?': 1 }] : [], rowCount: suppressed ? 1 : 0 };
      }
      if (s.includes('FROM ioc_feed_memberships m') && s.includes('SELECT m.status, m.purged_at')) {
        return { rows: memberships, rowCount: memberships.length };
      }
      if (s.includes('MIN(m.expires_at)')) {
        return { rows: [{ min_exp: minExp }], rowCount: 1 };
      }
      if (s.startsWith('UPDATE ioc_items')) {
        updates.push({ sql: s, params: [...params] });
        return { rowCount: 1, rows: [] };
      }
      throw new Error(`Unexpected query: ${s.slice(0, 120)}`);
    }
  };
}

const baseIoc = {
  id: 1,
  observable: '1.1.1.1',
  observable_type: 'ip',
  status: 'active',
  manual_status_override: false,
  manual_status: null,
  manual_expires_at: null,
  expires_at: null,
  expired_at: null,
  expiration_reason: null
};

test('C: active suppression forces status=suppressed even with active membership', async () => {
  const client = makeRecomputeClient({
    iocRow: { ...baseIoc, status: 'active' },
    suppressed: true,
    memberships: [{ status: 'active', purged_at: null }]
  });
  const res = await recomputeIocGlobalStatus(client, 1, 'ip');
  assert.equal(res.status, 'suppressed');
  assert.ok(client.updates.some((u) => u.sql.includes("status = 'suppressed'")));
});

test('C-idempotent: already-suppressed IOC stays suppressed with no update', async () => {
  const client = makeRecomputeClient({
    iocRow: { ...baseIoc, status: 'suppressed' },
    suppressed: true,
    memberships: [{ status: 'active', purged_at: null }]
  });
  const res = await recomputeIocGlobalStatus(client, 1, 'ip');
  assert.equal(res.status, 'suppressed');
  assert.equal(res.changed, false);
  assert.equal(client.updates.length, 0);
});

test('F: suppression removed + active membership → active', async () => {
  const client = makeRecomputeClient({
    iocRow: { ...baseIoc, status: 'suppressed' },
    suppressed: false,
    memberships: [{ status: 'active', purged_at: null }]
  });
  const res = await recomputeIocGlobalStatus(client, 1, 'ip');
  assert.equal(res.status, 'active');
});

test('G: suppression removed + no active membership → expired', async () => {
  const client = makeRecomputeClient({
    iocRow: { ...baseIoc, status: 'suppressed' },
    suppressed: false,
    memberships: [{ status: 'expired', purged_at: null }]
  });
  const res = await recomputeIocGlobalStatus(client, 1, 'ip');
  assert.equal(res.status, 'expired');
});
