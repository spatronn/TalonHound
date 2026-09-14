import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuditLogService } from './auditLogService.js';

// Column order of the INSERT in auditLogService.auditLog.
const COL = {
  actor_user_id: 0,
  actor_username: 1,
  actor_email: 2,
  actor_role: 3,
  action: 4,
  entity_type: 5,
  entity_id: 6,
  entity_display: 7,
  severity: 13,
  status: 14,
  ip_address: 15,
  user_agent: 16,
  request_id: 17,
  source: 18,
  before_data: 19,
  after_data: 20,
  metadata: 21
};

const USER_PUBLIC_ID = '2f1c9d0e-5a6b-4c7d-8e9f-0a1b2c3d4e5f';

function fakePool() {
  const inserts = [];
  return {
    inserts,
    async query(sql, params) {
      if (/^SELECT public_id FROM users/.test(sql)) {
        return { rows: params[0] === 7 ? [{ public_id: USER_PUBLIC_ID }] : [] };
      }
      if (/INSERT INTO audit_logs/.test(sql)) {
        inserts.push(params);
        return { rows: [] };
      }
      return { rows: [] };
    }
  };
}

function webRequest(overrides = {}) {
  return {
    user: { id: 7, email: 'safa@safa.com', username: 'safa@safa.com', role: 'analyst' },
    authVia: 'cookie',
    headers: { 'user-agent': 'UA/1.0' },
    ip: '10.0.0.5',
    requestId: 'req_abc123',
    ...overrides
  };
}

test('actor is persisted from the request principal (cookie session carries only the numeric id)', async () => {
  const pool = fakePool();
  const audit = createAuditLogService(pool);
  await audit.auditSuccess({
    req: webRequest(),
    action: 'threat_library.report.imported.pdf',
    entityType: 'threat_report',
    entityId: 'c9e28440-a25f-4149-a993-c78d8b458805',
    entityDisplay: 'PurpleBravo report'
  });
  const row = pool.inserts[0];
  assert.equal(row[COL.actor_user_id], USER_PUBLIC_ID);
  assert.equal(row[COL.actor_email], 'safa@safa.com');
  assert.equal(row[COL.actor_username], 'safa@safa.com');
  assert.equal(row[COL.actor_role], 'analyst');
  assert.equal(row[COL.source], 'web');
  assert.equal(row[COL.ip_address], '10.0.0.5');
  assert.equal(row[COL.request_id], 'req_abc123');
  assert.equal(row[COL.action], 'threat_library.report.imported.pdf');
});

test('actor field (req.user-shaped) attributes an event emitted outside the request lifecycle', async () => {
  const pool = fakePool();
  const audit = createAuditLogService(pool);
  await audit.auditLog({
    actor: { id: 7, email: 'safa@safa.com', username: 'safa@safa.com', role: 'analyst' },
    source: 'worker',
    action: 'threat_library.report.analysis.completed',
    entityType: 'threat_report',
    entityId: 'rep-1',
    metadata: { executed_by: 'threat-library-worker' }
  });
  const row = pool.inserts[0];
  assert.equal(row[COL.actor_user_id], USER_PUBLIC_ID);
  assert.equal(row[COL.actor_email], 'safa@safa.com');
  assert.equal(row[COL.source], 'worker');
  assert.equal(row[COL.ip_address], null);
  assert.deepEqual(row[COL.metadata], { executed_by: 'threat-library-worker' });
});

test('no principal at all leaves the actor columns null (legacy rows keep rendering "—")', async () => {
  const pool = fakePool();
  const audit = createAuditLogService(pool);
  await audit.auditLog({ action: 'x.y', entityType: 'x' });
  const row = pool.inserts[0];
  assert.equal(row[COL.actor_user_id], null);
  assert.equal(row[COL.actor_username], null);
  assert.equal(row[COL.actor_email], null);
});

test('explicit X-Request-Id header wins over the server-assigned request id', async () => {
  const pool = fakePool();
  const audit = createAuditLogService(pool);
  await audit.auditLog({
    req: webRequest({ headers: { 'x-request-id': 'client-corr-1' } }),
    action: 'x.y',
    entityType: 'x'
  });
  assert.equal(pool.inserts[0][COL.request_id], 'client-corr-1');
});

test('explicit requestId overrides both header and server id', async () => {
  const pool = fakePool();
  const audit = createAuditLogService(pool);
  await audit.auditLog({ req: webRequest(), requestId: 'op-77', action: 'x.y', entityType: 'x' });
  assert.equal(pool.inserts[0][COL.request_id], 'op-77');
});

test('status normalizes to success | partial | failed', async () => {
  const pool = fakePool();
  const audit = createAuditLogService(pool);
  await audit.auditLog({ action: 'a', entityType: 'x', status: 'partial' });
  await audit.auditLog({ action: 'a', entityType: 'x', status: 'failed' });
  await audit.auditLog({ action: 'a', entityType: 'x', status: 'weird' });
  assert.deepEqual(pool.inserts.map((r) => r[COL.status]), ['partial', 'failed', 'success']);
});

test('resolveActor returns the principal enriched with its persisted public id', async () => {
  const pool = fakePool();
  const audit = createAuditLogService(pool);
  const actor = await audit.resolveActor(webRequest());
  assert.equal(actor.publicId, USER_PUBLIC_ID);
  assert.equal(actor.email, 'safa@safa.com');
  assert.equal(await audit.resolveActor({}), null);
  const unknown = await audit.resolveActor(webRequest({ user: { id: 99, email: 'x@y' } }));
  assert.equal(unknown.publicId, null);
});

test('source is derived from the auth channel', async () => {
  const pool = fakePool();
  const audit = createAuditLogService(pool);
  await audit.auditLog({ req: webRequest({ authVia: 'mcp' }), action: 'a', entityType: 'x' });
  await audit.auditLog({ req: webRequest({ authVia: 'api_key' }), action: 'a', entityType: 'x' });
  await audit.auditLog({ req: webRequest({ authVia: 'cookie' }), action: 'a', entityType: 'x' });
  assert.deepEqual(pool.inserts.map((r) => r[COL.source]), ['mcp', 'api', 'web']);
});
