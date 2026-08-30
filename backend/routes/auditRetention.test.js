import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { registerAuditRetentionRoutes } from './auditRetention.js';

function makePool({ retentionDays = 365, systemAdmins = new Set() } = {}) {
  const state = {
    audit_log_retention_days: retentionDays,
    audit_log_retention_updated_at: null,
    audit_log_retention_updated_by: null,
    audit_log_retention_last_run_at: null
  };
  const pool = {
    state,
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('FROM users') && s.includes('is_system_admin')) {
        const id = Number(params[0]);
        return { rows: [{ is_system_admin: systemAdmins.has(id) }] };
      }
      if (s.includes('SELECT audit_log_retention_days')) {
        return { rows: [{ ...state }] };
      }
      if (s.startsWith('INSERT INTO system_settings')) {
        return { rows: [] };
      }
      if (s.includes('UPDATE system_settings') && s.includes('audit_log_retention_days = $2')) {
        state.audit_log_retention_days = params[1];
        state.audit_log_retention_updated_by = params[2];
        state.audit_log_retention_updated_at = new Date();
        return { rows: [] };
      }
      throw new Error(`unexpected sql: ${s}`);
    }
  };
  return pool;
}

const auditStub = { auditLog: async () => {}, auditSuccess: async () => {} };

function withApp(pool, user) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.user = user; next(); });
  registerAuditRetentionRoutes(app, pool, { audit: auditStub });
  return app;
}

function call(app, method, path, body) {
  return new Promise((resolve) => {
    const server = app.listen(0, async () => {
      const { port } = server.address();
      try {
        const res = await fetch(`http://127.0.0.1:${port}${path}`, {
          method,
          headers: { 'content-type': 'application/json' },
          body: body === undefined ? undefined : JSON.stringify(body)
        });
        const data = await res.json().catch(() => ({}));
        resolve({ status: res.status, body: data });
      } finally {
        server.close();
      }
    });
  });
}

test('GET returns default 365 to admins', async () => {
  const pool = makePool({ retentionDays: 365 });
  const app = withApp(pool, { id: 2, role: 'admin', email: 'a@x' });
  const res = await call(app, 'GET', '/api/settings/audit-log-retention');
  assert.equal(res.status, 200);
  assert.equal(res.body.retention_days, 365);
  assert.equal(res.body.keep_forever, false);
  assert.deepEqual(res.body.preset_days, [90, 180, 365, 730]);
  assert.equal(res.body.can_edit, false);
});

test('GET is forbidden for readonly role', async () => {
  const pool = makePool();
  const app = withApp(pool, { id: 3, role: 'readonly', email: 'ro@x' });
  const res = await call(app, 'GET', '/api/settings/audit-log-retention');
  assert.equal(res.status, 403);
});

test('GET reports can_edit=true for the system administrator', async () => {
  const pool = makePool({ systemAdmins: new Set([1]) });
  const app = withApp(pool, { id: 1, role: 'admin', email: 'sysadmin@x' });
  const res = await call(app, 'GET', '/api/settings/audit-log-retention');
  assert.equal(res.status, 200);
  assert.equal(res.body.can_edit, true);
});

test('non-system-admin admin cannot update retention', async () => {
  const pool = makePool({ retentionDays: 365 });
  const app = withApp(pool, { id: 2, role: 'admin', email: 'plainadmin@x' });
  const res = await call(app, 'PUT', '/api/settings/audit-log-retention', { retention_days: 90 });
  assert.equal(res.status, 403);
  assert.equal(res.body.code, 'FORBIDDEN');
  // unchanged
  assert.equal(pool.state.audit_log_retention_days, 365);
});

test('system admin can update to a valid preset', async () => {
  const pool = makePool({ retentionDays: 365, systemAdmins: new Set([1]) });
  const app = withApp(pool, { id: 1, role: 'admin', email: 'sysadmin@x' });
  const res = await call(app, 'PUT', '/api/settings/audit-log-retention', { retention_days: 730 });
  assert.equal(res.status, 200);
  assert.equal(res.body.retention_days, 730);
  assert.equal(pool.state.audit_log_retention_days, 730);
});

test('system admin can set a custom positive integer', async () => {
  const pool = makePool({ retentionDays: 365, systemAdmins: new Set([1]) });
  const app = withApp(pool, { id: 1, role: 'admin', email: 'sysadmin@x' });
  const res = await call(app, 'PUT', '/api/settings/audit-log-retention', { retention_days: 45 });
  assert.equal(res.status, 200);
  assert.equal(res.body.retention_days, 45);
});

test('system admin can select Keep forever', async () => {
  const pool = makePool({ retentionDays: 365, systemAdmins: new Set([1]) });
  const app = withApp(pool, { id: 1, role: 'admin', email: 'sysadmin@x' });
  const res = await call(app, 'PUT', '/api/settings/audit-log-retention', { keep_forever: true });
  assert.equal(res.status, 200);
  assert.equal(res.body.keep_forever, true);
  assert.equal(res.body.retention_days, null);
  assert.equal(pool.state.audit_log_retention_days, null);
});

test('invalid values are rejected with 400', async () => {
  const pool = makePool({ retentionDays: 365, systemAdmins: new Set([1]) });
  const app = withApp(pool, { id: 1, role: 'admin', email: 'sysadmin@x' });
  for (const bad of [{ retention_days: 0 }, { retention_days: -1 }, { retention_days: 12.5 }, { retention_days: 'abc' }]) {
    const res = await call(app, 'PUT', '/api/settings/audit-log-retention', bad);
    assert.equal(res.status, 400, `expected 400 for ${JSON.stringify(bad)}`);
    assert.equal(res.body.code, 'INVALID_RETENTION');
  }
  // unchanged after all rejections
  assert.equal(pool.state.audit_log_retention_days, 365);
});
