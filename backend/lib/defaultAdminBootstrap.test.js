import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import bcrypt from 'bcrypt';
import {
  DEFAULT_ADMIN_EMAIL,
  DEFAULT_ADMIN_ROLE,
  ensureDefaultAdminBootstrap,
  resolveBootstrapAdminPassword
} from './defaultAdminBootstrap.js';

function createBootstrapPool(initial = {}) {
  const state = {
    bootstrapped: Boolean(initial.bootstrapped),
    users: Array.isArray(initial.users) ? [...initial.users] : [],
    lockAcquired: initial.lockAcquired !== false,
    inserts: 0,
    flagUpdates: 0
  };

  const client = {
    release() {},
    async query(sql, params = []) {
      const s = String(sql);

      if (s.includes('pg_try_advisory_lock')) {
        return { rows: [{ acquired: state.lockAcquired }] };
      }
      if (s.includes('pg_advisory_unlock')) {
        return { rows: [{ pg_advisory_unlock: true }] };
      }
      if (s.startsWith('BEGIN') || s.startsWith('COMMIT') || s.startsWith('ROLLBACK')) {
        return { rows: [] };
      }
      if (s.includes('INSERT INTO system_settings')) {
        return { rows: [] };
      }
      if (s.includes('SELECT default_admin_bootstrapped')) {
        return { rows: [{ default_admin_bootstrapped: state.bootstrapped }] };
      }
      if (s.includes('SELECT COUNT(*)')) {
        return { rows: [{ n: state.users.length }] };
      }
      if (s.includes('INSERT INTO users')) {
        state.inserts += 1;
        const [username, password_hash, role] = params;
        assert.equal(username, DEFAULT_ADMIN_EMAIL);
        assert.equal(role, DEFAULT_ADMIN_ROLE);
        assert.notEqual(password_hash, 'admin');
        assert.match(String(password_hash), /^\$2[aby]?\$/);
        state.users.push({
          username,
          password_hash,
          role,
          must_change_password: true
        });
        return { rows: [] };
      }
      if (s.includes('UPDATE system_settings') && s.includes('default_admin_bootstrapped')) {
        state.flagUpdates += 1;
        state.bootstrapped = true;
        return { rows: [] };
      }
      throw new Error(`unexpected sql: ${s.slice(0, 120)}`);
    }
  };

  return {
    state,
    async connect() {
      return client;
    }
  };
}

test('SECRET-01: resolveBootstrapAdminPassword rejects known legacy admin password', () => {
  assert.throws(
    () => resolveBootstrapAdminPassword({ INITIAL_ADMIN_PASSWORD: 'admin' }),
    /must not be the known legacy default/i
  );
});

test('SECRET-01: bootstrap uses INITIAL_ADMIN_PASSWORD when provided', async () => {
  const pool = createBootstrapPool({ bootstrapped: false, users: [] });
  const password = 'OperatorProvided-99';
  const result = await ensureDefaultAdminBootstrap(pool, {
    logger: { info() {}, warn() {} },
    env: { INITIAL_ADMIN_PASSWORD: password }
  });
  assert.equal(result.status, 'created');
  assert.equal(result.passwordSource, 'env');
  const ok = await bcrypt.compare(password, pool.state.users[0].password_hash);
  assert.equal(ok, true);
  const legacy = await bcrypt.compare('admin', pool.state.users[0].password_hash);
  assert.equal(legacy, false);
});

test('SECRET-01: bootstrap generates unique password and writes one-time file', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'th-bootstrap-'));
  const file = path.join(dir, 'bootstrap-admin-password.once');
  const pool = createBootstrapPool({ bootstrapped: false, users: [] });
  const result = await ensureDefaultAdminBootstrap(pool, {
    logger: { info() {}, warn() {} },
    env: { BOOTSTRAP_ADMIN_PASSWORD_FILE: file }
  });
  assert.equal(result.status, 'created');
  assert.equal(result.passwordSource, 'generated');
  assert.ok(fs.existsSync(file));
  const written = fs.readFileSync(file, 'utf8').trim();
  assert.ok(written.length >= 12);
  assert.notEqual(written, 'admin');
  const ok = await bcrypt.compare(written, pool.state.users[0].password_hash);
  assert.equal(ok, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('SECRET-01: two generated bootstraps yield different passwords', async () => {
  const a = resolveBootstrapAdminPassword({});
  const b = resolveBootstrapAdminPassword({});
  assert.equal(a.source, 'generated');
  assert.equal(b.source, 'generated');
  assert.notEqual(a.password, b.password);
});

test('bootstrap skips when users already exist and marks bootstrapped', async () => {
  const pool = createBootstrapPool({
    bootstrapped: false,
    users: [{ username: 'existing@example.com' }]
  });
  const result = await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} } });
  assert.equal(result.status, 'skipped_users_exist');
  assert.equal(pool.state.inserts, 0);
  assert.equal(pool.state.bootstrapped, true);
});

test('bootstrap is idempotent after flag is set (no second user)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'th-bootstrap-'));
  const file = path.join(dir, 'pw.once');
  const pool = createBootstrapPool({ bootstrapped: false, users: [] });
  const env = { BOOTSTRAP_ADMIN_PASSWORD_FILE: file };
  const first = await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} }, env });
  assert.equal(first.status, 'created');
  const second = await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} }, env });
  assert.equal(second.status, 'skipped_already_bootstrapped');
  assert.equal(pool.state.inserts, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('bootstrap does not recreate after admin deleted (flag remains true, users empty)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'th-bootstrap-'));
  const file = path.join(dir, 'pw.once');
  const pool = createBootstrapPool({ bootstrapped: false, users: [] });
  const env = { BOOTSTRAP_ADMIN_PASSWORD_FILE: file, INITIAL_ADMIN_PASSWORD: 'CleanInstallSecret1' };
  await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} }, env });
  pool.state.users = [];
  assert.equal(pool.state.bootstrapped, true);
  const again = await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} }, env });
  assert.equal(again.status, 'skipped_already_bootstrapped');
  assert.equal(pool.state.inserts, 1);
  assert.equal(pool.state.users.length, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('bootstrap skips when advisory lock not acquired', async () => {
  const pool = createBootstrapPool({ bootstrapped: false, users: [], lockAcquired: false });
  const result = await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} } });
  assert.equal(result.status, 'skipped_lock');
  assert.equal(pool.state.inserts, 0);
});
