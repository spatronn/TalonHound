import test from 'node:test';
import assert from 'node:assert/strict';
import bcrypt from 'bcrypt';
import {
  DEFAULT_ADMIN_EMAIL,
  DEFAULT_ADMIN_PASSWORD,
  DEFAULT_ADMIN_ROLE,
  ensureDefaultAdminBootstrap
} from './defaultAdminBootstrap.js';

/**
 * Stateful mock pool that exercises the bootstrap SQL paths.
 */
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
        assert.notEqual(password_hash, DEFAULT_ADMIN_PASSWORD);
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

test('bootstrap creates default admin when users empty and not yet bootstrapped', async () => {
  const pool = createBootstrapPool({ bootstrapped: false, users: [] });
  const result = await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} } });
  assert.equal(result.status, 'created');
  assert.equal(pool.state.inserts, 1);
  assert.equal(pool.state.bootstrapped, true);
  assert.equal(pool.state.users.length, 1);
  assert.equal(pool.state.users[0].username, DEFAULT_ADMIN_EMAIL);
  assert.equal(pool.state.users[0].role, DEFAULT_ADMIN_ROLE);
  assert.equal(pool.state.users[0].must_change_password, true);
  const ok = await bcrypt.compare(DEFAULT_ADMIN_PASSWORD, pool.state.users[0].password_hash);
  assert.equal(ok, true);
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
  assert.equal(pool.state.users.length, 1);
});

test('bootstrap is idempotent after flag is set (no second user)', async () => {
  const pool = createBootstrapPool({ bootstrapped: false, users: [] });
  const first = await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} } });
  assert.equal(first.status, 'created');
  const second = await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} } });
  assert.equal(second.status, 'skipped_already_bootstrapped');
  assert.equal(pool.state.inserts, 1);
  assert.equal(pool.state.users.length, 1);
});

test('bootstrap does not recreate after admin deleted (flag remains true, users empty)', async () => {
  const pool = createBootstrapPool({ bootstrapped: false, users: [] });
  await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} } });
  pool.state.users = [];
  assert.equal(pool.state.bootstrapped, true);
  const again = await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} } });
  assert.equal(again.status, 'skipped_already_bootstrapped');
  assert.equal(pool.state.inserts, 1);
  assert.equal(pool.state.users.length, 0);
});

test('bootstrap skips when advisory lock not acquired', async () => {
  const pool = createBootstrapPool({ bootstrapped: false, users: [], lockAcquired: false });
  const result = await ensureDefaultAdminBootstrap(pool, { logger: { info() {}, warn() {} } });
  assert.equal(result.status, 'skipped_lock');
  assert.equal(pool.state.inserts, 0);
});
