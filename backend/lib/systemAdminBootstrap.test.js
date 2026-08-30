import test from 'node:test';
import assert from 'node:assert/strict';
import bcrypt from 'bcrypt';
import { DEFAULT_ADMIN_EMAIL } from './defaultAdminBootstrap.js';
import {
  ensureSystemAdminAccount,
  provisionSystemAdmin,
  SystemAdminBootstrapError,
  SYSTEM_ADMIN_EMAIL
} from './systemAdminBootstrap.js';

/**
 * Stateful mock pool for the reconcile/provision SQL paths. `inserts` lets tests assert that the
 * startup reconcile NEVER creates an account (only the operator CLI path may). Username matching
 * is lowercased so case-insensitivity is genuinely exercised.
 */
function createPool(initial = {}) {
  const state = {
    users: (initial.users || []).map((u, i) => ({ id: u.id ?? i + 1, ...u })),
    lockAcquired: initial.lockAcquired !== false,
    inserts: 0,
    flagUpdates: 0,
    roleUpdates: 0
  };

  const client = {
    release() {},
    async query(sql, params = []) {
      const s = String(sql);
      if (s.includes('pg_try_advisory_lock')) return { rows: [{ acquired: state.lockAcquired }] };
      if (s.includes('pg_advisory_unlock')) return { rows: [{}] };
      if (/^\s*(BEGIN|COMMIT|ROLLBACK)/i.test(s)) return { rows: [] };

      if (s.includes('LOWER(username) = LOWER($1)')) {
        const t = String(params[0] || '').toLowerCase();
        const f = state.users.find((u) => String(u.username || '').toLowerCase() === t);
        return { rows: f ? [{ id: f.id, role: f.role, status: f.status, is_system_admin: f.is_system_admin }] : [], rowCount: f ? 1 : 0 };
      }
      if (s.includes("role = 'admin' AND status = 'active'")) {
        return { rows: [{ n: state.users.filter((u) => u.role === 'admin' && u.status === 'active').length }], rowCount: 1 };
      }
      if (s.includes('SELECT COUNT(*)::int AS n FROM users')) {
        return { rows: [{ n: state.users.length }], rowCount: 1 };
      }
      if (s.includes('UPDATE users SET is_system_admin = TRUE, role =')) {
        state.flagUpdates += 1; state.roleUpdates += 1;
        const f = state.users.find((u) => u.id === params[0]);
        if (f) { f.is_system_admin = true; f.role = params[1]; }
        return { rows: [], rowCount: f ? 1 : 0 };
      }
      if (s.includes('UPDATE users SET is_system_admin = TRUE WHERE id = $1')) {
        state.flagUpdates += 1;
        const f = state.users.find((u) => u.id === params[0]);
        if (f) f.is_system_admin = true;
        return { rows: [], rowCount: f ? 1 : 0 };
      }
      if (s.includes('UPDATE users SET role =')) {
        state.roleUpdates += 1;
        const f = state.users.find((u) => u.id === params[0]);
        if (f) f.role = params[1];
        return { rows: [], rowCount: f ? 1 : 0 };
      }
      if (s.includes('INSERT INTO users')) {
        state.inserts += 1;
        const [username, password_hash, role] = params;
        state.users.push({ id: 900 + state.inserts, username, password_hash, role, status: 'active', must_change_password: true, is_system_admin: true, first_name: 'System', last_name: 'Administrator' });
        return { rows: [], rowCount: 1 };
      }
      throw new Error(`unexpected sql: ${s.slice(0, 90)}`);
    }
  };

  return { state, async connect() { return client; } };
}

const log = { info() {}, warn() {}, error() {} };

// ---------------------------------------------------------------------------------------------
// ensureSystemAdminAccount — startup reconcile (never creates with the default password)
// ---------------------------------------------------------------------------------------------

test('empty clean database defers to the first-install bootstrap and creates nothing', async () => {
  const pool = createPool({ users: [] });
  const res = await ensureSystemAdminAccount(pool, { logger: log });
  assert.equal(res.status, 'deferred_clean_install');
  assert.equal(pool.state.inserts, 0);
});

test('existing admin@talonhound.local (already admin) is flagged, password hash preserved', async () => {
  const pool = createPool({
    users: [{ username: DEFAULT_ADMIN_EMAIL, role: 'admin', status: 'active', is_system_admin: false, password_hash: 'PRESERVED', first_name: 'Ada' }]
  });
  const res = await ensureSystemAdminAccount(pool, { logger: log });
  assert.equal(res.status, 'reconciled');
  assert.equal(pool.state.inserts, 0);
  const row = pool.state.users[0];
  assert.equal(row.is_system_admin, true);
  assert.equal(row.role, 'admin');
  assert.equal(row.password_hash, 'PRESERVED');
  assert.equal(row.first_name, 'Ada');
});

test('already-flagged admin account is a no-op', async () => {
  const pool = createPool({ users: [{ username: DEFAULT_ADMIN_EMAIL, role: 'admin', status: 'active', is_system_admin: true }] });
  const res = await ensureSystemAdminAccount(pool, { logger: log });
  assert.equal(res.status, 'noop');
  assert.equal(pool.state.inserts, 0);
  assert.equal(pool.state.flagUpdates, 0);
});

test('flagged account with a drifted role is reconciled back to admin', async () => {
  const pool = createPool({ users: [{ username: DEFAULT_ADMIN_EMAIL, role: 'analyst', status: 'active', is_system_admin: true }] });
  const res = await ensureSystemAdminAccount(pool, { logger: log });
  assert.equal(res.status, 'reconciled');
  assert.equal(pool.state.users[0].role, 'admin');
  assert.equal(pool.state.inserts, 0);
});

test('case-different email reconciles the same row, no duplicate created', async () => {
  const pool = createPool({ users: [{ username: 'Admin@TalonHound.Local', role: 'admin', status: 'active', is_system_admin: false }] });
  const res = await ensureSystemAdminAccount(pool, { logger: log });
  assert.equal(res.status, 'reconciled');
  assert.equal(pool.state.inserts, 0);
  assert.equal(pool.state.users.filter((u) => String(u.username).toLowerCase() === SYSTEM_ADMIN_EMAIL).length, 1);
});

test('existing install missing the account but with another active admin: manual-required, no create', async () => {
  const pool = createPool({ users: [{ username: 'ops@corp', role: 'admin', status: 'active', is_system_admin: false }] });
  const res = await ensureSystemAdminAccount(pool, { logger: log });
  assert.equal(res.status, 'missing_manual_required');
  assert.equal(res.activeAdminCount, 1);
  assert.equal(pool.state.inserts, 0); // never auto-created with the known default password
});

test('existing install missing the account AND no active admin: startup fails loudly', async () => {
  const pool = createPool({ users: [{ username: 'reader@corp', role: 'readonly', status: 'active', is_system_admin: false }] });
  await assert.rejects(
    ensureSystemAdminAccount(pool, { logger: log }),
    (err) => err instanceof SystemAdminBootstrapError
  );
  assert.equal(pool.state.inserts, 0);
});

test('a non-admin squatting admin@talonhound.local is NOT auto-promoted (no privilege escalation)', async () => {
  const pool = createPool({
    users: [
      { username: DEFAULT_ADMIN_EMAIL, role: 'readonly', status: 'active', is_system_admin: false },
      { username: 'realadmin@corp', role: 'admin', status: 'active', is_system_admin: false }
    ]
  });
  const res = await ensureSystemAdminAccount(pool, { logger: log });
  assert.equal(res.status, 'missing_manual_required');
  assert.equal(pool.state.users[0].is_system_admin, false); // not flagged
  assert.equal(pool.state.users[0].role, 'readonly'); // not promoted
});

test('a non-admin squatter with no other active admin fails startup', async () => {
  const pool = createPool({ users: [{ username: DEFAULT_ADMIN_EMAIL, role: 'readonly', status: 'active', is_system_admin: false }] });
  await assert.rejects(ensureSystemAdminAccount(pool, { logger: log }), SystemAdminBootstrapError);
});

test('missing account never returns a success/created status (no silent success)', async () => {
  const pool = createPool({ users: [{ username: 'ops@corp', role: 'admin', status: 'active', is_system_admin: false }] });
  const res = await ensureSystemAdminAccount(pool, { logger: log });
  assert.notEqual(res.status, 'created');
  assert.notEqual(res.status, 'noop');
  assert.notEqual(res.status, 'reconciled');
});

test('skips when the advisory lock is not acquired', async () => {
  const pool = createPool({ users: [], lockAcquired: false });
  const res = await ensureSystemAdminAccount(pool, { logger: log });
  assert.equal(res.status, 'skipped_lock');
  assert.equal(pool.state.inserts, 0);
});

// ---------------------------------------------------------------------------------------------
// provisionSystemAdmin — operator CLI path (may create, with a securely supplied password)
// ---------------------------------------------------------------------------------------------

test('provision creates a flagged, must-change account with the supplied password', async () => {
  const pool = createPool({ users: [{ username: 'ops@corp', role: 'admin', status: 'active', is_system_admin: false }] });
  const res = await provisionSystemAdmin(pool, { password: 'Operator-Chosen-Pw-1', logger: log });
  assert.equal(res.status, 'created');
  const created = pool.state.users.find((u) => u.username === SYSTEM_ADMIN_EMAIL);
  assert.ok(created);
  assert.equal(created.role, 'admin');
  assert.equal(created.status, 'active');
  assert.equal(created.is_system_admin, true);
  assert.equal(created.must_change_password, true);
  assert.notEqual(created.password_hash, 'Operator-Chosen-Pw-1');
  assert.match(String(created.password_hash), /^\$2[aby]?\$/);
  assert.equal(await bcrypt.compare('Operator-Chosen-Pw-1', created.password_hash), true);
});

test('provision on an existing account reconciles flag/role and preserves the password hash', async () => {
  const pool = createPool({ users: [{ username: DEFAULT_ADMIN_EMAIL, role: 'analyst', status: 'active', is_system_admin: false, password_hash: 'KEEP_ME' }] });
  const res = await provisionSystemAdmin(pool, { password: 'unused-because-exists', logger: log });
  assert.equal(res.status, 'reconciled');
  assert.equal(pool.state.inserts, 0);
  const row = pool.state.users[0];
  assert.equal(row.is_system_admin, true);
  assert.equal(row.role, 'admin');
  assert.equal(row.password_hash, 'KEEP_ME');
});

test('provision requires a non-empty password', async () => {
  const pool = createPool({ users: [] });
  await assert.rejects(provisionSystemAdmin(pool, { password: '', logger: log }), /password/i);
});
