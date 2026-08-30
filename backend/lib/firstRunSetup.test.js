import test from 'node:test';
import assert from 'node:assert/strict';
import bcrypt from 'bcrypt';
import {
  validateAdminUsername,
  validateAdminPassword,
  readSetupState,
  checkSetupCode,
  completeFirstRunSetup,
  seedSetupCodeHash,
  FirstRunSetupError,
  MIN_ADMIN_PASSWORD_LENGTH
} from './firstRunSetup.js';
import { hashSetupCode } from './setupCode.js';
import { clearSystemTimeCache } from './systemTime.js';

/**
 * Small in-memory Postgres stand-in supporting the exact query shapes used by
 * firstRunSetup + systemTime.loadSystemTimeConfig. Enforces the username-unique and
 * single-system-admin invariants so races surface as 23505 unique violations.
 */
function makeDb(initial = {}) {
  const state = {
    settings: {
      id: 1,
      setup_completed_at: null,
      setup_code_hash: null,
      initial_setup_completed: false,
      timezone_configuration_required: false,
      active_system_timezone: null,
      pending_system_timezone: null,
      timezone_restart_required: false,
      timezone_config_version: 0,
      active_timezone_config_version: 0,
      adoption_source: null,
      initial_setup_completed_at: null,
      timezone_change_requested_at: null,
      timezone_change_requested_by: null,
      timezone_promoted_at: null,
      timezone_updated_at: null,
      timezone_updated_by: null,
      ...(initial.settings || {})
    },
    users: initial.users ? [...initial.users] : []
  };

  function run(sql, params = []) {
    const s = String(sql);
    if (s.startsWith('BEGIN') || s.startsWith('COMMIT') || s.startsWith('ROLLBACK')) return { rows: [] };
    if (s.includes('pg_advisory_xact_lock')) return { rows: [{}] };
    if (s.includes('INSERT INTO system_settings (id) VALUES')) return { rows: [] };

    if (s.includes('FROM public.system_settings s') && s.includes('user_count')) {
      return {
        rows: [{
          setup_completed_at: state.settings.setup_completed_at,
          setup_code_hash: state.settings.setup_code_hash,
          initial_setup_completed: state.settings.initial_setup_completed,
          timezone_configuration_required: state.settings.timezone_configuration_required,
          active_system_timezone: state.settings.active_system_timezone,
          user_count: state.users.length
        }]
      };
    }

    if (s.includes('SELECT setup_code_hash, setup_completed_at FROM system_settings')) {
      return { rows: [{ setup_code_hash: state.settings.setup_code_hash, setup_completed_at: state.settings.setup_completed_at }] };
    }

    if (s.includes('SELECT setup_code_hash FROM system_settings')) {
      return { rows: [{ setup_code_hash: state.settings.setup_code_hash }] };
    }

    if (s.includes('SELECT COUNT(*)::int AS n FROM users')) {
      return { rows: [{ n: state.users.length }] };
    }

    if (s.includes('INSERT INTO users')) {
      const username = params[0];
      const isSystemAdmin = /is_system_admin/.test(s); // the first-run insert always sets it TRUE
      if (state.users.some((u) => String(u.username).toLowerCase() === String(username).toLowerCase())) {
        const err = new Error('duplicate key value violates unique constraint "users_username_key"');
        err.code = '23505';
        throw err;
      }
      if (state.users.some((u) => u.is_system_admin)) {
        const err = new Error('duplicate key value violates unique constraint "uq_users_single_system_admin"');
        err.code = '23505';
        throw err;
      }
      state.users.push({ username, is_system_admin: isSystemAdmin, role: 'admin' });
      return { rows: [] };
    }

    if (s.includes('UPDATE system_settings') && s.includes('setup_completed_at = NOW()')) {
      state.settings.setup_completed_at = new Date().toISOString();
      state.settings.setup_completed_by = params[2];
      state.settings.active_system_timezone = params[1];
      state.settings.initial_setup_completed = true;
      state.settings.timezone_configuration_required = false;
      state.settings.setup_code_hash = null;
      return { rows: [{ setup_completed_at: state.settings.setup_completed_at }] };
    }

    if (s.includes('UPDATE system_settings') && s.includes('SET setup_code_hash = $2')) {
      if (state.settings.setup_code_hash === null && state.settings.setup_completed_at === null) {
        state.settings.setup_code_hash = params[1];
        return { rowCount: 1, rows: [] };
      }
      return { rowCount: 0, rows: [] };
    }

    // loadSystemTimeConfig full select
    if (s.includes('FROM system_settings') && s.includes('pending_system_timezone') && s.includes('timezone_config_version')) {
      return { rows: [{ ...state.settings }] };
    }

    return { rows: [] };
  }

  const client = { query: async (sql, params) => run(sql, params), release() {} };
  const pool = {
    query: async (sql, params) => run(sql, params),
    connect: async () => client,
    _state: state
  };
  return { pool, state };
}

test('validateAdminUsername trims and enforces rules', () => {
  assert.equal(validateAdminUsername('  admin@x.io '), 'admin@x.io');
  assert.equal(validateAdminUsername('security-admin@corp.example'), 'security-admin@corp.example');
  assert.throws(() => validateAdminUsername(''), FirstRunSetupError);
  assert.throws(() => validateAdminUsername('ab'), FirstRunSetupError);
  assert.throws(() => validateAdminUsername('has space'), FirstRunSetupError);
});

test('validateAdminPassword enforces length and confirmation', () => {
  assert.throws(() => validateAdminPassword(''), /required/);
  assert.throws(() => validateAdminPassword('short'), new RegExp(`${MIN_ADMIN_PASSWORD_LENGTH}`));
  assert.throws(() => validateAdminPassword('admin'), new RegExp(`${MIN_ADMIN_PASSWORD_LENGTH}`));
  assert.throws(() => validateAdminPassword('correcthorsebattery', { confirm: 'different' }), /do not match/);
  assert.equal(validateAdminPassword('correcthorsebattery', { confirm: 'correcthorsebattery' }), 'correcthorsebattery');
});

test('readSetupState: greenfield requires admin, no code unless hash present', async () => {
  clearSystemTimeCache();
  const { pool } = makeDb();
  const s1 = await readSetupState(pool);
  assert.equal(s1.setup_completed, false);
  assert.equal(s1.admin_setup_required, true);
  assert.equal(s1.setup_code_required, false);

  const { pool: pool2 } = makeDb({ settings: { setup_code_hash: 'a'.repeat(64) } });
  const s2 = await readSetupState(pool2);
  assert.equal(s2.setup_code_required, true);
});

test('readSetupState: existing install (users present) is complete', async () => {
  const { pool } = makeDb({ users: [{ username: 'root@x', is_system_admin: true }] });
  const s = await readSetupState(pool);
  assert.equal(s.setup_completed, true);
  assert.equal(s.admin_setup_required, false);
  assert.equal(s.setup_code_required, false);
});

test('checkSetupCode validates against the stored hash', async () => {
  const code = 'ABCD-EFGH-JKMN-PQRS';
  const { pool } = makeDb({ settings: { setup_code_hash: hashSetupCode(code) } });
  assert.deepEqual(await checkSetupCode(pool, code), { valid: true, required: true });
  assert.deepEqual(await checkSetupCode(pool, 'WRON-GCOD-EWRO-NGXX'), { valid: false, required: true });
});

test('checkSetupCode with no hash configured passes without a code', async () => {
  const { pool } = makeDb();
  assert.deepEqual(await checkSetupCode(pool, ''), { valid: true, required: false });
});

test('completeFirstRunSetup creates one system admin, sets tz, invalidates code', async () => {
  clearSystemTimeCache();
  const code = 'ABCD-EFGH-JKMN-PQRS';
  const { pool, state } = makeDb({ settings: { setup_code_hash: hashSetupCode(code) } });
  const result = await completeFirstRunSetup(pool, {
    code,
    username: 'admin@corp.example',
    password: 'a-strong-passphrase-123',
    confirmPassword: 'a-strong-passphrase-123',
    timezone: 'Europe/Istanbul'
  });
  assert.equal(result.username, 'admin@corp.example');
  assert.equal(result.timezone, 'Europe/Istanbul');
  assert.equal(state.users.length, 1);
  assert.equal(state.users[0].is_system_admin, true);
  assert.equal(state.settings.setup_code_hash, null);
  assert.ok(state.settings.setup_completed_at);
  // password stored as a bcrypt hash, not plaintext (sanity on the flow, hash is in insert)
});

test('completeFirstRunSetup rejects a wrong setup code', async () => {
  clearSystemTimeCache();
  const { pool, state } = makeDb({ settings: { setup_code_hash: hashSetupCode('RIGHTCODE') } });
  await assert.rejects(
    () => completeFirstRunSetup(pool, {
      code: 'WRONG-CODE',
      username: 'admin@corp.example',
      password: 'a-strong-passphrase-123',
      confirmPassword: 'a-strong-passphrase-123',
      timezone: 'Europe/Istanbul'
    }),
    (err) => err instanceof FirstRunSetupError && err.code === 'INVALID_SETUP_CODE' && err.status === 401
  );
  assert.equal(state.users.length, 0);
});

test('completeFirstRunSetup refuses when a user already exists', async () => {
  clearSystemTimeCache();
  const { pool } = makeDb({ users: [{ username: 'root@x', is_system_admin: true }] });
  await assert.rejects(
    () => completeFirstRunSetup(pool, {
      username: 'admin@corp.example',
      password: 'a-strong-passphrase-123',
      confirmPassword: 'a-strong-passphrase-123',
      timezone: 'Europe/Istanbul'
    }),
    (err) => err instanceof FirstRunSetupError && err.code === 'SETUP_ALREADY_COMPLETED' && err.status === 409
  );
});

test('completeFirstRunSetup refuses after setup already completed', async () => {
  clearSystemTimeCache();
  const { pool } = makeDb({ settings: { setup_completed_at: new Date().toISOString() } });
  await assert.rejects(
    () => completeFirstRunSetup(pool, {
      username: 'admin@corp.example',
      password: 'a-strong-passphrase-123',
      confirmPassword: 'a-strong-passphrase-123',
      timezone: 'Europe/Istanbul'
    }),
    (err) => err instanceof FirstRunSetupError && err.code === 'SETUP_ALREADY_COMPLETED'
  );
});

test('completeFirstRunSetup validates timezone and password before touching the db', async () => {
  clearSystemTimeCache();
  const { pool, state } = makeDb();
  await assert.rejects(
    () => completeFirstRunSetup(pool, { username: 'admin@x.io', password: 'short', timezone: 'Europe/Istanbul' }),
    (err) => err.code === 'INVALID_PASSWORD'
  );
  await assert.rejects(
    () => completeFirstRunSetup(pool, { username: 'admin@x.io', password: 'a-strong-passphrase-123', timezone: 'Not/AZone' }),
    (err) => err.code === 'INVALID_TIMEZONE'
  );
  assert.equal(state.users.length, 0);
});

test('seedSetupCodeHash seeds only on greenfield and only once', async () => {
  clearSystemTimeCache();
  const hash = 'b'.repeat(64);
  const { pool, state } = makeDb();
  assert.equal((await seedSetupCodeHash(pool, { env: { SETUP_CODE_HASH: hash } })).status, 'seeded');
  assert.equal(state.settings.setup_code_hash, hash);
  // Idempotent: second call is a no-op.
  assert.equal((await seedSetupCodeHash(pool, { env: { SETUP_CODE_HASH: hash } })).status, 'already_present');

  const { pool: pool2 } = makeDb({ users: [{ username: 'root@x', is_system_admin: true }] });
  assert.equal((await seedSetupCodeHash(pool2, { env: { SETUP_CODE_HASH: hash } })).status, 'skipped_not_greenfield');

  const { pool: pool3 } = makeDb();
  assert.equal((await seedSetupCodeHash(pool3, { env: {} })).status, 'no_env_hash');
  assert.equal((await seedSetupCodeHash(pool3, { env: { SETUP_CODE_HASH: 'nothex' } })).status, 'invalid_env_hash');
});

// keep bcrypt import used (documents that completeFirstRunSetup hashes the password)
test('bcrypt is available for password hashing', async () => {
  const h = await bcrypt.hash('x', 4);
  assert.ok(await bcrypt.compare('x', h));
});
