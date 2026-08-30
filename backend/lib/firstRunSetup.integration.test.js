import test from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import {
  readSetupState,
  completeFirstRunSetup,
  seedSetupCodeHash,
  FirstRunSetupError
} from './firstRunSetup.js';
import { hashSetupCode } from './setupCode.js';
import { clearSystemTimeCache } from './systemTime.js';

/**
 * Real-Postgres integration tests for the first-run Setup Wizard. Exercises the transactional
 * completion, the single-System-Administrator invariant, and concurrent-setup safety against an
 * actual database (the migrated schema, including uq_users_single_system_admin). Skips cleanly
 * when no database is reachable (e.g. local dev without a DB), so it is safe in every suite.
 *
 * In CI this runs after `npm run migrate`, against the postgres service.
 */

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 6
});

let hasDb = false;
try {
  await pool.query('SELECT 1');
  await pool.query("SELECT setup_code_hash, setup_completed_at FROM system_settings LIMIT 1");
  hasDb = true;
} catch {
  hasDb = false;
}

const opts = { skip: hasDb ? false : 'no database available (set DB_HOST/DB_PASSWORD to run)' };

async function resetGreenfield(codeHash = null) {
  clearSystemTimeCache();
  await pool.query('INSERT INTO system_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING');
  // Clear audit rows first (FK to users) then users, to reach a true greenfield state.
  await pool.query('DELETE FROM audit_logs').catch(() => {});
  await pool.query('DELETE FROM users');
  await pool.query(
    `UPDATE system_settings
        SET setup_completed_at = NULL,
            setup_completed_by = NULL,
            setup_code_hash = $1::text,
            initial_setup_completed = FALSE,
            timezone_configuration_required = FALSE,
            active_system_timezone = NULL,
            pending_system_timezone = NULL,
            default_admin_bootstrapped = FALSE
      WHERE id = 1`,
    [codeHash]
  );
  clearSystemTimeCache();
}

test('integration: greenfield completion creates one system admin + tz, invalidates code', opts, async () => {
  const code = 'ABCD-EFGH-JKMN-PQRS';
  await resetGreenfield(hashSetupCode(code));

  const before = await readSetupState(pool);
  assert.equal(before.admin_setup_required, true);
  assert.equal(before.setup_code_required, true);

  const result = await completeFirstRunSetup(pool, {
    code,
    username: 'sysadmin@corp.example',
    password: 'a-strong-passphrase-123',
    confirmPassword: 'a-strong-passphrase-123',
    timezone: 'Europe/Istanbul'
  });
  assert.equal(result.username, 'sysadmin@corp.example');

  const users = await pool.query("SELECT username, role, status, is_system_admin, must_change_password FROM users");
  assert.equal(users.rowCount, 1);
  assert.equal(users.rows[0].is_system_admin, true);
  assert.equal(users.rows[0].role, 'admin');
  assert.equal(users.rows[0].status, 'active');
  assert.equal(users.rows[0].must_change_password, false);

  const settings = await pool.query('SELECT setup_code_hash, setup_completed_at, active_system_timezone, initial_setup_completed FROM system_settings WHERE id=1');
  assert.equal(settings.rows[0].setup_code_hash, null);
  assert.ok(settings.rows[0].setup_completed_at);
  assert.equal(settings.rows[0].active_system_timezone, 'Europe/Istanbul');
  assert.equal(settings.rows[0].initial_setup_completed, true);

  const after = await readSetupState(pool);
  assert.equal(after.setup_completed, true);
  assert.equal(after.admin_setup_required, false);
});

test('integration: completion is locked after setup already done', opts, async () => {
  const code = 'ABCD-EFGH-JKMN-PQRS';
  await resetGreenfield(hashSetupCode(code));
  await completeFirstRunSetup(pool, {
    code, username: 'admin1@corp.example', password: 'a-strong-passphrase-123', confirmPassword: 'a-strong-passphrase-123', timezone: 'Europe/Istanbul'
  });
  await assert.rejects(
    () => completeFirstRunSetup(pool, {
      code, username: 'admin2@corp.example', password: 'a-strong-passphrase-123', confirmPassword: 'a-strong-passphrase-123', timezone: 'Europe/London'
    }),
    (err) => err instanceof FirstRunSetupError && err.status === 409
  );
  const users = await pool.query('SELECT COUNT(*)::int AS n FROM users');
  assert.equal(users.rows[0].n, 1);
});

test('integration: wrong setup code is rejected and creates no user', opts, async () => {
  await resetGreenfield(hashSetupCode('RIGHT-CODE-HERE-XXXX'));
  await assert.rejects(
    () => completeFirstRunSetup(pool, {
      code: 'WRONG-CODE-HERE-YYYY', username: 'x@corp.example', password: 'a-strong-passphrase-123', confirmPassword: 'a-strong-passphrase-123', timezone: 'Europe/Istanbul'
    }),
    (err) => err instanceof FirstRunSetupError && err.code === 'INVALID_SETUP_CODE'
  );
  const users = await pool.query('SELECT COUNT(*)::int AS n FROM users');
  assert.equal(users.rows[0].n, 0);
});

test('integration: concurrent setup yields exactly one administrator', opts, async () => {
  const code = 'ABCD-EFGH-JKMN-PQRS';
  await resetGreenfield(hashSetupCode(code));

  const attempt = (username, timezone) => completeFirstRunSetup(pool, {
    code, username, password: 'a-strong-passphrase-123', confirmPassword: 'a-strong-passphrase-123', timezone
  }).then(
    (r) => ({ ok: true, r }),
    (e) => ({ ok: false, e })
  );

  const results = await Promise.all([
    attempt('race-a@corp.example', 'Europe/Istanbul'),
    attempt('race-b@corp.example', 'Europe/London'),
    attempt('race-c@corp.example', 'America/New_York')
  ]);

  const winners = results.filter((x) => x.ok);
  const losers = results.filter((x) => !x.ok);
  assert.equal(winners.length, 1, 'exactly one setup completion should succeed');
  assert.ok(losers.every((l) => l.e instanceof FirstRunSetupError && l.e.status === 409));

  const users = await pool.query('SELECT COUNT(*)::int AS n, COUNT(*) FILTER (WHERE is_system_admin)::int AS admins FROM users');
  assert.equal(users.rows[0].n, 1, 'exactly one user row');
  assert.equal(users.rows[0].admins, 1, 'exactly one system administrator');
});

test('integration: seedSetupCodeHash only seeds on greenfield', opts, async () => {
  await resetGreenfield(null);
  const hash = hashSetupCode('SEED-CODE-TEST-ZZZZ');
  assert.equal((await seedSetupCodeHash(pool, { env: { SETUP_CODE_HASH: hash } })).status, 'seeded');
  const seeded = await pool.query('SELECT setup_code_hash FROM system_settings WHERE id=1');
  assert.equal(seeded.rows[0].setup_code_hash, hash);
  // Second call: idempotent.
  assert.equal((await seedSetupCodeHash(pool, { env: { SETUP_CODE_HASH: hash } })).status, 'already_present');

  // Complete setup, then seeding must never re-arm the code.
  await completeFirstRunSetup(pool, {
    code: 'SEED-CODE-TEST-ZZZZ', username: 'seed-admin@corp.example', password: 'a-strong-passphrase-123', confirmPassword: 'a-strong-passphrase-123', timezone: 'Europe/Istanbul'
  });
  assert.equal((await seedSetupCodeHash(pool, { env: { SETUP_CODE_HASH: hash } })).status, 'skipped_not_greenfield');
});

test.after(async () => {
  // Best-effort cleanup so the shared CI database is left greenfield.
  if (hasDb) {
    await pool.query('DELETE FROM audit_logs').catch(() => {});
    await pool.query('DELETE FROM users').catch(() => {});
    await pool.query(
      `UPDATE system_settings SET setup_completed_at=NULL, setup_completed_by=NULL, setup_code_hash=NULL,
              initial_setup_completed=FALSE, active_system_timezone=NULL, default_admin_bootstrapped=FALSE WHERE id=1`
    ).catch(() => {});
  }
  await pool.end().catch(() => {});
});
