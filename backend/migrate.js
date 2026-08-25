import './lib/ensure-db-password.js';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { listRunnableMigrationFiles } from './lib/migrationFiles.js';

const { Pool } = pg;

export const MIGRATION_ADVISORY_LOCK_KEY = 'talonhound:migrations';

const DEFAULT_LOCK_TIMEOUT = process.env.MIGRATION_LOCK_TIMEOUT || '5s';
const DEFAULT_STATEMENT_TIMEOUT = process.env.MIGRATION_STATEMENT_TIMEOUT || '120s';

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

/** @param {string} value */
function assertSafePgDuration(value, label) {
  const v = String(value || '').trim();
  if (!/^\d+(ms|s|min|h)?$/i.test(v)) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return v;
}

export { isRunnableMigrationFile, sortMigrationFiles } from './lib/migrationFiles.js';

async function ensureMigrationsTable(client) {
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function acquireMigrationLock(client) {
  const { rows } = await client.query(
    'SELECT pg_try_advisory_lock(hashtext($1)) AS acquired',
    [MIGRATION_ADVISORY_LOCK_KEY]
  );
  return Boolean(rows[0]?.acquired);
}

async function releaseMigrationLock(client) {
  await client.query('SELECT pg_advisory_unlock(hashtext($1))', [MIGRATION_ADVISORY_LOCK_KEY]).catch(() => {});
}

async function configureSessionTimeouts(client) {
  const lockTimeout = assertSafePgDuration(DEFAULT_LOCK_TIMEOUT, 'MIGRATION_LOCK_TIMEOUT');
  const statementTimeout = assertSafePgDuration(DEFAULT_STATEMENT_TIMEOUT, 'MIGRATION_STATEMENT_TIMEOUT');
  await client.query(`SET lock_timeout = '${lockTimeout}'`);
  await client.query(`SET statement_timeout = '${statementTimeout}'`);
}

async function listMode() {
  const dir = path.join(process.cwd(), 'migrations');
  const files = await listRunnableMigrationFiles(dir);
  console.log(`[migrate] runnable migrations (${files.length}):`);
  for (const file of files) {
    console.log(file);
  }
}

async function runMigrations() {
  const client = await pool.connect();
  let lockHeld = false;

  try {
    console.log('[migrate] starting');
    await configureSessionTimeouts(client);

    lockHeld = await acquireMigrationLock(client);
    if (!lockHeld) {
      console.error('[migrate] Another migration process is already running.');
      process.exit(1);
    }

    await ensureMigrationsTable(client);

    const dir = path.join(process.cwd(), 'migrations');
    const files = await listRunnableMigrationFiles(dir);
    console.log(`[migrate] found ${files.length} runnable .sql file(s)`);

    let appliedCount = 0;
    for (const file of files) {
      const already = await client.query('SELECT 1 FROM schema_migrations WHERE name = $1', [file]);
      if (already.rowCount) continue;

      const sql = await readFile(path.join(dir, file), 'utf8');
      console.log(`[migrate] applying ${file}`);
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
        appliedCount += 1;
        console.log(`[migrate] applied ${file}`);
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      }
    }

    console.log(`[migrate] done (${appliedCount} new migration(s) applied)`);
  } catch (err) {
    console.error('[migrate] failed', err?.message || err);
    process.exit(1);
  } finally {
    if (lockHeld) {
      await releaseMigrationLock(client);
    }
    client.release();
    await pool.end();
  }
}

async function main() {
  const args = new Set(process.argv.slice(2));
  if (args.has('--list')) {
    await listMode();
    return;
  }
  await runMigrations();
}

const isDirectRun = process.argv[1]
  && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);

if (isDirectRun) {
  main();
}
