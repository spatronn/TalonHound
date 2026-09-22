import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { listRunnableMigrationFiles } from './migrationFiles.js';

/**
 * Real-Postgres check of a freshly migrated database (CI runs it right after
 * "Migrate fresh database" + the idempotency re-run).
 *
 * `npm run migrate` succeeding is not enough: the released 001_core.sql seeded
 * explicit ids without restoring their sequences, so 019 failed on a fresh DB and,
 * once migrations were retried past it, the first default-id insert into the other
 * seeded tables still collided (e.g. tags_pkey). This asserts:
 *   1. every runnable migration on disk is recorded in schema_migrations;
 *   2. each seeded sequence's next value is above MAX(id);
 *   3. a real default-id INSERT into each seeded table succeeds (rolled back).
 *
 * Opt-in (MIGRATION_CHAIN_ITEST=1) because the probe INSERTs consume sequence
 * values; only point it at a disposable / CI database.
 */

const { Pool } = pg;

const MIGRATIONS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations');

const enabled = process.env.MIGRATION_CHAIN_ITEST === '1';
const pool = enabled
  ? new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || 'talonhound',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'talonhound',
    connectionTimeoutMillis: 3000,
    max: 2
  })
  : null;

let hasDb = false;
if (pool) {
  try {
    await pool.query('SELECT 1 FROM schema_migrations LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = {
  skip: !enabled
    ? 'set MIGRATION_CHAIN_ITEST=1 against a disposable, migrated database'
    : (hasDb ? false : 'no migrated database available')
};

test.after(async () => {
  if (pool) await pool.end();
});

/** Minimal valid default-id insert per seeded table (all other columns defaulted). */
const SEEDED_TABLES = [
  {
    table: 'ioc_sources',
    insert: `INSERT INTO public.ioc_sources (name) VALUES ('zz_seq_probe') RETURNING id`
  },
  {
    table: 'tags',
    insert: `INSERT INTO public.tags (name, type, slug) VALUES ('zz-seq-probe', 'threat', 'zz-seq-probe') RETURNING id`
  },
  {
    table: 'threat_feed_expiration_policies',
    insert: `INSERT INTO public.threat_feed_expiration_policies (feed_id, observable_type)
             SELECT integration_id, 'zz-seq-probe' FROM public.integration_feeds ORDER BY integration_id LIMIT 1
             RETURNING id`
  },
  {
    table: 'threat_intel_provider_configs',
    insert: `INSERT INTO public.threat_intel_provider_configs (provider) VALUES ('zz-seq-probe') RETURNING id`
  }
];

test('every runnable migration on disk is recorded in schema_migrations', opts, async () => {
  const files = await listRunnableMigrationFiles(MIGRATIONS_DIR);
  const { rows } = await pool.query('SELECT name FROM schema_migrations WHERE name = ANY($1::text[])', [files]);
  const applied = new Set(rows.map((r) => r.name));
  assert.deepEqual(files.filter((f) => !applied.has(f)), [], 'pending migrations after migrate');
  assert.equal(applied.size, files.length);
});

for (const { table, insert } of SEEDED_TABLES) {
  test(`${table}: sequence is ahead of MAX(id) and a default-id INSERT succeeds`, opts, async () => {
    const client = await pool.connect();
    try {
      const { rows: [state] } = await client.query(
        `SELECT (SELECT max(id) FROM public.${table})::bigint AS max_id,
                s.last_value::bigint AS last_value, s.is_called
         FROM public.${table}_id_seq s`
      );
      const maxId = state.max_id == null ? 0 : Number(state.max_id);
      const nextValue = state.is_called ? Number(state.last_value) + 1 : Number(state.last_value);
      assert.ok(nextValue > maxId, `${table}_id_seq next value ${nextValue} must exceed MAX(id) ${maxId}`);

      await client.query('BEGIN');
      try {
        const { rows } = await client.query(insert);
        assert.equal(rows.length, 1, `${table} probe insert produced no row`);
        assert.ok(Number(rows[0].id) > maxId, `${table} generated id ${rows[0].id} must exceed MAX(id) ${maxId}`);
      } finally {
        await client.query('ROLLBACK');
      }
    } finally {
      client.release();
    }
  });
}
