#!/usr/bin/env node
/**
 * Disposable PostgreSQL harness for File Artifact migration/backfill/list/export tests.
 *
 * Safety:
 *   - Requires ALLOW_FILE_ARTIFACT_DB_TESTS=1
 *   - DB_HOST must be localhost/127.0.0.1
 *   - DB_NAME must contain "_test"
 *   - NODE_ENV must not be production
 *
 * Exit codes:
 *   0 = all tests passed
 *   1 = tests failed / migration error
 *   2 = environment unavailable (Docker/guard) — NOT a pass
 *
 * Env (defaults for dockerized run):
 *   DB_HOST=127.0.0.1 DB_PORT=55432 DB_USER=talonhound DB_PASSWORD=test
 *   DB_NAME=talonhound_file_artifact_test
 *   FILE_ARTIFACT_DB_KEEP_CONTAINER=1  — leave container running after tests
 *   FILE_ARTIFACT_DB_SKIP_DOCKER=1     — use already-running DB (still guarded)
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { assertFileArtifactDbTestAllowed } from '../lib/fileArtifacts/dbTestGuard.js';
import { seedFileArtifactFixture, FIXTURE_HASHES } from '../lib/fileArtifacts/testFixture.js';
import {
  attachExactHash,
  findArtifactByHash,
  buildGroupedCteBody,
  buildCanonicalActiveBrowsePageSql,
  collectFileArtifactValidationMetrics,
  countEmptyOrphanArtifacts
} from '../lib/fileArtifacts/index.js';
import { buildExportBatchQuery } from '../lib/iocSearchExport/exportRows.js';
import { queryActiveIocCanonicalBrowsePage } from '../lib/iocActiveSources.js';

const { Pool } = pg;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_ROOT = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(BACKEND_ROOT, '..');
const CONTAINER = 'th-file-artifact-test';
const IMAGE = 'postgres:16-alpine';
const DEFAULT_PORT = 55432;

const EXIT_FAIL = 1;
const EXIT_SKIP = 2;

let failures = 0;
let passed = 0;
const explainNotes = [];

function ok(name) {
  passed += 1;
  console.log(`  ✓ ${name}`);
}

function fail(name, err) {
  failures += 1;
  console.error(`  ✗ ${name}: ${err?.message || err}`);
}

async function assert(name, fn) {
  try {
    await fn();
    ok(name);
  } catch (err) {
    fail(name, err);
  }
}

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
      ...opts
    });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (d) => { stdout += d; });
    child.stderr?.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });
}

async function dockerAvailable() {
  try {
    const r = await run('docker', ['version', '--format', '{{.Server.Version}}']);
    return r.code === 0;
  } catch {
    return false;
  }
}

async function waitForPg(cfg, attempts = 40) {
  for (let i = 0; i < attempts; i += 1) {
    const pool = new Pool({
      host: cfg.host,
      port: cfg.port,
      user: cfg.user,
      password: cfg.password,
      database: 'postgres',
      connectionTimeoutMillis: 2000
    });
    try {
      await pool.query('SELECT 1');
      await pool.end();
      return;
    } catch {
      await pool.end().catch(() => {});
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  throw new Error('PostgreSQL did not become ready in time');
}

async function ensureContainer(cfg) {
  if (String(process.env.FILE_ARTIFACT_DB_SKIP_DOCKER || '') === '1') {
    console.log('[harness] FILE_ARTIFACT_DB_SKIP_DOCKER=1 — using existing DB');
    return { started: false };
  }

  const hasDocker = await dockerAvailable();
  if (!hasDocker) {
    const err = new Error(
      'Docker is not available. Install Docker Desktop (or set FILE_ARTIFACT_DB_SKIP_DOCKER=1 with a guarded local test DB).'
    );
    err.code = 'DOCKER_MISSING';
    throw err;
  }

  await run('docker', ['rm', '-f', CONTAINER]).catch(() => {});
  const r = await run('docker', [
    'run', '--rm', '-d',
    '--name', CONTAINER,
    '-e', `POSTGRES_PASSWORD=${cfg.password}`,
    '-e', `POSTGRES_USER=${cfg.user}`,
    '-e', `POSTGRES_DB=${cfg.database}`,
    '-p', `${cfg.port}:5432`,
    IMAGE
  ]);
  if (r.code !== 0) {
    throw new Error(`docker run failed: ${r.stderr || r.stdout}`);
  }
  console.log(`[harness] started ${CONTAINER} on port ${cfg.port}`);
  await waitForPg(cfg);
  return { started: true };
}

async function stopContainer(started) {
  if (!started) return;
  if (String(process.env.FILE_ARTIFACT_DB_KEEP_CONTAINER || '') === '1') {
    console.log(`[harness] keeping container ${CONTAINER}`);
    return;
  }
  await run('docker', ['rm', '-f', CONTAINER]);
  console.log(`[harness] removed ${CONTAINER}`);
}

async function runMigrations(cfg) {
  const env = {
    ...process.env,
    DB_HOST: cfg.host,
    DB_PORT: String(cfg.port),
    DB_USER: cfg.user,
    DB_PASSWORD: cfg.password,
    DB_NAME: cfg.database,
    NODE_ENV: 'test'
  };
  const r = await run(process.execPath, ['migrate.js'], {
    cwd: BACKEND_ROOT,
    env
  });
  if (r.code !== 0) {
    throw new Error(`migrate failed:\n${r.stderr || r.stdout}`);
  }
  console.log('[harness] migrations applied');
}

async function runBackfill(cfg, extraEnv = {}) {
  const env = {
    ...process.env,
    DB_HOST: cfg.host,
    DB_PORT: String(cfg.port),
    DB_USER: cfg.user,
    DB_PASSWORD: cfg.password,
    DB_NAME: cfg.database,
    NODE_ENV: 'test',
    ...extraEnv
  };
  const script = path.join(REPO_ROOT, 'integration', 'backfill-file-artifacts.js');
  const r = await run(process.execPath, [script], { cwd: path.join(REPO_ROOT, 'integration'), env });
  return r;
}

function countArtifacts(pool) {
  return pool.query(`SELECT COUNT(*)::int AS c FROM file_artifacts`).then((r) => r.rows[0].c);
}

function countHashes(pool) {
  return pool.query(`SELECT COUNT(*)::int AS c FROM file_artifact_hashes`).then((r) => r.rows[0].c);
}

async function runSqlListPage(pool, pageSize = 25, offset = 0) {
  process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
  const grouped = buildGroupedCteBody();
  const sql = `
    WITH filtered AS (
      SELECT id, public_id, observable, observable_type, source_name, confidence,
             category, threat_classification, threat_actor_id, note, created_at, status
      FROM ioc_items
      WHERE COALESCE(status, 'active') = 'active'
    ),
    grouped AS (
      ${grouped}
    )
    SELECT *, COUNT(*) OVER()::int AS total_count
    FROM grouped
    ORDER BY platform_imported_at DESC NULLS LAST, identity_key ASC
    LIMIT $1 OFFSET $2
  `;
  const { rows } = await pool.query(sql, [pageSize, offset]);
  return rows;
}

async function main() {
  console.log('[file-artifact-db-tests] starting');

  let cfg;
  try {
    // Apply defaults before guard so local docker path works out of the box
    if (!process.env.DB_HOST) process.env.DB_HOST = '127.0.0.1';
    if (!process.env.DB_PORT) process.env.DB_PORT = String(DEFAULT_PORT);
    if (!process.env.DB_NAME) process.env.DB_NAME = 'talonhound_file_artifact_test';
    if (!process.env.DB_USER) process.env.DB_USER = 'talonhound';
    if (!process.env.DB_PASSWORD) process.env.DB_PASSWORD = 'test';
    if (!process.env.NODE_ENV) process.env.NODE_ENV = 'test';
    if (!process.env.ALLOW_FILE_ARTIFACT_DB_TESTS) {
      process.env.ALLOW_FILE_ARTIFACT_DB_TESTS = '1';
    }
    cfg = assertFileArtifactDbTestAllowed(process.env);
  } catch (err) {
    console.error(`[file-artifact-db-tests] SKIP (guard): ${err.message}`);
    process.exit(EXIT_SKIP);
  }

  let started = false;
  try {
    const c = await ensureContainer(cfg);
    started = c.started;
  } catch (err) {
    if (err.code === 'DOCKER_MISSING') {
      console.error(`[file-artifact-db-tests] SKIP: ${err.message}`);
      process.exit(EXIT_SKIP);
    }
    console.error(`[file-artifact-db-tests] FAILED to start DB: ${err.message}`);
    process.exit(EXIT_FAIL);
  }

  const pool = new Pool({
    host: cfg.host,
    port: cfg.port,
    user: cfg.user,
    password: cfg.password,
    database: cfg.database
  });

  try {
    await runMigrations(cfg);

    await assert('migration 131 applied', async () => {
      const { rows } = await pool.query(
        `SELECT 1 FROM schema_migrations WHERE name = '131_file_artifacts.sql'`
      );
      if (!rows.length) throw new Error('131_file_artifacts.sql missing from schema_migrations');
      const tables = await pool.query(`
        SELECT COUNT(*)::int AS c FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name IN (
            'file_artifacts','file_artifact_hashes','file_artifact_ioc_links',
            'file_artifact_source_observations','file_artifact_non_identity_attrs',
            'file_artifact_merge_conflicts'
          )
      `);
      if (tables.rows[0].c !== 6) throw new Error(`expected 6 file_artifact tables, got ${tables.rows[0].c}`);
    });

    await assert('one-primary unique index exists', async () => {
      const { rows } = await pool.query(`
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'uq_file_artifact_hashes_one_primary'
      `);
      if (!rows.length) throw new Error('missing uq_file_artifact_hashes_one_primary');
    });

    const fixture = await seedFileArtifactFixture(pool);
    ok('seed fixture');

    // Dry-run must not mutate
    const beforeArt = await countArtifacts(pool);
    const beforeHash = await countHashes(pool);
    const dry = await runBackfill(cfg, {
      FILE_ARTIFACT_BACKFILL_DRY_RUN: '1',
      FILE_ARTIFACT_BACKFILL_PHASE: 'all'
    });
    await assert('dry-run exit 0', async () => {
      if (dry.code !== 0) throw new Error(dry.stderr || dry.stdout || `exit ${dry.code}`);
    });
    await assert('dry-run no mutation', async () => {
      const a = await countArtifacts(pool);
      const h = await countHashes(pool);
      if (a !== beforeArt || h !== beforeHash) {
        throw new Error(`dry-run mutated artifacts ${beforeArt}->${a} hashes ${beforeHash}->${h}`);
      }
    });

    // Real backfill
    const bf1 = await runBackfill(cfg, {
      FILE_ARTIFACT_BACKFILL_DRY_RUN: '0',
      FILE_ARTIFACT_BACKFILL_PHASE: 'all',
      FILE_ARTIFACT_BACKFILL_BATCH_SIZE: '200'
    });
    await assert('backfill #1 exit 0', async () => {
      if (bf1.code !== 0) throw new Error(bf1.stderr || bf1.stdout || `exit ${bf1.code}`);
    });

    await assert('MD5+SHA256 share one artifact after provider phase', async () => {
      const md5Art = await findArtifactByHash(pool, 'md5', fixture.MD5);
      const shaArt = await findArtifactByHash(pool, 'sha256', fixture.SHA256);
      if (!md5Art?.artifact_id || !shaArt?.artifact_id) {
        throw new Error('missing artifact for fixture hashes');
      }
      if (String(md5Art.artifact_id) !== String(shaArt.artifact_id)) {
        throw new Error(`MD5 artifact ${md5Art.artifact_id} != SHA256 artifact ${shaArt.artifact_id}`);
      }
    });

    const artCount1 = await countArtifacts(pool);
    const hashCount1 = await countHashes(pool);

    const bf2 = await runBackfill(cfg, {
      FILE_ARTIFACT_BACKFILL_PHASE: 'all',
      FILE_ARTIFACT_BACKFILL_BATCH_SIZE: '200'
    });
    await assert('backfill #2 idempotent', async () => {
      if (bf2.code !== 0) throw new Error(bf2.stderr || bf2.stdout);
      const a = await countArtifacts(pool);
      const h = await countHashes(pool);
      if (a !== artCount1 || h !== hashCount1) {
        throw new Error(`second backfill changed counts artifacts ${artCount1}->${a} hashes ${hashCount1}->${h}`);
      }
    });

    await assert('concurrent attach converges to one artifact', async () => {
      const sha256 = 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd';
      const results = await Promise.all(
        Array.from({ length: 10 }, (_, i) =>
          attachExactHash(pool, {
            hash_type: 'sha256',
            hash_value: sha256,
            verification_source: `concurrent-${i}`
          })
        )
      );
      const ids = [...new Set(results.filter((r) => r.ok).map((r) => String(r.artifact_id)))];
      if (ids.length !== 1) throw new Error(`expected 1 artifact id, got ${ids.join(',')}`);
      const { rows } = await pool.query(
        `SELECT COUNT(*)::int AS c FROM file_artifact_hashes
         WHERE hash_type = 'sha256' AND normalized_hash_value = $1`,
        [sha256]
      );
      if (rows[0].c !== 1) throw new Error(`expected 1 hash row, got ${rows[0].c}`);
      const orphans = await countEmptyOrphanArtifacts(pool);
      if (orphans !== 0) throw new Error(`empty orphans after concurrent attach: ${orphans}`);
    });

    process.env.FILE_ARTIFACTS_READ_ENABLED = '1';

    await assert('empty orphan invariant = 0', async () => {
      const metrics = await collectFileArtifactValidationMetrics(pool);
      console.log('[validation]', JSON.stringify(metrics));
      if (metrics.empty_orphan_artifacts !== 0) {
        throw new Error(`empty_orphan_artifacts=${metrics.empty_orphan_artifacts}`);
      }
      if (metrics.duplicate_exact_hashes !== 0) {
        throw new Error(`duplicate_exact_hashes=${metrics.duplicate_exact_hashes}`);
      }
      if (metrics.multiple_primary_hashes !== 0) {
        throw new Error(`multiple_primary_hashes=${metrics.multiple_primary_hashes}`);
      }
    });

    await assert('SQL browse page size 25, no cross-page dups', async () => {
      const sql = buildCanonicalActiveBrowsePageSql();
      if (!/LIMIT \$3 OFFSET \$4/.test(sql)) throw new Error('browse SQL missing page LIMIT/OFFSET');
      if (sql.indexOf('GROUP BY') < 0 || sql.indexOf('GROUP BY') > sql.lastIndexOf('LIMIT $3 OFFSET $4')) {
        throw new Error('browse SQL must GROUP BY before page LIMIT');
      }
      const page1 = await queryActiveIocCanonicalBrowsePage(pool, { limit: 25, offset: 0, browseCap: 2000 });
      const page2 = await queryActiveIocCanonicalBrowsePage(pool, { limit: 25, offset: 25, browseCap: 2000 });
      const page3 = await queryActiveIocCanonicalBrowsePage(pool, { limit: 25, offset: 50, browseCap: 2000 });
      if (page1.length !== 25) throw new Error(`page1 length ${page1.length}`);
      if (page2.length !== 25) throw new Error(`page2 length ${page2.length}`);
      const keys1 = new Set(page1.map((r) => r.identity_key));
      const keys2 = new Set(page2.map((r) => r.identity_key));
      const keys3 = new Set(page3.map((r) => r.identity_key));
      if (keys1.size !== page1.length) throw new Error('dup identity within page1');
      for (const k of keys2) {
        if (keys1.has(k)) throw new Error(`cross-page 1/2 duplicate ${k}`);
      }
      for (const k of keys3) {
        if (keys1.has(k) || keys2.has(k)) throw new Error(`cross-page duplicate involving page3 ${k}`);
      }
      console.log('[pagination]', JSON.stringify({
        page_1_count: page1.length,
        page_2_count: page2.length,
        page_3_count: page3.length,
        page_overlap: 0
      }));
    });

    await assert('list page size 25, no cross-page dups, total = identity count', async () => {
      const page1 = await runSqlListPage(pool, 25, 0);
      const page2 = await runSqlListPage(pool, 25, 25);
      if (page1.length > 25) throw new Error(`page1 length ${page1.length}`);
      if (!page1.length) throw new Error('page1 empty');
      const total = page1[0].total_count;
      const keys1 = new Set(page1.map((r) => r.identity_key));
      const keys2 = new Set(page2.map((r) => r.identity_key));
      if (keys1.size !== page1.length) throw new Error('dup identity_key within page1');
      for (const k of keys2) {
        if (keys1.has(k)) throw new Error(`cross-page duplicate ${k}`);
      }
      if (total < 60) throw new Error(`total_count too low: ${total}`);
      console.log('[cte-list]', JSON.stringify({ canonical_total: total, page_1: page1.length, page_2: page2.length }));
    });

    await assert('MD5/SHA256 search resolve same artifact', async () => {
      const a = await findArtifactByHash(pool, 'md5', FIXTURE_HASHES.MD5);
      const b = await findArtifactByHash(pool, 'sha256', FIXTURE_HASHES.SHA256);
      if (!a?.artifact_id || !b?.artifact_id || String(a.artifact_id) !== String(b.artifact_id)) {
        throw new Error('search hashes did not resolve same artifact');
      }
    });

    await assert('export row count matches identity count (read on)', async () => {
      process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
      const list = await runSqlListPage(pool, 500, 0);
      const identityTotal = list[0]?.total_count ?? 0;
      const { sql, params } = buildExportBatchQuery({
        whereSql: `COALESCE(i.status,'active') = 'active'`,
        dslParams: [],
        cutoff: new Date().toISOString(),
        cursor: null,
        batchSize: 1000
      });
      const { rows } = await pool.query(sql, params);
      if (rows.length !== identityTotal) {
        throw new Error(`export ${rows.length} != list identity ${identityTotal}`);
      }
    });

    await assert('flag off export uses raw ioc_items grain', async () => {
      process.env.FILE_ARTIFACTS_READ_ENABLED = '0';
      const { rows: raw } = await pool.query(
        `SELECT COUNT(*)::int AS c FROM ioc_items WHERE COALESCE(status,'active') = 'active'`
      );
      const { sql, params } = buildExportBatchQuery({
        whereSql: `COALESCE(i.status,'active') = 'active'`,
        dslParams: [],
        cutoff: new Date().toISOString(),
        cursor: null,
        batchSize: 5000
      });
      const { rows } = await pool.query(sql, params);
      if (rows.length !== raw[0].c) {
        throw new Error(`flag-off export ${rows.length} != raw ${raw[0].c}`);
      }
      process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
    });

    // EXPLAIN notes
    await assert('EXPLAIN browse/CTE identity grouping', async () => {
      process.env.FILE_ARTIFACTS_READ_ENABLED = '1';
      const browseExplain = `
        EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
        ${buildCanonicalActiveBrowsePageSql()}
      `;
      const browsePlanRows = await pool.query(browseExplain, [2000, 2000, 25, 0]);
      const browsePlan = browsePlanRows.rows.map((r) => Object.values(r)[0]).join('\n');
      explainNotes.push(browsePlan);
      console.log('[EXPLAIN] canonical browse (truncated):\n' + browsePlan.split('\n').slice(0, 30).join('\n'));

      const grouped = buildGroupedCteBody();
      const explainSql = `
        EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
        WITH filtered AS (
          SELECT id, public_id, observable, observable_type, source_name, confidence,
                 category, threat_classification, threat_actor_id, note, created_at, status
          FROM ioc_items
          WHERE COALESCE(status, 'active') = 'active'
        ),
        grouped AS ( ${grouped} )
        SELECT * FROM grouped
        ORDER BY platform_imported_at DESC, identity_key ASC
        LIMIT 25
      `;
      const { rows } = await pool.query(explainSql);
      const plan = rows.map((r) => Object.values(r)[0]).join('\n');
      explainNotes.push(plan);
      console.log('[EXPLAIN] CTE list (truncated):\n' + plan.split('\n').slice(0, 25).join('\n'));
      if (/Seq Scan on ioc_items/i.test(browsePlan + plan) && !/Index/i.test(browsePlan + plan)) {
        explainNotes.push('NOTE: sequential scan on ioc_items at fixture scale; production list paths already filter — no 132 index added yet.');
      } else {
        explainNotes.push('NOTE: No additive 132 index required at fixture scale (~60+ identities). Re-check with 1–5k identities before prod.');
      }
    });

    console.log(`\n[file-artifact-db-tests] ${passed} passed, ${failures} failed`);
    if (failures > 0) {
      process.exitCode = EXIT_FAIL;
    }
  } catch (err) {
    console.error('[file-artifact-db-tests] fatal:', err);
    process.exitCode = EXIT_FAIL;
  } finally {
    await pool.end().catch(() => {});
    await stopContainer(started);
  }

  if (explainNotes.length) {
    console.log('\n--- EXPLAIN notes ---');
    for (const n of explainNotes) {
      if (n.startsWith('NOTE:')) console.log(n);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(EXIT_FAIL);
});
