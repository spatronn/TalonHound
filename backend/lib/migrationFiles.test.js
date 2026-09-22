import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  isRunnableMigrationFile,
  sortMigrationFiles,
  getLatestMigrationMeta
} from './migrationFiles.js';

test('isRunnableMigrationFile accepts plain .sql migrations', () => {
  assert.equal(isRunnableMigrationFile('001_core.sql'), true);
  assert.equal(isRunnableMigrationFile('002_add_feature.sql'), true);
});

test('isRunnableMigrationFile rejects disabled and backup suffixes', () => {
  assert.equal(isRunnableMigrationFile('071_ioc_confidence_model.sql.disabled'), false);
  assert.equal(isRunnableMigrationFile('071.disabled.sql'), false);
  assert.equal(isRunnableMigrationFile('001_core.sql.bak'), false);
  assert.equal(isRunnableMigrationFile('001_core.sql.tmp'), false);
  assert.equal(isRunnableMigrationFile('001_core.sql.old'), false);
  assert.equal(isRunnableMigrationFile('README'), false);
  assert.equal(isRunnableMigrationFile('notes.txt'), false);
});

test('sortMigrationFiles is deterministic', () => {
  const sorted = sortMigrationFiles(['010_b.sql', '002_a.sql', '001_core.sql']);
  assert.deepEqual(sorted, ['001_core.sql', '002_a.sql', '010_b.sql']);
});

test('getLatestMigrationMeta reads numeric prefix from highest file', async () => {
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations');
  const meta = await getLatestMigrationMeta(dir);
  assert.equal(meta.latestMigrationFile, '029_align_seeded_sequences.sql');
  assert.equal(meta.latestMigration, 29);
});

test('009 snapshot constraint allows chunk_owned success rows', () => {
  const sql = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/009_published_feed_snapshots_chunk_owned.sql'),
    'utf8'
  );
  assert.match(sql, /chunk_owned/);
  assert.match(sql, /DROP CONSTRAINT IF EXISTS chk_pf_snapshots_content_or_artifact/);
  assert.match(sql, /ADD CONSTRAINT chk_pf_snapshots_content_or_artifact/);
  // Repair must precede re-add so existing null/null success rows can satisfy the check.
  const dropAt = sql.indexOf('DROP CONSTRAINT');
  const repairAt = sql.indexOf('UPDATE public.published_feed_snapshots');
  const addAt = sql.lastIndexOf('ADD CONSTRAINT');
  assert.ok(dropAt >= 0 && repairAt > dropAt && addAt > repairAt);
});

test('001_core snapshot constraint includes chunk_owned for fresh installs', () => {
  const sql = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/001_core.sql'),
    'utf8'
  );
  assert.match(sql, /chk_pf_snapshots_content_or_artifact[\s\S]*chunk_owned/);
});

test('001_core baseline contains core product schema objects', () => {
  const sql = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/001_core.sql'),
    'utf8'
  );
  assert.ok(sql.includes('CREATE TABLE public.ioc_items'));
  assert.ok(sql.includes('CREATE TABLE public.users'));
  assert.ok(sql.includes('CREATE TABLE public.file_artifacts'));
  assert.ok(sql.includes('CREATE TABLE public.ioc_saved_searches'));
  assert.ok(sql.includes('CREATE TABLE public.ioc_bulk_query_jobs'));
  assert.ok(sql.includes('CREATE TABLE public.published_feed_generations'));
  assert.ok(sql.includes('CREATE TABLE public.auth_sessions'));
  assert.ok(sql.includes('CREATE TABLE public.enrichment_provider_health'));
  assert.ok(!sql.includes('CREATE TABLE public.schema_migrations'));
});

test('001_core baseline includes canonical seed data markers', () => {
  const sql = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/001_core.sql'),
    'utf8'
  );
  assert.ok(sql.includes('INSERT INTO public.threat_classifications'));
  assert.ok(sql.includes('INSERT INTO public.tags'));
  assert.ok(sql.includes('INSERT INTO public.integration_feeds'));
  assert.ok(sql.includes('certpl-warning-list'));
  assert.ok(sql.includes('INSERT INTO public.threat_intel_provider_configs'));
});

test('001_core published feeds schema uses multi ioc_types', () => {
  const sql = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/001_core.sql'),
    'utf8'
  );
  assert.match(sql, /ioc_types jsonb NOT NULL/);
  assert.match(sql, /chk_published_feeds_ioc_types/);
  assert.match(sql, /published_feeds_bridge_ioc_types/);
});

test('025 documents last_seen_in_feed as last source observation and bounds ThreatFox backfill', () => {
  const sql = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/025_ioc_source_last_seen.sql'),
    'utf8'
  );
  assert.match(sql, /COMMENT ON COLUMN public\.ioc_feed_memberships\.last_seen_in_feed/);
  assert.match(sql, /threatfox-abusech/);
  assert.match(sql, /source_name LIKE 'ThreatFox:%'/);
  assert.match(sql, /SOURCE ISOLATION/);
  // Must never assign membership last_seen from a non-ThreatFox ioc_items row.
  assert.match(sql, /WHERE tf\.source_name LIKE 'ThreatFox:%'/);
  assert.match(sql, /last_seen_in_feed = o\.observed_at/);
  assert.doesNotMatch(sql, /DELETE /);
  // Guard against accidental global MAX(last_seen_at) across all sources.
  assert.doesNotMatch(sql, /MAX\(\s*(?:i|anchor)\.last_seen_at\s*\)/);
  // Postgres rejects UPDATE target aliases inside JOIN/ON of FROM.
  assert.doesNotMatch(sql, /JOIN\s+ioc_items\s+anchor\s*\n\s*ON\s+anchor\.id\s*=\s*m\./i);
  assert.match(sql, /FROM\s+integration_feeds\s+f,\s*\n\s*ioc_items\s+anchor,\s*\n\s*threatfox_obs\s+o/i);
});

test('027 reparents tombstone IOC links without deleting enrichments or IOC rows', () => {
  const sql = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/027_reparent_merged_artifact_ioc_links.sql'),
    'utf8'
  );
  assert.match(sql, /file_artifact_ioc_links/);
  assert.match(sql, /merged_into_artifact_id/);
  assert.match(sql, /is_canonical_ioc = FALSE/);
  assert.match(sql, /status = 'merged'/);
  assert.doesNotMatch(sql, /DELETE FROM public\.ioc_items/i);
  assert.doesNotMatch(sql, /DELETE FROM public\.ioc_enrichments/i);
  assert.doesNotMatch(sql, /DROP TABLE/i);
});

test('028 adds ioc_item_id index for page-scoped alias expansion', () => {
  const sql = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/028_file_artifact_ioc_links_ioc_item_id_idx.sql'),
    'utf8'
  );
  assert.match(sql, /CREATE INDEX IF NOT EXISTS idx_file_artifact_ioc_links_ioc_item_id/);
  assert.match(sql, /ON file_artifact_ioc_links \(ioc_item_id\)/);
});

// ---- Seeded sequence regression (fresh install failed at 019: ioc_sources_pkey) ----

const MIGRATIONS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations');
const REPO_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** Tables whose id defaults to a sequence AND that 001_core.sql seeds with explicit ids. */
function seededSequenceTables(coreSql) {
  const withSequence = [...coreSql.matchAll(
    /^ALTER TABLE ONLY public\.([a-z_]+) ALTER COLUMN id SET DEFAULT nextval\('public\.([a-z_]+)'::regclass\);$/gm
  )].map((m) => ({ table: m[1], sequence: m[2] }));
  const seeded = new Set([...coreSql.matchAll(/^INSERT INTO public\.([a-z_]+) \(id, /gm)].map((m) => m[1]));
  return withSequence
    .filter((t) => seeded.has(t.table))
    .sort((a, b) => a.table.localeCompare(b.table));
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function forwardOnlySetval({ table, sequence }) {
  return new RegExp([
    escapeRe(`SELECT pg_catalog.setval('public.${sequence}', m.max_id, true)`),
    escapeRe(`FROM (SELECT max(id) AS max_id FROM public.${table}) m, public.${sequence} s`),
    escapeRe('WHERE m.max_id IS NOT NULL'),
    escapeRe('AND m.max_id >= CASE WHEN s.is_called THEN s.last_value + 1 ELSE s.last_value END;')
  ].join('\\s+'));
}

test('001_core seeds explicit ids only into the four known sequence-backed tables', () => {
  const core = readFileSync(path.join(MIGRATIONS_DIR, '001_core.sql'), 'utf8');
  assert.deepEqual(seededSequenceTables(core).map((t) => t.table), [
    'ioc_sources',
    'tags',
    'threat_feed_expiration_policies',
    'threat_intel_provider_configs'
  ]);
});

test('001_core restores every seeded sequence after its explicit-id rows (fresh install)', () => {
  const core = readFileSync(path.join(MIGRATIONS_DIR, '001_core.sql'), 'utf8');
  for (const t of seededSequenceTables(core)) {
    const setvalAt = core.search(forwardOnlySetval(t));
    assert.ok(setvalAt > 0, `001_core must align ${t.sequence}`);
    const lastInsert = core.lastIndexOf(`INSERT INTO public.${t.table} (id, `);
    assert.ok(setvalAt > lastInsert, `${t.sequence} must be aligned after the last seeded ${t.table} row`);
  }
});

test('029 repairs every seeded sequence forward-only (never RESTART / backwards)', () => {
  const core = readFileSync(path.join(MIGRATIONS_DIR, '001_core.sql'), 'utf8');
  const sql = readFileSync(path.join(MIGRATIONS_DIR, '029_align_seeded_sequences.sql'), 'utf8');
  const tables = seededSequenceTables(core);
  for (const t of tables) {
    assert.match(sql, forwardOnlySetval(t), `029 must align ${t.sequence}`);
  }
  const code = sql.replace(/^--.*$/gm, '');
  assert.doesNotMatch(code, /RESTART|ALTER SEQUENCE|DROP|DELETE|UPDATE|TRUNCATE|INSERT/i);
  assert.equal((code.match(/setval\(/g) || []).length, tables.length);
});

test('baseline builder keeps pg_dump setval lines and drops only the session preamble', () => {
  const script = readFileSync(path.join(REPO_ROOT, 'scripts/baseline/build-001-core.sh'), 'utf8');
  assert.doesNotMatch(script, /\/\^SELECT pg_catalog\/d/, 'a bare pg_catalog filter strips setval');
  const m = script.match(/^PG_DUMP_SESSION_FILTER='(.+)'$/m);
  assert.ok(m, 'PG_DUMP_SESSION_FILTER must be defined');
  // Each sed command is "/<BRE>/d"; in these BREs "\." is a literal dot and "(" is literal.
  const patterns = m[1].split(';').map((cmd) => new RegExp(
    cmd.replace(/^\//, '').replace(/\/d$/, '').replace(/\(/g, '\\(')
  ));
  const dropped = (line) => patterns.some((re) => re.test(line));
  assert.equal(dropped("SELECT pg_catalog.setval('public.tags_id_seq', 5, true);"), false);
  assert.equal(dropped("SELECT pg_catalog.set_config('search_path', '', false);"), true);
  assert.equal(dropped('SET statement_timeout = 0;'), true);
  assert.equal(dropped("INSERT INTO public.tags (id, name) VALUES (1, 'x');"), false);
  // Schema and seed-data pipelines both use the shared filter.
  assert.equal((script.match(/sed "\$\{PG_DUMP_SESSION_FILTER\}/g) || []).length, 2);
});

