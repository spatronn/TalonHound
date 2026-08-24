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
  assert.equal(meta.latestMigrationFile, '002_first_run_setup.sql');
  assert.equal(meta.latestMigration, 2);
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
