import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { isRunnableMigrationFile, sortMigrationFiles } from './migrationFiles.js';

test('isRunnableMigrationFile accepts plain .sql migrations', () => {
  assert.equal(isRunnableMigrationFile('071_ioc_confidence_model.sql'), true);
  assert.equal(isRunnableMigrationFile('072_ioc_confidence_model_safe.sql'), true);
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

test('155 STIX formats migration is runnable', () => {
  assert.equal(isRunnableMigrationFile('155_published_feeds_stix_format.sql'), true);
});

test('156 IOC read/export scopes migration is runnable and expands CHECKs', () => {
  assert.equal(isRunnableMigrationFile('156_api_ioc_read_export_scopes.sql'), true);
  const sql = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/156_api_ioc_read_export_scopes.sql'),
    'utf8'
  );
  assert.ok(sql.includes('ioc_read'));
  assert.ok(sql.includes('ioc:read'));
  assert.ok(sql.includes('ioc:export'));
  assert.ok(sql.includes('chk_pf_access_keys_key_type'));
  assert.ok(sql.includes('chk_pf_access_keys_scopes'));
});

test('155 migration allows stix in published_feeds formats CHECK', () => {
  const sql = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/155_published_feeds_stix_format.sql'),
    'utf8'
  );
  assert.ok(sql.includes('stix'));
  assert.ok(sql.includes('chk_published_feeds_formats'));
  assert.ok(sql.includes("jsonb_array_length(formats) <= 3"));
});

test('154 migration converts last_seen_ttl to fixed_ttl and tightens CHECK', () => {
  const sql = readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '../migrations/154_drop_last_seen_ttl_expiration.sql'),
    'utf8'
  );
  assert.ok(sql.includes("WHERE expiration_mode = 'last_seen_ttl'"));
  assert.ok(sql.includes("expiration_mode = 'fixed_ttl'"));
  assert.ok(sql.includes('first_seen_in_feed'));
  assert.ok(sql.includes("CHECK (expiration_mode IN ('never', 'fixed_ttl', 'missing_from_feed_ttl'))"));
  assert.equal(sql.includes("'last_seen_ttl'") && sql.includes('IN ('), true);
  assert.equal(/CHECK \(expiration_mode IN \([^)]*last_seen_ttl/.test(sql), false);
});
