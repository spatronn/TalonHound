import test from 'node:test';
import assert from 'node:assert/strict';
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

test('135 must_change_password migration is runnable', () => {
  assert.equal(isRunnableMigrationFile('135_users_must_change_password.sql'), true);
});
