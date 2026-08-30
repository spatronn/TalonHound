import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildManifest, parseManifest, isCompatibleFormatVersion } from './manifest.js';
import { BACKUP_FORMAT_VERSION } from './config.js';

describe('backup manifest', () => {
  it('builds a v2 manifest with required fields', () => {
    const m = buildManifest({
      backupId: 'backup-20260725-120000-abcd1234',
      schemaVersion: '127_system_backups.sql',
      postgresVersion: '16.4',
      triggerType: 'manual',
      components: { postgresBytes: 12345, archiveBytes: 10000 },
      checksums: { 'database/postgres.dump': 'abc' }
    });
    assert.equal(m.format_version, BACKUP_FORMAT_VERSION);
    assert.equal(m.application, 'TalonHound');
    assert.equal(m.backup_id, 'backup-20260725-120000-abcd1234');
    assert.equal(m.components.postgres.format, 'pg_custom');
    assert.equal(m.restore.api_restore_writes_data, false);
    assert.ok(m.excluded_components.includes('redis'));
    assert.ok(m.excluded_components.includes('clickhouse'));
  });

  it('parses legacy version field', () => {
    const m = parseManifest({ version: 1, bundle: 'talonhound-x', components: {} });
    assert.equal(m.format_version, 1);
    assert.equal(m.backup_id, 'talonhound-x');
  });

  it('rejects unsupported format version', () => {
    assert.throws(() => parseManifest({ format_version: 99, backup_id: 'x' }));
  });

  it('compatibility check', () => {
    assert.equal(isCompatibleFormatVersion(1), true);
    assert.equal(isCompatibleFormatVersion(2), true);
    assert.equal(isCompatibleFormatVersion(99), false);
  });
});
