import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { describeBackupContents } from './backupContents.js';

describe('describeBackupContents', () => {
  it('format 3 backup with Threat Library files', () => {
    const r = describeBackupContents({
      status: 'completed',
      format_version: 3,
      threat_library: { included: true, file_count: 271, bytes: 144_000_000 }
    });
    assert.equal(r.kind, 'full');
    assert.equal(r.short, 'DB + 271 Threat Library files');
    assert.equal(r.threatLibraryRecovery, true);
  });

  it('format 3 backup of an install without artifacts still counts as full', () => {
    const r = describeBackupContents({ status: 'completed', threat_library: { included: true, file_count: 1, bytes: 1 } });
    assert.equal(r.short, 'DB + 1 Threat Library file');
  });

  it('legacy PostgreSQL-only backup', () => {
    const r = describeBackupContents({
      status: 'completed',
      format_version: 2,
      threat_library: { included: false, file_count: null, bytes: null }
    });
    assert.equal(r.kind, 'database_only');
    assert.equal(r.threatLibraryRecovery, false);
    // rows serialized before threat_library existed
    assert.equal(describeBackupContents({ status: 'completed' }).kind, 'database_only');
  });

  it('non-completed rows describe nothing', () => {
    assert.equal(describeBackupContents({ status: 'failed' }).short, null);
  });
});
