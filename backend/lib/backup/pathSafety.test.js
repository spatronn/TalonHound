import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidBackupId,
  isValidArchiveFilename,
  assertSafeRelativeName,
  redactErrorMessage,
  publicErrorMessage
} from './pathSafety.js';

describe('backup pathSafety', () => {
  it('validates backup ids and archive names', () => {
    assert.equal(isValidBackupId('backup-20260725-120000-abcd12'), true);
    assert.equal(isValidBackupId('../etc/passwd'), false);
    assert.equal(isValidArchiveFilename('backup-20260725-120000-abcd12.tar.gz'), true);
    assert.equal(isValidArchiveFilename('../x.tar.gz'), false);
    assert.equal(isValidArchiveFilename('backup-20260725-120000-abcd12.tar.gz.enc'), true);
  });

  it('rejects traversal filenames', () => {
    assert.throws(() => assertSafeRelativeName('../x'), /Invalid/);
    assert.throws(() => assertSafeRelativeName('a/b'), /Invalid/);
    assert.equal(assertSafeRelativeName('ok.tar.gz'), 'ok.tar.gz');
  });

  it('redacts secrets from errors', () => {
    const s = redactErrorMessage('fail PGPASSWORD=supersecret password=also');
    assert.ok(!s.includes('supersecret'));
    assert.ok(s.includes('***'));
  });

  it('maps public error codes', () => {
    assert.match(publicErrorMessage('CHECKSUM_MISMATCH'), /checksum/i);
    assert.match(publicErrorMessage('CONFIRMATION'), /confirmation/i);
  });
});
