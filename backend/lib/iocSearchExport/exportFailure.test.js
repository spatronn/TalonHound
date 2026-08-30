import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyExportFailure, EXPORT_FAILURE_CODES, exportFailurePublicMessage } from './exportFailure.js';

test('classifies the PostgreSQL shared-memory resize failure', () => {
  const err = new Error(
    'could not resize shared memory segment "/PostgreSQL.1786937221" to 33554432 bytes: No space left on device'
  );
  const { code, publicMessage } = classifyExportFailure(err);
  assert.equal(code, EXPORT_FAILURE_CODES.INSUFFICIENT_SHARED_MEMORY);
  assert.equal(publicMessage, 'Export failed due to insufficient database shared memory. Check server resources and retry.');
  // The safe message must not echo any raw internals.
  assert.doesNotMatch(publicMessage, /PostgreSQL|segment|33554432|device/i);
});

test('classifies "out of shared memory" as the shared-memory class', () => {
  const { code } = classifyExportFailure(new Error('out of shared memory\nHINT: You might need to increase max_locks_per_transaction.'));
  assert.equal(code, EXPORT_FAILURE_CODES.INSUFFICIENT_SHARED_MEMORY);
});

test('a plain disk-full temp-file error is NOT misclassified as shared memory', () => {
  // "No space left on device" without shared-memory wording -> generic, not shm-specific.
  const { code, publicMessage } = classifyExportFailure(new Error('could not write to temporary file: No space left on device'));
  assert.equal(code, EXPORT_FAILURE_CODES.UNEXPECTED);
  assert.equal(publicMessage, exportFailurePublicMessage(EXPORT_FAILURE_CODES.UNEXPECTED));
});

test('an arbitrary DB error maps to the safe generic message', () => {
  const { code, publicMessage } = classifyExportFailure(new Error('deadlock detected'));
  assert.equal(code, EXPORT_FAILURE_CODES.UNEXPECTED);
  assert.match(publicMessage, /unexpected server error/i);
  assert.doesNotMatch(publicMessage, /deadlock/i);
});

test('tolerates non-Error inputs', () => {
  assert.equal(classifyExportFailure(undefined).code, EXPORT_FAILURE_CODES.UNEXPECTED);
  assert.equal(classifyExportFailure('boom').code, EXPORT_FAILURE_CODES.UNEXPECTED);
  assert.equal(classifyExportFailure({ message: 'could not resize shared memory segment' }).code, EXPORT_FAILURE_CODES.INSUFFICIENT_SHARED_MEMORY);
});
