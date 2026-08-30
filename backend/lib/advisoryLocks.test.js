import test from 'node:test';
import assert from 'node:assert/strict';
import {
  FIXED_INTEGER_ADVISORY_LOCKS,
  OTX_ADVISORY_LOCK,
  MALWAREBAZAAR_RECOVERY_ADVISORY_LOCK,
  CERTPL_ADVISORY_LOCK,
  findDuplicateFixedAdvisoryLocks
} from './advisoryLocks.js';
import { MALWAREBAZAAR_RECOVERY_LOCK_ID } from './malwarebazaarCoverage.js';

test('fixed integer advisory locks are unique across unrelated jobs', () => {
  const duplicates = findDuplicateFixedAdvisoryLocks();
  assert.deepEqual(duplicates, [], `colliding advisory lock ids: ${JSON.stringify(duplicates)}`);
  assert.equal(FIXED_INTEGER_ADVISORY_LOCKS.length, new Set(FIXED_INTEGER_ADVISORY_LOCKS.map((e) => e.id)).size);
});

test('OTX and MalwareBazaar recovery use distinct advisory lock ids', () => {
  assert.notEqual(OTX_ADVISORY_LOCK, MALWAREBAZAAR_RECOVERY_ADVISORY_LOCK);
  assert.equal(MALWAREBAZAAR_RECOVERY_LOCK_ID, MALWAREBAZAAR_RECOVERY_ADVISORY_LOCK);
  assert.equal(OTX_ADVISORY_LOCK, 942007);
  assert.equal(MALWAREBAZAAR_RECOVERY_ADVISORY_LOCK, 942008);
});

test('CERT.PL advisory lock uses next free id in the 94200x series', () => {
  assert.equal(CERTPL_ADVISORY_LOCK, 942009);
  assert.notEqual(CERTPL_ADVISORY_LOCK, OTX_ADVISORY_LOCK);
  assert.notEqual(CERTPL_ADVISORY_LOCK, MALWAREBAZAAR_RECOVERY_ADVISORY_LOCK);
});
