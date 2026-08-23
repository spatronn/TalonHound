import test from 'node:test';
import assert from 'node:assert/strict';
import { readCanonicalVersion } from './productVersion.js';

test('readCanonicalVersion reads repository VERSION file', () => {
  assert.equal(readCanonicalVersion(), '0.1.0-beta.1');
});
