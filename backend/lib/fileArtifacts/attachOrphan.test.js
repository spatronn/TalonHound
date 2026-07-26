import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { exactHashAdvisoryLockKeys } from './attach.js';
import { EMPTY_ORPHAN_ARTIFACTS_SQL } from './validate.js';

describe('orphan-safe attach helpers', () => {
  it('advisory lock keys are deterministic for hash identity', () => {
    const a = exactHashAdvisoryLockKeys('MD5', 'AABB');
    const b = exactHashAdvisoryLockKeys('md5', 'aabb');
    assert.deepEqual(a, b);
    assert.equal(a[0], 'fa_hash:md5');
    assert.equal(a[1], 'aabb');
  });

  it('empty orphan SQL requires no hashes/links/observations', () => {
    assert.match(EMPTY_ORPHAN_ARTIFACTS_SQL, /file_artifact_hashes/);
    assert.match(EMPTY_ORPHAN_ARTIFACTS_SQL, /file_artifact_ioc_links/);
    assert.match(EMPTY_ORPHAN_ARTIFACTS_SQL, /file_artifact_source_observations/);
    assert.match(EMPTY_ORPHAN_ARTIFACTS_SQL, /fah\.id IS NULL/);
    assert.match(EMPTY_ORPHAN_ARTIFACTS_SQL, /fa\.status = 'active'/);
  });
});
