import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Mirrors merge.js hash-move decision: own row must move; other row on canonical deletes;
 * other row on third artifact skips.
 */
function decideHashMove(h, existingRow, canonicalId) {
  if (!existingRow) return 'move';
  if (existingRow.id === h.id) return 'move';
  if (existingRow.artifact_id === canonicalId) return 'delete_dup';
  return 'skip_third';
}

describe('fileArtifacts/merge hash move decision', () => {
  it('moves the duplicate artifact own hash row (does not treat self as third-party)', () => {
    const h = { id: 'hash-dup', hash_type: 'md5' };
    const existing = { id: 'hash-dup', artifact_id: 'artifact-dup' };
    assert.equal(decideHashMove(h, existing, 'artifact-canon'), 'move');
  });

  it('deletes when same identity already on canonical', () => {
    const h = { id: 'hash-dup', hash_type: 'md5' };
    const existing = { id: 'hash-canon', artifact_id: 'artifact-canon' };
    assert.equal(decideHashMove(h, existing, 'artifact-canon'), 'delete_dup');
  });

  it('skips when bound to a third artifact', () => {
    const h = { id: 'hash-dup', hash_type: 'md5' };
    const existing = { id: 'hash-other', artifact_id: 'artifact-other' };
    assert.equal(decideHashMove(h, existing, 'artifact-canon'), 'skip_third');
  });
});
