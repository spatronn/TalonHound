import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

/**
 * Mirrors merge.js hash-move / IOC-link-move decision: own row must move;
 * other row on canonical deletes; other row on third artifact skips.
 */
function decideIdentityRowMove(row, existingRow, canonicalId) {
  if (!existingRow) return 'move';
  if (existingRow.id === row.id) return 'move';
  if (existingRow.artifact_id === canonicalId) return 'delete_dup';
  return 'skip_third';
}

describe('fileArtifacts/merge hash move decision', () => {
  it('moves the duplicate artifact own hash row (does not treat self as third-party)', () => {
    const h = { id: 'hash-dup', hash_type: 'md5' };
    const existing = { id: 'hash-dup', artifact_id: 'artifact-dup' };
    assert.equal(decideIdentityRowMove(h, existing, 'artifact-canon'), 'move');
  });

  it('deletes when same identity already on canonical', () => {
    const h = { id: 'hash-dup', hash_type: 'md5' };
    const existing = { id: 'hash-canon', artifact_id: 'artifact-canon' };
    assert.equal(decideIdentityRowMove(h, existing, 'artifact-canon'), 'delete_dup');
  });

  it('skips when bound to a third artifact', () => {
    const h = { id: 'hash-dup', hash_type: 'md5' };
    const existing = { id: 'hash-other', artifact_id: 'artifact-other' };
    assert.equal(decideIdentityRowMove(h, existing, 'artifact-canon'), 'skip_third');
  });
});

describe('fileArtifacts/merge IOC link move decision', () => {
  it('moves the duplicate artifact own IOC link (does not treat self as collision)', () => {
    const link = { id: 10, ioc_item_id: 3472708 };
    const existing = { id: 10, artifact_id: 'artifact-dup' };
    assert.equal(decideIdentityRowMove(link, existing, 'artifact-canon'), 'move');
  });

  it('deletes when the same IOC is already linked on canonical', () => {
    const link = { id: 10, ioc_item_id: 3472708 };
    const existing = { id: 99, artifact_id: 'artifact-canon' };
    assert.equal(decideIdentityRowMove(link, existing, 'artifact-canon'), 'delete_dup');
  });

  it('skips when the same IOC is bound to a third artifact', () => {
    const link = { id: 10, ioc_item_id: 3472708 };
    const existing = { id: 99, artifact_id: 'artifact-other' };
    assert.equal(decideIdentityRowMove(link, existing, 'artifact-canon'), 'skip_third');
  });
});
