import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  extractExactHashesFromNote,
  isWeakMergeSignal,
  selectPrimaryHash
} from './hashNormalize.js';
import { selectCanonicalArtifact, mergeArtifactMetadata } from './metadataPolicy.js';
import { detectMultiArtifactConflict } from './conflicts.js';

const MD5 = '9aed790a18f214b04619837cd71546d3';
const SHA1 = '0f9a253afc55a8ebbd29a70c43d0e3cd668920f4';
const SHA256 = '8ec6066000f5585d6fefbc1d5a30fa094ac9893456dbf4085fec81e6b71cef3b';

describe('fileArtifacts trust rules', () => {
  it('same-record exact hash extraction is trusted evidence shape', () => {
    const hashes = extractExactHashesFromNote({
      observableType: 'sha256',
      observable: SHA256,
      note: `md5=${MD5} | sha1=${SHA1}`
    });
    assert.equal(hashes.length, 3);
  });

  it('non-identity fields are weak signals only', () => {
    assert.equal(isWeakMergeSignal('imphash'), true);
    assert.equal(isWeakMergeSignal('tlsh'), true);
    assert.equal(isWeakMergeSignal('ssdeep'), true);
    assert.equal(isWeakMergeSignal('file_name'), true);
    assert.equal(isWeakMergeSignal('md5'), false);
  });

  it('idempotent primary selection is stable', () => {
    const a = selectPrimaryHash([
      { hash_type: 'md5', id: '1' },
      { hash_type: 'sha256', id: '2' }
    ]);
    const b = selectPrimaryHash([
      { hash_type: 'sha256', id: '2' },
      { hash_type: 'md5', id: '1' }
    ]);
    assert.equal(a.id, b.id);
    assert.equal(a.hash_type, 'sha256');
  });

  it('canonical selection prefers sha256 then older created_at', () => {
    const c = selectCanonicalArtifact([
      { id: 'new-sha', created_at: '2025-01-01T00:00:00Z', has_sha256: true, link_count: 1 },
      { id: 'old-md5', created_at: '2020-01-01T00:00:00Z', has_sha256: false, link_count: 9 }
    ]);
    assert.equal(c.id, 'new-sha');
  });

  it('multi-artifact conflict detection', () => {
    assert.equal(
      detectMultiArtifactConflict([{ artifact_id: 'a' }, { artifact_id: 'b' }]).conflict,
      true
    );
  });

  it('metadata merge keeps first_seen min and last_seen max', () => {
    const m = mergeArtifactMetadata(
      { first_seen_at: '2024-06-01T00:00:00Z', last_seen_at: '2024-06-02T00:00:00Z' },
      { first_seen_at: '2024-01-01T00:00:00Z', last_seen_at: '2024-12-01T00:00:00Z' }
    );
    assert.equal(m.first_seen_at, '2024-01-01T00:00:00Z');
    assert.equal(m.last_seen_at, '2024-12-01T00:00:00Z');
  });
});
