import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { resolveCanonicalDetailRedirect } from './fileArtifactDetailRedirect.js';

const MD5_ID = 'f47e6f29-0785-4a3d-9600-51e9111e8891';
const SHA_ID = 'f915bc21-68dd-411f-92da-31cbae1c49b1';

describe('resolveCanonicalDetailRedirect', () => {
  it('redirects MD5 alias to canonical SHA256 public id', () => {
    const r = resolveCanonicalDetailRedirect({
      requestedPublicId: MD5_ID,
      summary: { observable_type: 'md5' },
      fileArtifact: {
        is_legacy_alias: true,
        canonical_ioc_public_id: SHA_ID,
        primary_hash: { hash_type: 'sha256' }
      }
    });
    assert.equal(r?.toPublicId, SHA_ID);
    assert.match(r.message, /MD5/i);
    assert.match(r.message, /SHA256/i);
  });

  it('redirects SHA1 alias to canonical SHA256 public id', () => {
    const r = resolveCanonicalDetailRedirect({
      requestedPublicId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      summary: { observable_type: 'sha1' },
      fileArtifact: {
        is_legacy_alias: true,
        canonical_ioc_public_id: SHA_ID,
        primary_hash: { hash_type: 'sha256' }
      }
    });
    assert.equal(r?.toPublicId, SHA_ID);
  });

  it('does not redirect when already on canonical SHA256', () => {
    const r = resolveCanonicalDetailRedirect({
      requestedPublicId: SHA_ID,
      summary: { observable_type: 'sha256' },
      fileArtifact: {
        is_legacy_alias: false,
        canonical_ioc_public_id: SHA_ID,
        primary_hash: { hash_type: 'sha256' }
      }
    });
    assert.equal(r, null);
  });

  it('does not redirect when artifact block missing (unlinked MD5)', () => {
    const r = resolveCanonicalDetailRedirect({
      requestedPublicId: MD5_ID,
      summary: { observable_type: 'md5' },
      fileArtifact: null
    });
    assert.equal(r, null);
  });

  it('does not redirect when canonical id equals requested', () => {
    const r = resolveCanonicalDetailRedirect({
      requestedPublicId: SHA_ID,
      summary: { observable_type: 'md5' },
      fileArtifact: {
        is_legacy_alias: true,
        canonical_ioc_public_id: SHA_ID,
        primary_hash: { hash_type: 'sha256' }
      }
    });
    // is_legacy_alias with same ids should still no-op via equality guard
    assert.equal(r, null);
  });
});
