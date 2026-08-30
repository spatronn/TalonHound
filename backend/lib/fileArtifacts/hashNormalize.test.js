import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeExactHash,
  normalizeHashValue,
  inferExactHashType,
  selectPrimaryHash,
  shouldPromotePrimary,
  primaryPriorityRank,
  extractExactHashesFromNote,
  extractExactHashesFromVtRaw,
  extractNonIdentityAttrsFromNote,
  isWeakMergeSignal,
  isExactFileHashIocType
} from './hashNormalize.js';
import { mergeArtifactMetadata, selectCanonicalArtifact } from './metadataPolicy.js';
import { detectMultiArtifactConflict } from './conflicts.js';
import { formatObservationForApi, OBSERVATION_TYPE } from './observations.js';
import { isFileArtifactsDualWriteEnabled, isFileArtifactsReadEnabled } from './flags.js';
import { dedupeListItemsByArtifact } from './read.js';

const MD5 = '9aed790a18f214b04619837cd71546d3';
const SHA1 = '0f9a253afc55a8ebbd29a70c43d0e3cd668920f4';
const SHA256 = '8ec6066000f5585d6fefbc1d5a30fa094ac9893456dbf4085fec81e6b71cef3b';

describe('fileArtifacts/hashNormalize', () => {
  it('normalizes hash values to lowercase', () => {
    assert.equal(normalizeHashValue(' AABB '), 'aabb');
  });

  it('validates exact hash length and format', () => {
    assert.deepEqual(normalizeExactHash('MD5', MD5.toUpperCase()), {
      hash_type: 'md5',
      normalized_hash_value: MD5
    });
    assert.equal(normalizeExactHash('md5', 'too-short'), null);
    assert.equal(normalizeExactHash('sha512', 'a'.repeat(128)), null);
    assert.equal(normalizeExactHash('ssdeep', '12288:abc:def'), null);
  });

  it('infers type from hex length', () => {
    assert.equal(inferExactHashType(MD5), 'md5');
    assert.equal(inferExactHashType(SHA1), 'sha1');
    assert.equal(inferExactHashType(SHA256), 'sha256');
    assert.equal(inferExactHashType('abc'), null);
  });

  it('selects primary with SHA256 > SHA1 > MD5', () => {
    const primary = selectPrimaryHash([
      { hash_type: 'md5', id: '1' },
      { hash_type: 'sha256', id: '2' },
      { hash_type: 'sha1', id: '3' }
    ]);
    assert.equal(primary.id, '2');
    assert.equal(primaryPriorityRank('sha256'), 0);
    assert.equal(shouldPromotePrimary('md5', 'sha256'), true);
    assert.equal(shouldPromotePrimary('sha256', 'md5'), false);
    assert.equal(shouldPromotePrimary(null, 'md5'), true);
  });

  it('extracts exact hashes from MB-style note without treating imphash as identity', () => {
    const hashes = extractExactHashesFromNote({
      observableType: 'sha256',
      observable: SHA256,
      note: `Auto-imported | md5=${MD5} | sha1=${SHA1} | imphash=112233445566778899aabbccddeeff00 | ssdeep=12288:a:b | tlsh=T1abc`
    });
    assert.equal(hashes.length, 3);
    assert.ok(hashes.some((h) => h.hash_type === 'md5' && h.normalized_hash_value === MD5));
    assert.ok(hashes.some((h) => h.hash_type === 'sha1'));
    assert.ok(hashes.some((h) => h.hash_type === 'sha256'));

    const nonId = extractNonIdentityAttrsFromNote(
      `imphash=112233445566778899aabbccddeeff00 | ssdeep=12288:a:b | tlsh=T1abc`
    );
    assert.equal(nonId.length, 3);
    assert.ok(isWeakMergeSignal('imphash'));
    assert.ok(isWeakMergeSignal('file_name'));
    assert.ok(!isWeakMergeSignal('sha256'));
  });

  it('extracts exact hashes from VT raw_response attributes', () => {
    const hashes = extractExactHashesFromVtRaw({
      data: { attributes: { md5: MD5, sha1: SHA1, sha256: SHA256, names: ['x.exe'] } }
    });
    assert.equal(hashes.length, 3);
  });

  it('recognizes exact file hash IOC types only', () => {
    assert.equal(isExactFileHashIocType('md5'), true);
    assert.equal(isExactFileHashIocType('imphash'), false);
    assert.equal(isExactFileHashIocType('domain'), false);
  });
});

describe('fileArtifacts/metadataPolicy', () => {
  it('merges timestamps with min/max and keeps size conflict metadata', () => {
    const merged = mergeArtifactMetadata(
      {
        first_seen_at: '2024-01-02T00:00:00Z',
        last_seen_at: '2024-01-03T00:00:00Z',
        file_name: 'a.exe',
        size_bytes: 100,
        metadata: {}
      },
      {
        first_seen_at: '2024-01-01T00:00:00Z',
        last_seen_at: '2024-01-04T00:00:00Z',
        file_name: 'b.exe',
        size_bytes: 200,
        metadata: {}
      }
    );
    assert.equal(merged.first_seen_at, '2024-01-01T00:00:00Z');
    assert.equal(merged.last_seen_at, '2024-01-04T00:00:00Z');
    assert.equal(merged.file_name, 'a.exe');
    assert.equal(merged.size_bytes, 100);
    assert.deepEqual(merged.metadata.size_conflict, { canonical: 100, duplicate: 200 });
  });

  it('selects canonical artifact deterministically', () => {
    const chosen = selectCanonicalArtifact([
      { id: 'b', created_at: '2024-01-01T00:00:00Z', has_sha256: false, link_count: 5 },
      { id: 'a', created_at: '2024-01-02T00:00:00Z', has_sha256: true, link_count: 1 },
      { id: 'c', created_at: '2023-01-01T00:00:00Z', has_sha256: true, link_count: 0 }
    ]);
    // Both a and c have sha256; older created_at wins → c
    assert.equal(chosen.id, 'c');
  });
});

describe('fileArtifacts/conflicts', () => {
  it('detects multi-artifact conflict', () => {
    assert.equal(detectMultiArtifactConflict([{ artifact_id: 'a' }, { artifact_id: 'a' }]).conflict, false);
    assert.equal(detectMultiArtifactConflict([{ artifact_id: 'a' }, { artifact_id: 'b' }]).conflict, true);
  });
});

describe('fileArtifacts/observations', () => {
  it('formats observed-as without inventing source hashes', () => {
    const formatted = formatObservationForApi({
      id: 1,
      artifact_id: 'art',
      source_name: 'Custom Feed',
      observed_hash_type: 'md5',
      observed_hash_value: MD5,
      observation_type: OBSERVATION_TYPE.DIRECT,
      relation_method: 'same_source_record'
    });
    assert.equal(formatted.observed_as, 'md5');
    assert.equal(formatted.observed_hash_value, MD5);
    assert.equal(formatted.evidence_label, 'Direct source observation');
    assert.equal(formatted.source_name, 'Custom Feed');
  });
});

describe('fileArtifacts/flags', () => {
  let prevDual;
  let prevRead;
  before(() => {
    prevDual = process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
    prevRead = process.env.FILE_ARTIFACTS_READ_ENABLED;
  });
  after(() => {
    if (prevDual == null) delete process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
    else process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = prevDual;
    if (prevRead == null) delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    else process.env.FILE_ARTIFACTS_READ_ENABLED = prevRead;
  });

  it('defaults flags to false', () => {
    delete process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED;
    delete process.env.FILE_ARTIFACTS_READ_ENABLED;
    assert.equal(isFileArtifactsDualWriteEnabled(), false);
    assert.equal(isFileArtifactsReadEnabled(), false);
  });

  it('parses true values', () => {
    process.env.FILE_ARTIFACTS_DUAL_WRITE_ENABLED = '1';
    process.env.FILE_ARTIFACTS_READ_ENABLED = 'true';
    assert.equal(isFileArtifactsDualWriteEnabled(), true);
    assert.equal(isFileArtifactsReadEnabled(), true);
  });
});

describe('fileArtifacts/list dedupe', () => {
  it('collapses md5 and sha256 rows that share an artifact', () => {
    const map = new Map([
      ['pub-md5', 'art-1'],
      ['pub-sha256', 'art-1']
    ]);
    const rows = dedupeListItemsByArtifact(
      [
        { public_id: 'pub-md5', observable_type: 'md5', observable: MD5, sources: ['Custom'] },
        { public_id: 'pub-sha256', observable_type: 'sha256', observable: SHA256, sources: ['MalwareBazaar'] }
      ],
      map
    );
    assert.equal(rows.length, 1);
    assert.equal(rows[0].observable_type, 'sha256');
    assert.ok(rows[0].sources.includes('Custom'));
    assert.ok(rows[0].sources.includes('MalwareBazaar'));
  });
});
