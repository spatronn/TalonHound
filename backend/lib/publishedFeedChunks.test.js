import test from 'node:test';
import assert from 'node:assert/strict';
import {
  artifactPartitionIdentity,
  choosePublishedFeedChunkCount,
  logicalRepresentationLength,
  observablePartitionIdentity,
  partitionIdentityForProjectionRow,
  publishedFeedChunkKey,
  strongRepresentationEtag
} from './publishedFeedChunks.js';

test('chunk count policy targets roughly 5000 rows with bounded powers of two', () => {
  assert.equal(choosePublishedFeedChunkCount(0), 64);
  assert.equal(choosePublishedFeedChunkCount(100_000), 64);
  assert.equal(choosePublishedFeedChunkCount(1_216_000), 256);
  assert.equal(choosePublishedFeedChunkCount(1_100_000), 256);
  assert.equal(choosePublishedFeedChunkCount(2_000_000), 512);
});

test('versioned SHA-256 chunk key is deterministic and bounded', () => {
  const identity = observablePartitionIdentity('domain', 'Example.COM');
  const first = publishedFeedChunkKey(identity, 256);
  const second = publishedFeedChunkKey(identity, 256);
  assert.equal(first, second);
  assert.ok(first >= 0 && first < 256);
  assert.equal(identity, 'o:domain:example.com');
  assert.throws(() => publishedFeedChunkKey(identity, 250), /power of two/);
  assert.throws(() => publishedFeedChunkKey(identity, 256, { version: 2 }), /Unsupported/);
});

test('file output changes do not change stable artifact partition identity', () => {
  const artifactId = '123e4567-e89b-12d3-a456-426614174000';
  const partition = artifactPartitionIdentity(artifactId);
  const md5 = partitionIdentityForProjectionRow({
    partition_identity: partition,
    observable_type: 'md5',
    observable: 'a'.repeat(32)
  });
  const sha256 = partitionIdentityForProjectionRow({
    partition_identity: partition,
    observable_type: 'sha256',
    observable: 'b'.repeat(64)
  });
  assert.equal(md5, sha256);
  assert.equal(publishedFeedChunkKey(md5, 256), publishedFeedChunkKey(sha256, 256));
});

test('logical length accounts for envelopes and only inter-chunk separators', () => {
  const chunks = [
    { content_hash: 'a'.repeat(64), byte_length: 3 },
    { content_hash: 'b'.repeat(64), byte_length: 5 }
  ];
  assert.equal(logicalRepresentationLength({
    header: '{"items":[',
    footer: ']}\n',
    separator: ',',
    chunks
  }), Buffer.byteLength('{"items":[') + 3 + 1 + 5 + 3);
});

test('strong representation ETag changes for every byte-affecting component', () => {
  const base = {
    format: 'json',
    serializerVersion: 1,
    header: '{"items":[',
    footer: ']}\n',
    separator: ',',
    chunks: [{ content_hash: 'a'.repeat(64), byte_length: 3 }]
  };
  const etag = strongRepresentationEtag(base);
  assert.match(etag, /^"[a-f0-9]{64}"$/);
  assert.notEqual(etag, strongRepresentationEtag({ ...base, header: '{"items":[ ' }));
  assert.notEqual(etag, strongRepresentationEtag({
    ...base,
    chunks: [{ content_hash: 'b'.repeat(64), byte_length: 3 }]
  }));
});
