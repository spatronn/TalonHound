import crypto from 'node:crypto';

export const PUBLISHED_FEED_CHUNK_ALGO_VERSION = 1;
export const PUBLISHED_FEED_CHUNK_TARGET_ROWS = 5000;
export const PUBLISHED_FEED_CHUNK_MIN = 64;
export const PUBLISHED_FEED_CHUNK_MAX = 512;
export const PUBLISHED_FEED_CHUNK_SERIALIZER_VERSION = {
  txt: 1,
  json: 1,
  stix: 1
};

function clampPowerOfTwo(value, min, max) {
  let n = 1;
  while (n < value) n *= 2;
  const lower = n > 1 ? n / 2 : 1;
  const nearest = value - lower < n - value ? lower : n;
  return Math.max(min, Math.min(max, nearest));
}

export function choosePublishedFeedChunkCount(itemCount, {
  targetRows = PUBLISHED_FEED_CHUNK_TARGET_ROWS,
  min = PUBLISHED_FEED_CHUNK_MIN,
  max = PUBLISHED_FEED_CHUNK_MAX
} = {}) {
  const rows = Math.max(0, Number(itemCount) || 0);
  const target = Math.max(1, Number(targetRows) || PUBLISHED_FEED_CHUNK_TARGET_ROWS);
  return clampPowerOfTwo(Math.max(1, Math.ceil(rows / target)), min, max);
}

export function normalizePartitionIdentity(value) {
  const identity = String(value || '').trim();
  if (!identity || !/^[ao]:/i.test(identity)) {
    throw new Error('Invalid Published Feed partition identity');
  }
  return identity;
}

/**
 * Version 1 is SHA-256 over UTF-8 partition_identity; the first unsigned 32 bits
 * select a power-of-two bucket. This is stable across Node/PostgreSQL/OS versions.
 */
export function publishedFeedChunkKey(partitionIdentity, chunkCount, {
  version = PUBLISHED_FEED_CHUNK_ALGO_VERSION
} = {}) {
  if (Number(version) !== PUBLISHED_FEED_CHUNK_ALGO_VERSION) {
    throw new Error(`Unsupported Published Feed chunk algorithm version: ${version}`);
  }
  const count = Number(chunkCount);
  if (!Number.isInteger(count) || count < 1 || (count & (count - 1)) !== 0) {
    throw new Error('Published Feed chunk_count must be a power of two');
  }
  const digest = crypto
    .createHash('sha256')
    .update(normalizePartitionIdentity(partitionIdentity), 'utf8')
    .digest();
  return digest.readUInt32BE(0) & (count - 1);
}

export function observablePartitionIdentity(observableType, observable) {
  const type = String(observableType || '').trim().toLowerCase();
  const value = String(observable || '').trim().toLowerCase();
  if (!type || !value) throw new Error('Observable partition identity requires type and value');
  return `o:${type}:${value}`;
}

export function artifactPartitionIdentity(artifactId) {
  const id = String(artifactId || '').trim().toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id)) {
    throw new Error('Invalid File Artifact id for Published Feed partition identity');
  }
  return `a:${id}`;
}

export function partitionIdentityForProjectionRow(row) {
  if (row?.partition_identity) return normalizePartitionIdentity(row.partition_identity);
  if (row?.resolved_artifact_id) return artifactPartitionIdentity(row.resolved_artifact_id);
  return observablePartitionIdentity(row?.observable_type, row?.txt_value ?? row?.observable);
}

export function strongRepresentationEtag({
  format,
  serializerVersion,
  header = '',
  footer = '',
  chunks = [],
  separator = ''
}) {
  const hash = crypto.createHash('sha256');
  hash.update('talonhound-published-feed-representation-v1\0', 'utf8');
  hash.update(String(format || ''), 'utf8');
  hash.update('\0', 'utf8');
  hash.update(String(serializerVersion ?? ''), 'utf8');
  hash.update('\0', 'utf8');
  hash.update(Buffer.from(String(header), 'utf8'));
  for (let i = 0; i < chunks.length; i += 1) {
    if (i > 0) hash.update(Buffer.from(String(separator), 'utf8'));
    hash.update(String(chunks[i].content_hash || ''), 'utf8');
    hash.update(':', 'utf8');
    hash.update(String(chunks[i].byte_length ?? ''), 'utf8');
    hash.update(';', 'utf8');
  }
  hash.update(Buffer.from(String(footer), 'utf8'));
  return `"${hash.digest('hex')}"`;
}

export function logicalRepresentationLength({
  header = '',
  footer = '',
  chunks = [],
  separator = ''
}) {
  const nonEmpty = chunks.filter((chunk) => Number(chunk.byte_length || 0) > 0);
  const chunkBytes = nonEmpty.reduce((sum, chunk) => sum + Number(chunk.byte_length || 0), 0);
  const separators = Math.max(0, nonEmpty.length - 1) * Buffer.byteLength(String(separator), 'utf8');
  return Buffer.byteLength(String(header), 'utf8')
    + chunkBytes
    + separators
    + Buffer.byteLength(String(footer), 'utf8');
}
