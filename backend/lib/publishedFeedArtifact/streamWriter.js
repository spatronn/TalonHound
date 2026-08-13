// Bounded-memory streaming writers for Published Feed artifacts.
//
// Each writer consumes items one at a time and writes serialized bytes to a Node Writable
// (a file .part stream), applying backpressure. Nothing accumulates the full artifact in
// memory. The LOGICAL content hash is computed incrementally and is byte-for-byte identical
// to the in-memory writers (feedFormatter.buildPlainTextFeed / publishedFeedJson.JsonFeedWriter)
// so ETag / 304 semantics are unchanged when a feed switches to the streamed path.

import crypto from 'node:crypto';
import { PUBLISHED_FEED_SCHEMA_VERSION } from '../publishedFeedJson.js';
import { STIX_SPEC_VERSION, stixBundleIdForFeed } from '../publishedFeedStix.js';

/** Promise-based sink write that honors backpressure. */
export function makeSinkWriter(stream) {
  return (chunk) => new Promise((resolve, reject) => {
    stream.write(chunk, (err) => (err ? reject(err) : resolve()));
  });
}

/**
 * Streaming TXT writer. Output equals `lines.join('\n') + '\n'` (empty feed → '') exactly,
 * so content_hash matches buildPlainTextFeed for the same ordered, deduped value list.
 */
export class StreamingTxtWriter {
  constructor(stream) {
    this._write = makeSinkWriter(stream);
    this._hash = crypto.createHash('sha256');
    this._count = 0;
  }

  async addValue(value) {
    const line = `${value}\n`;
    this._hash.update(line, 'utf8');
    this._count += 1;
    await this._write(line);
  }

  get itemCount() { return this._count; }

  finish() {
    return { content_hash: this._hash.digest('hex'), item_count: this._count };
  }
}

/**
 * Streaming JSON body writer: emits the comma-separated items ONLY (no envelope) to a body
 * sink, and computes the logical content hash identically to JsonFeedWriter. The generator
 * assembles the final artifact as: header(item_count) + body + footer, so `feed.item_count`
 * is exact without buffering the items. `generated_at` is intentionally excluded from the
 * hash (stable ETag across regenerations).
 */
export class StreamingJsonBodyWriter {
  constructor(stream, feedMeta = {}) {
    this._write = makeSinkWriter(stream);
    this._count = 0;
    this._first = true;
    this._name = feedMeta.name != null ? String(feedMeta.name) : null;
    this._flags = {
      include_source_metadata: Boolean(feedMeta.includeSourceMetadata),
      include_classification: Boolean(feedMeta.includeClassification),
      include_enrichment: Boolean(feedMeta.includeEnrichment)
    };
    this._hash = crypto.createHash('sha256');
    this._hash.update(JSON.stringify({
      schema_version: PUBLISHED_FEED_SCHEMA_VERSION,
      name: this._name,
      flags: this._flags
    }));
  }

  async addItem(item) {
    const chunk = JSON.stringify(item);
    this._hash.update('\n');
    this._hash.update(chunk);
    this._count += 1;
    await this._write(this._first ? chunk : `,${chunk}`);
    this._first = false;
  }

  get itemCount() { return this._count; }

  /** The header bytes for the final artifact, with the now-known item_count + generated_at. */
  buildHeader(itemCount, generatedAt) {
    return `{"schema_version":${JSON.stringify(PUBLISHED_FEED_SCHEMA_VERSION)},`
      + `"feed":${JSON.stringify({
        name: this._name,
        generated_at: generatedAt,
        item_count: itemCount,
        include_source_metadata: this._flags.include_source_metadata,
        include_classification: this._flags.include_classification,
        include_enrichment: this._flags.include_enrichment
      })},"items":[`;
  }

  buildFooter() { return ']}\n'; }

  finish() {
    return { content_hash: this._hash.digest('hex'), item_count: this._count };
  }
}

/**
 * Streaming STIX 2.1 body writer: emits comma-separated Indicator objects to a body
 * sink. Header/footer (bundle envelope) are assembled after the body, matching
 * StixBundleWriter hashing (spec_version + bundle_id + each object).
 */
export class StreamingStixBodyWriter {
  constructor(stream, { slug } = {}) {
    this._write = makeSinkWriter(stream);
    this._count = 0;
    this._first = true;
    this._slug = slug != null ? String(slug) : '';
    this._bundleId = stixBundleIdForFeed(this._slug);
    this._hash = crypto.createHash('sha256');
    this._hash.update(JSON.stringify({
      spec_version: STIX_SPEC_VERSION,
      bundle_id: this._bundleId
    }));
  }

  get bundleId() { return this._bundleId; }

  async addIndicator(indicator) {
    if (!indicator) return false;
    const chunk = JSON.stringify(indicator);
    this._hash.update('\n');
    this._hash.update(chunk);
    this._count += 1;
    await this._write(this._first ? chunk : `,${chunk}`);
    this._first = false;
    return true;
  }

  get itemCount() { return this._count; }

  buildHeader() {
    return `{"type":"bundle","id":${JSON.stringify(this._bundleId)},"spec_version":${JSON.stringify(STIX_SPEC_VERSION)},"objects":[`;
  }

  buildFooter() { return ']}\n'; }

  finish() {
    return { content_hash: this._hash.digest('hex'), item_count: this._count };
  }
}
