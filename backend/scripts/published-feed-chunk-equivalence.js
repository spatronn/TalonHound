#!/usr/bin/env node
/**
 * Compare legacy monolithic artifacts vs composed chunk generation for one feed.
 * Streams JSON/STIX object-by-object so million-row feeds do not need a 4GB heap.
 * Read-only except for opening files. Does not mutate IOC rows.
 */
import fs from 'node:fs';
import { createReadStream } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Writable } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';
import { pipeline } from 'node:stream/promises';
import pg from 'pg';
import { getPublishedFeedArtifactConfig, resolveStoredArtifactPath } from '../lib/publishedFeedArtifact/store.js';
import {
  getActiveChunkGeneration,
  getChunkGenerationFiles,
  streamChunkGeneration
} from '../lib/publishedFeedChunkGeneration.js';

const feedId = Number(process.argv[process.argv.indexOf('--feed-id') + 1]);
const windowName = 'all';
const iocTypeKey = process.argv.includes('--ioc-type-key')
  ? process.argv[process.argv.indexOf('--ioc-type-key') + 1]
  : 'domain';

const pool = new pg.Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

function parseTxtSet(buf) {
  const text = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf);
  const lines = text.endsWith('\n') ? text.slice(0, -1).split('\n') : text.split('\n').filter(Boolean);
  const set = new Set(lines);
  return { count: lines.length, unique: set.size, dupes: lines.length - set.size, set };
}

function setDiff(a, b, limit = 5) {
  const missing = [];
  const extra = [];
  for (const v of a) {
    if (!b.has(v)) {
      missing.push(v);
      if (missing.length >= limit) break;
    }
  }
  for (const v of b) {
    if (!a.has(v)) {
      extra.push(v);
      if (extra.length >= limit) break;
    }
  }
  let missingCount = 0;
  let extraCount = 0;
  for (const v of a) if (!b.has(v)) missingCount += 1;
  for (const v of b) if (!a.has(v)) extraCount += 1;
  return {
    missing_count: missingCount,
    extra_count: extraCount,
    missing_sample: missing,
    extra_sample: extra
  };
}

function stableStringify(value) {
  if (value == null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

class ByteCountingSink extends Writable {
  constructor() {
    super();
    this.received = 0;
    this.parts = [];
    this.keepBuffer = false;
  }

  _write(chunk, _enc, cb) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    this.received += buf.length;
    if (this.keepBuffer) this.parts.push(buf);
    cb();
  }

  buffer() {
    return Buffer.concat(this.parts);
  }
}

class ArrayObjectParser extends Writable {
  constructor(arrayKey, onObject) {
    super();
    this.arrayKey = `"${arrayKey}":`;
    this.onObject = onObject;
    this.decoder = new StringDecoder('utf8');
    this.header = '';
    this.phase = 'header';
    this.pending = '';
    this.depth = 0;
    this.inString = false;
    this.escape = false;
    this.current = '';
    this.count = 0;
    this.parseErrors = 0;
  }

  _write(chunk, _enc, cb) {
    try {
      this._consume(this.decoder.write(chunk));
      cb();
    } catch (err) {
      cb(err);
    }
  }

  _final(cb) {
    try {
      this._consume(this.decoder.end());
      if (this.phase === 'header') this.header += this.pending;
      cb();
    } catch (err) {
      cb(err);
    }
  }

  _consume(text) {
    const data = this.pending + text;
    this.pending = '';
    let i = 0;
    if (this.phase === 'header') {
      const idx = data.indexOf(this.arrayKey);
      if (idx < 0) {
        if (data.length > 1_000_000) throw new Error(`Did not find ${this.arrayKey} in header`);
        this.pending = data;
        return;
      }
      this.header = data.slice(0, idx + this.arrayKey.length);
      i = idx + this.arrayKey.length;
      while (i < data.length && (data[i] === ' ' || data[i] === '\n' || data[i] === '\r' || data[i] === '\t')) i += 1;
      this.phase = 'items';
    }
    for (; i < data.length; i += 1) {
      const ch = data[i];
      if (this.depth === 0) {
        if (ch === ']') {
          this.phase = 'done';
          return;
        }
        if (ch === ',') continue;
        if (ch === ' ' || ch === '\n' || ch === '\r' || ch === '\t') continue;
        if (ch === '{') {
          this.depth = 1;
          this.current = '{';
          this.inString = false;
          this.escape = false;
          continue;
        }
        continue;
      }
      this.current += ch;
      if (this.inString) {
        if (this.escape) this.escape = false;
        else if (ch === '\\') this.escape = true;
        else if (ch === '"') this.inString = false;
        continue;
      }
      if (ch === '"') this.inString = true;
      else if (ch === '{') this.depth += 1;
      else if (ch === '}') {
        this.depth -= 1;
        if (this.depth === 0) {
          try {
            this.onObject(JSON.parse(this.current));
            this.count += 1;
          } catch {
            this.parseErrors += 1;
          }
          this.current = '';
        }
      }
    }
  }
}

async function collectStream(generation, chunks, { keepBuffer = false } = {}) {
  const sink = new ByteCountingSink();
  sink.keepBuffer = keepBuffer;
  const req = { aborted: false, once() {}, off() {} };
  await streamChunkGeneration(sink, req, generation, chunks);
  return { buf: keepBuffer ? sink.buffer() : null, received: sink.received };
}

async function streamComposed(generation, chunks, parser) {
  const sink = new ByteCountingSink();
  const req = { aborted: false, once() {}, off() {} };
  const originalWrite = sink.write.bind(sink);
  sink.write = (chunk, enc, cb) => {
    parser.write(chunk);
    return originalWrite(chunk, enc, cb);
  };
  sink.end = (chunk) => {
    if (chunk) parser.write(chunk);
    parser.end();
    ByteCountingSink.prototype.end.call(sink);
  };
  await streamChunkGeneration(sink, req, generation, chunks);
  return sink.received;
}

async function parseFileArray(abs, arrayKey, onObject) {
  const parser = new ArrayObjectParser(arrayKey, onObject);
  await pipeline(createReadStream(abs, { encoding: 'utf8' }), parser);
  return parser;
}

function jsonMetaFromHeader(header) {
  const schema = header.match(/"schema_version"\s*:\s*(\d+)/);
  const itemCount = header.match(/"item_count"\s*:\s*(\d+)/);
  const generated = header.match(/"generated_at"\s*:\s*"([^"]*)"/);
  const name = header.match(/"name"\s*:\s*"([^"]*)"/);
  return {
    schema_version: schema ? Number(schema[1]) : null,
    item_count: itemCount ? Number(itemCount[1]) : null,
    generated_at: generated ? generated[1] : null,
    name: name ? name[1] : null
  };
}

function stixMetaFromHeader(header) {
  const type = header.match(/"type"\s*:\s*"([^"]*)"/);
  const spec = header.match(/"spec_version"\s*:\s*"([^"]*)"/);
  const id = header.match(/"id"\s*:\s*"([^"]*)"/);
  return { type: type ? type[1] : null, spec: spec ? spec[1] : null, bundle_id: id ? id[1] : null };
}

async function main() {
  const cfg = getPublishedFeedArtifactConfig();
  const client = await pool.connect();
  try {
    const snaps = await client.query(
      `SELECT artifact_format, item_count, content_hash, storage_path, file_size, generated_at
       FROM published_feed_snapshots
       WHERE feed_id = $1 AND status = 'success'
         AND params->>'window' = $2
       ORDER BY generated_at DESC`,
      [feedId, windowName]
    );
    const latest = {};
    for (const row of snaps.rows) {
      if (!latest[row.artifact_format]) latest[row.artifact_format] = row;
    }
    const report = { feed_id: feedId, window: windowName, formats: {}, integrity: {} };
    const genAll = await getActiveChunkGeneration(client, feedId, iocTypeKey, windowName);
    if (!genAll?.length) throw new Error('no active chunk generation');
    report.generation_id = genAll[0].id;
    report.generation_state = genAll[0].state;
    report.item_count = Number(genAll[0].item_count);
    report.chunk_count = Number(genAll[0].chunk_count);
    report.candidate_cutoff = genAll[0].candidate_cutoff;
    report.generated_at = genAll[0].generated_at;

    let missingFiles = 0;
    let hashMismatch = 0;
    let sizeMismatch = 0;
    let partFiles = 0;
    let dupKeys = 0;
    const sumItems = {};
    for (const format of ['txt', 'json', 'stix']) {
      const generation = await getActiveChunkGeneration(client, feedId, iocTypeKey, windowName, format);
      const chunks = await getChunkGenerationFiles(client, generation.id, format);
      const keys = new Set();
      sumItems[format] = 0;
      for (const chunk of chunks) {
        if (keys.has(chunk.chunk_key)) dupKeys += 1;
        keys.add(chunk.chunk_key);
        sumItems[format] += Number(chunk.item_count || 0);
        const abs = resolveStoredArtifactPath(cfg.storageDir, chunk.storage_path);
        if (abs.endsWith('.part')) partFiles += 1;
        if (!fs.existsSync(abs)) {
          missingFiles += 1;
          continue;
        }
        const st = fs.statSync(abs);
        if (Number(st.size) !== Number(chunk.byte_length)) sizeMismatch += 1;
        const hash = crypto.createHash('sha256');
        const fh = createReadStream(abs);
        // eslint-disable-next-line no-await-in-loop
        await pipeline(fh, hash);
        if (hash.digest('hex') !== chunk.content_hash) hashMismatch += 1;
      }
      const legacy = latest[format];
      const legacyAbs = legacy ? resolveStoredArtifactPath(cfg.storageDir, legacy.storage_path) : null;
      const fmtReport = {
        chunk_files: chunks.length,
        logical_bytes: Number(generation.byte_length),
        etag: generation.strong_etag,
        generated_at: generation.generated_at,
        recency_head: generation.recency_head_path || null,
        sum_chunk_items: sumItems[format],
        legacy_item_count: legacy ? Number(legacy.item_count) : null,
        legacy_file_size: legacy ? Number(legacy.file_size) : null,
        legacy_path: legacy?.storage_path || null
      };

      if (format === 'txt') {
        const streamed = await collectStream(generation, chunks, { keepBuffer: true });
        fmtReport.streamed_bytes = streamed.received;
        fmtReport.content_length_ok = streamed.received === Number(generation.byte_length);
        const composed = parseTxtSet(streamed.buf);
        const legacyBuf = fs.readFileSync(legacyAbs);
        const mono = parseTxtSet(legacyBuf);
        const diff = setDiff(mono.set, composed.set);
        fmtReport.legacy_lines = mono.count;
        fmtReport.composed_lines = composed.count;
        fmtReport.legacy_unique = mono.unique;
        fmtReport.composed_unique = composed.unique;
        fmtReport.composed_dupes = composed.dupes;
        fmtReport.legacy_dupes = mono.dupes;
        Object.assign(fmtReport, diff);
        if (generation.recency_head_path) {
          const headAbs = resolveStoredArtifactPath(cfg.storageDir, generation.recency_head_path);
          const headLines = fs.readFileSync(headAbs, 'utf8').split('\n').filter(Boolean);
          const monoLines = legacyBuf.toString('utf8').split('\n').filter(Boolean);
          const n = Math.min(25, monoLines.length, headLines.length);
          fmtReport.limit25_match = headLines.slice(0, n).join('\n') === monoLines.slice(0, n).join('\n');
          fmtReport.limit25_head = headLines.slice(0, 3);
          fmtReport.limit25_legacy = monoLines.slice(0, 3);
        }
      } else if (format === 'json') {
        const composedIds = new Set();
        const composedFp = new Set();
        let composedDupes = 0;
        const composedParser = new ArrayObjectParser('items', (item) => {
          const id = `${item?.type || ''}|${item?.value || ''}`;
          if (composedIds.has(id)) composedDupes += 1;
          composedIds.add(id);
          composedFp.add(stableStringify(item));
        });
        const streamedBytes = await streamComposed(generation, chunks, composedParser);
        fmtReport.streamed_bytes = streamedBytes;
        fmtReport.content_length_ok = streamedBytes === Number(generation.byte_length);
        fmtReport.parse_ok = composedParser.parseErrors === 0;
        fmtReport.parse_errors = composedParser.parseErrors;
        const composedMeta = jsonMetaFromHeader(composedParser.header);
        Object.assign(fmtReport, composedMeta);

        const legacyIds = new Set();
        const legacyFp = new Set();
        let legacyDupes = 0;
        const legacyParser = await parseFileArray(legacyAbs, 'items', (item) => {
          const id = `${item?.type || ''}|${item?.value || ''}`;
          if (legacyIds.has(id)) legacyDupes += 1;
          legacyIds.add(id);
          legacyFp.add(stableStringify(item));
        });
        const legacyMeta = jsonMetaFromHeader(legacyParser.header);
        fmtReport.composed_items = composedParser.count;
        fmtReport.legacy_items = legacyParser.count;
        fmtReport.composed_dupes = composedDupes;
        fmtReport.legacy_dupes = legacyDupes;
        fmtReport.legacy_generated_at = legacyMeta.generated_at;
        fmtReport.legacy_schema_version = legacyMeta.schema_version;
        const diff = setDiff(legacyIds, composedIds);
        Object.assign(fmtReport, diff);
        let fpMissing = 0;
        let fpExtra = 0;
        for (const fp of legacyFp) if (!composedFp.has(fp)) fpMissing += 1;
        for (const fp of composedFp) if (!legacyFp.has(fp)) fpExtra += 1;
        fmtReport.semantic_fp_missing = fpMissing;
        fmtReport.semantic_fp_extra = fpExtra;
        fmtReport.identity_equal = diff.missing_count === 0 && diff.extra_count === 0;
      } else {
        const composedIds = new Set();
        const composedFp = new Set();
        let composedDupes = 0;
        const composedParser = new ArrayObjectParser('objects', (obj) => {
          const id = String(obj?.id || '');
          if (composedIds.has(id)) composedDupes += 1;
          composedIds.add(id);
          const copy = { ...obj };
          composedFp.add(stableStringify(copy));
        });
        const streamedBytes = await streamComposed(generation, chunks, composedParser);
        fmtReport.streamed_bytes = streamedBytes;
        fmtReport.content_length_ok = streamedBytes === Number(generation.byte_length);
        fmtReport.parse_ok = composedParser.parseErrors === 0;
        fmtReport.parse_errors = composedParser.parseErrors;
        const composedMeta = stixMetaFromHeader(composedParser.header);
        fmtReport.bundle_type = composedMeta.type;
        fmtReport.spec_version = composedMeta.spec;
        fmtReport.composed_bundle_id = composedMeta.bundle_id;

        const legacyIds = new Set();
        const legacyFp = new Set();
        let legacyDupes = 0;
        const legacyParser = await parseFileArray(legacyAbs, 'objects', (obj) => {
          const id = String(obj?.id || '');
          if (legacyIds.has(id)) legacyDupes += 1;
          legacyIds.add(id);
          legacyFp.add(stableStringify(obj));
        });
        const legacyMeta = stixMetaFromHeader(legacyParser.header);
        fmtReport.legacy_bundle_id = legacyMeta.bundle_id;
        fmtReport.composed_objects = composedParser.count;
        fmtReport.legacy_objects = legacyParser.count;
        fmtReport.composed_dupes = composedDupes;
        const diff = setDiff(legacyIds, composedIds);
        Object.assign(fmtReport, diff);
        let fpMissing = 0;
        let fpExtra = 0;
        for (const fp of legacyFp) if (!composedFp.has(fp)) fpMissing += 1;
        for (const fp of composedFp) if (!legacyFp.has(fp)) fpExtra += 1;
        fmtReport.semantic_fp_missing = fpMissing;
        fmtReport.semantic_fp_extra = fpExtra;
        fmtReport.identity_equal = diff.missing_count === 0 && diff.extra_count === 0;
        fmtReport.bundle_id_match = composedMeta.bundle_id === legacyMeta.bundle_id;
      }
      report.formats[format] = fmtReport;
    }

    report.integrity = {
      missing_files: missingFiles,
      hash_mismatch: hashMismatch,
      size_mismatch: sizeMismatch,
      part_files: partFiles,
      duplicate_chunk_keys: dupKeys,
      sum_txt: sumItems.txt,
      sum_json: sumItems.json,
      sum_stix: sumItems.stix,
      generation_item_count: Number(genAll[0].item_count)
    };
    console.log(JSON.stringify(report, null, 2));
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err?.stack || err);
  process.exitCode = 1;
});
