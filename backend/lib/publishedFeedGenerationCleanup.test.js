// Failed / abandoned Published Feed generations must not leave unbounded files behind.
//
// A transactional in-memory store stands in for PostgreSQL (BEGIN copies state, ROLLBACK
// discards it) while chunk files are written to a real temp directory, so each test checks
// the database-vs-filesystem invariant the production leak violated.

import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildAndActivateChunkGeneration } from './publishedFeedChunkGeneration.js';
import { generateFeedArtifact, publishedItemCount } from './publishedFeedStreamGenerator.js';
import {
  runPublishedFeedOrphanGc,
  describeArtifactPath,
  resolveOrphanGcMinAgeMinutes
} from './publishedFeedArtifact/orphanGc.js';
import {
  isPublishedFeedDue,
  publishedFeedScheduleIntervalMs
} from './feedPublisherService.js';

let root;
const previousStorageDir = process.env.PUBLISHED_FEED_STORAGE_DIR;

before(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-cleanup-'));
  process.env.PUBLISHED_FEED_STORAGE_DIR = root;
});
after(() => {
  fs.rmSync(root, { recursive: true, force: true });
  if (previousStorageDir === undefined) delete process.env.PUBLISHED_FEED_STORAGE_DIR;
  else process.env.PUBLISHED_FEED_STORAGE_DIR = previousStorageDir;
});
beforeEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });
});

const HOUR = 60 * 60 * 1000;

function item(n, { timestamps = true } = {}) {
  const value = n.toString(16).padStart(64, '0');
  return {
    identity_key: `h:${value}`,
    chunk_key: n % 4,
    txt_value: value,
    item_json: {
      value,
      type: 'sha256',
      sources: [],
      // An item without timestamps is valid TXT/JSON but gets no STIX Indicator.
      timestamps: timestamps ? { imported_at: '2026-09-01T00:00:00.000Z' } : {},
      classification: { confidence: 100 }
    }
  };
}

class FakeStore {
  constructor({ feedIds = [25] } = {}) {
    this.committed = {
      feeds: feedIds.map((id) => ({ id })),
      generations: [],
      chunks: [],
      genChunks: [],
      formats: [],
      active: [],
      snapshots: []
    };
    this.tx = null;
    this.items = new Map();
    this.cursor = [];
    this.fetches = 0;
    this.fetchHook = null;
    this.locked = new Set();
    this.nextChunkId = 1;
  }

  get s() { return this.tx || this.committed; }

  async connect() {
    return { query: (sql, params) => this.query(sql, params), release() {} };
  }

  async query(sql, params = []) {
    const q = String(sql).replace(/\s+/g, ' ').trim();
    const s = this.s;
    if (q === 'BEGIN') { this.tx = structuredClone(this.committed); return { rows: [] }; }
    if (q === 'COMMIT') { this.committed = this.tx; this.tx = null; return { rows: [] }; }
    if (q === 'ROLLBACK') { this.tx = null; return { rows: [] }; }
    if (q.includes('pg_try_advisory_lock')) return { rows: [{ ok: !this.locked.has(Number(params[1])) }] };
    if (q.includes('pg_advisory_unlock')) return { rows: [{ ok: true }] };
    if (q.startsWith('SELECT id FROM published_feeds WHERE id = ANY')) {
      const ids = new Set(params[0].map(Number));
      return { rows: s.feeds.filter((f) => ids.has(f.id)) };
    }
    if (q.includes('FROM published_feed_active_generations a JOIN published_feed_generations g')) {
      const [feedId, window, typeKey, format] = params;
      const rows = [];
      for (const a of s.active) {
        if (a.feed_id !== Number(feedId) || a.snapshot_window !== window || a.ioc_type_key !== typeKey) continue;
        const g = s.generations.find((x) => x.id === a.generation_id && x.state === 'active');
        if (!g) continue;
        for (const gf of s.formats.filter((x) => x.generation_id === g.id)) {
          if (format && gf.format !== format) continue;
          rows.push({ ...g, format: gf.format, format_item_count: gf.item_count });
        }
      }
      return { rows };
    }
    if (q.startsWith('INSERT INTO published_feed_generations')) {
      s.generations.push({
        id: params[0], feed_id: Number(params[1]), snapshot_window: params[2], ioc_type_key: params[3],
        parent_generation_id: params[4], state: 'building', item_count: params[7], chunk_count: params[8]
      });
      return { rows: [] };
    }
    if (q.startsWith('DECLARE pf_chunk_cur')) {
      const keys = new Set(params[2].map(Number));
      this.cursor = (this.items.get(Number(params[0])) || [])
        .filter((r) => keys.has(r.chunk_key))
        .sort((a, b) => a.chunk_key - b.chunk_key || a.identity_key.localeCompare(b.identity_key));
      this.fetches = 0;
      return { rows: [] };
    }
    if (q.startsWith('FETCH FORWARD')) {
      this.fetches += 1;
      if (this.fetchHook) this.fetchHook(this.fetches);
      return { rows: this.cursor.splice(0, 2) };
    }
    if (q.startsWith('CLOSE')) return { rows: [] };
    if (q.startsWith('INSERT INTO published_feed_chunks')) {
      const key = params.slice(0, 8).join('|');
      let row = s.chunks.find((c) => c.key === key);
      if (!row) {
        row = {
          id: this.nextChunkId++, key, feed_id: Number(params[0]), chunk_key: Number(params[4]),
          format: params[5], content_hash: params[7], byte_length: params[8], item_count: params[9]
        };
        s.chunks.push(row);
      }
      row.storage_path = params[10];
      return { rows: [{ id: row.id }] };
    }
    if (q.startsWith('INSERT INTO published_feed_generation_chunks') && q.includes('SELECT $1')) {
      const [id, parentId, affected] = params;
      const skip = new Set(affected.map(Number));
      for (const gc of s.genChunks.filter((x) => x.generation_id === parentId && !skip.has(x.chunk_key))) {
        s.genChunks.push({ ...gc, generation_id: id });
      }
      return { rows: [] };
    }
    if (q.startsWith('INSERT INTO published_feed_generation_chunks')) {
      s.genChunks.push({ generation_id: params[0], format: params[1], chunk_key: Number(params[2]), chunk_id: params[3] });
      return { rows: [] };
    }
    if (q.startsWith('SELECT txt_value FROM published_feed_items')) {
      return { rows: (this.items.get(Number(params[0])) || []).map((r) => ({ txt_value: r.txt_value })) };
    }
    if (q.startsWith('SELECT c.content_hash, c.byte_length, c.item_count')) {
      const rows = s.genChunks
        .filter((gc) => gc.generation_id === params[0] && gc.format === params[1])
        .sort((a, b) => a.chunk_key - b.chunk_key)
        .map((gc) => s.chunks.find((c) => c.id === gc.chunk_id));
      return { rows };
    }
    if (q.startsWith('INSERT INTO published_feed_generation_formats')) {
      s.formats.push({ generation_id: params[0], format: params[1], item_count: params[6], recency_head_path: params[9] });
      return { rows: [] };
    }
    if (q.startsWith('UPDATE published_feed_generations')) {
      const g = s.generations.find((x) => x.id === params[0]);
      if (g && q.includes("state = 'ready'")) g.state = 'ready';
      else if (g && q.includes("state = 'superseded'") && g.state === 'active') g.state = 'superseded';
      else if (g && q.includes("state = 'active'")) g.state = 'active';
      return { rows: [] };
    }
    if (q.startsWith('INSERT INTO published_feed_active_generations')) {
      const [feedId, window, typeKey, id] = params;
      const existing = s.active.find((a) => a.feed_id === Number(feedId) && a.snapshot_window === window && a.ioc_type_key === typeKey);
      if (existing) existing.generation_id = id;
      else s.active.push({ feed_id: Number(feedId), snapshot_window: window, ioc_type_key: typeKey, generation_id: id });
      return { rows: [] };
    }
    if (q.startsWith('UPDATE published_feeds')) return { rows: [] };
    if (q.includes('published_feed_snapshots') && q.startsWith('UPDATE')) return { rows: [], rowCount: 0 };
    // Orphan GC reference loads.
    if (q.startsWith('SELECT storage_path FROM published_feed_chunks WHERE feed_id')) {
      return { rows: s.chunks.filter((c) => c.feed_id === Number(params[0])) };
    }
    if (q.startsWith('SELECT gf.recency_head_path')) {
      const genIds = new Set(s.generations.filter((g) => g.feed_id === Number(params[0])).map((g) => g.id));
      return { rows: s.formats.filter((f) => genIds.has(f.generation_id) && f.recency_head_path) };
    }
    if (q.startsWith('SELECT id FROM published_feed_generations WHERE feed_id')) {
      return { rows: s.generations.filter((g) => g.feed_id === Number(params[0])) };
    }
    if (q.startsWith('SELECT storage_path FROM published_feed_snapshots')) {
      return { rows: s.snapshots.filter((x) => x.feed_id === Number(params[0]) && x.storage_path) };
    }
    throw new Error(`FakeStore: unexpected SQL: ${q.slice(0, 140)}`);
  }
}

const feed = (over = {}) => ({
  id: 25, name: 'hash', slug: 'hash', formats: ['txt', 'json', 'stix'],
  include_source_metadata: true, include_classification: true, include_enrichment: false,
  chunk_backfill_status: 'ready', chunk_count: 4, chunk_algo_version: 1,
  ...over
});

async function runGeneration(store, f, opts = {}) {
  await store.query('BEGIN');
  try {
    const result = await buildAndActivateChunkGeneration(store, f, {
      window: 'all',
      iocTypeKey: 'hash',
      configHash: 'cfg',
      candidateCutoff: new Date('2026-09-27T00:00:00.000Z'),
      expectedItemCount: (store.items.get(f.id) || []).length,
      ...opts
    });
    await store.query('COMMIT');
    return result;
  } catch (err) {
    await store.query('ROLLBACK');
    throw err;
  }
}

function listFiles(dir = root) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.existsSync(d) ? fs.readdirSync(d, { withFileTypes: true }) : []) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else out.push(path.relative(root, p).split(path.sep).join('/'));
    }
  };
  walk(dir);
  return out.sort();
}

function referencedPaths(store) {
  const s = store.committed;
  return new Set([
    ...s.chunks.map((c) => c.storage_path),
    ...s.formats.map((f) => f.recency_head_path).filter(Boolean)
  ]);
}

/** Every file on disk is referenced by committed DB state, and every reference exists. */
function assertDbAndFilesConsistent(store) {
  const files = listFiles();
  const refs = referencedPaths(store);
  assert.deepEqual(files, [...refs].sort());
}

function ageAllFiles(ms) {
  const t = new Date(Date.now() - ms);
  for (const rel of listFiles()) fs.utimesSync(path.join(root, rel), t, t);
}

function writeFile(rel, content = 'x', ageMs = 0) {
  const abs = path.join(root, ...rel.split('/'));
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
  if (ageMs) {
    const t = new Date(Date.now() - ageMs);
    fs.utimesSync(abs, t, t);
  }
  return abs;
}

const CHUNK_DIR = 'chunks/feed-25/all/v1/n4/txt';
const orphanChunk = (key = 1, hashChar = 'a') => `${CHUNK_DIR}/${key}-${hashChar.repeat(64)}.txt`;

describe('Feed 25 regression: item count is the published TXT/JSON count, not STIX', () => {
  it('publishedItemCount prefers TXT, then JSON, and uses STIX only for STIX-only feeds', () => {
    assert.equal(publishedItemCount({ txt: 10, json: 10, stix: 9 }), 10);
    assert.equal(publishedItemCount({ json: 7, stix: 6 }), 7);
    assert.equal(publishedItemCount({ stix: 5 }), 5);
  });

  it('a hash without STIX timestamps keeps itemCount equal to TXT lines and projection rows', async () => {
    // Canonical hash feed: the published sha256 comes from the file artifact and has no
    // ioc_items row of its own, so sibling metadata resolution finds nothing for it.
    const published = (n) => n.toString(16).padStart(64, '0');
    const rows = [1, 2, 3].map((n) => ({
      id: n, observable: published(n), observable_type: 'sha256', confidence: 'high', category: null,
      created_at: '2026-09-01T00:00:00Z', ioc_source_id: null, source_name: 'otx', recency_ts: '2026-09-02T00:00:00Z'
    }));
    const siblings = rows.slice(0, 2);
    let pos = 0;
    const projection = [];
    const db = {
      async query(sql, params) {
        const q = String(sql).replace(/\s+/g, ' ');
        if (q.startsWith('FETCH FORWARD')) { const r = rows.slice(pos, pos + 100); pos += r.length; return { rows: r }; }
        if (q.includes('lower(i.observable) = ANY') && q.includes('FROM ioc_items i') && !q.includes('ioc_sources')) {
          return { rows: siblings.map((r) => ({ id: r.id, obs: r.observable, otype: r.observable_type, created_at: r.created_at })) };
        }
        if (q.includes('INSERT INTO published_feed_items')) { projection.push(...(params?.[0] || [])); return { rows: [], rowCount: 0 }; }
        return { rows: [] };
      }
    };
    const art = await generateFeedArtifact(db, feed({ ioc_types: ['hash'] }), 'all', {
      formatTypes: ['hash'], maxItems: null, cfg: { storageDir: root, supersededRetentionMinutes: 60, stalePartMinutes: 30 }
    });
    const byFormat = Object.fromEntries(art.artifacts.map((a) => [a.format, a]));
    assert.equal(byFormat.txt.itemCount, 3);
    assert.equal(byFormat.stix.itemCount, 2, 'the timestamp-less hash has no STIX indicator');
    assert.equal(art.itemCount, 3, 'feed item count must match TXT/projection, not the last (STIX) writer');
  });

  it('chunk activation succeeds when STIX skips an item and the expected count is the TXT count', async () => {
    const store = new FakeStore();
    store.items.set(25, [item(1), item(2), item(3, { timestamps: false }), item(4)]);
    const result = await runGeneration(store, feed());
    assert.equal(result.itemCount, 4);
    assert.equal(store.committed.generations.find((g) => g.id === result.generationId).state, 'active');
    assertDbAndFilesConsistent(store);
  });
});

describe('chunk generation lifecycle cleanup', () => {
  it('successful generation keeps its files and every file is DB-referenced', async () => {
    const store = new FakeStore();
    store.items.set(25, [item(1), item(2), item(3), item(4), item(5)]);
    const result = await runGeneration(store, feed());
    assert.ok(result.generatedChunks > 0);
    assert.ok(listFiles().length > 0);
    assertDbAndFilesConsistent(store);
  });

  it('failure before any chunk is written leaves no files', async () => {
    const store = new FakeStore();
    store.items.set(25, [item(1), item(2)]);
    await assert.rejects(runGeneration(store, feed(), { failAt: 'after_generation_insert' }), /injected/);
    assert.deepEqual(listFiles(), []);
    assert.equal(store.committed.generations.length, 0);
  });

  it('failure after chunk files are written but before chunk rows removes the files', async () => {
    const store = new FakeStore();
    store.items.set(25, [item(1), item(2), item(3), item(4)]);
    await assert.rejects(runGeneration(store, feed(), { failAt: 'after_chunks' }), /injected/);
    assert.deepEqual(listFiles(), []);
    assert.equal(store.committed.chunks.length, 0);
  });

  it('failure after partial DB persistence rolls back rows and removes files, head included', async () => {
    const store = new FakeStore();
    store.items.set(25, [item(1), item(2), item(3), item(4)]);
    await assert.rejects(runGeneration(store, feed(), { failAt: 'after_manifest' }), /injected/);
    assert.deepEqual(listFiles(), []);
    assert.deepEqual(store.committed.formats, []);
  });

  it('cancellation mid-cursor removes finished chunk files and open .part files', async () => {
    const store = new FakeStore();
    store.items.set(25, [item(1), item(2), item(3), item(4), item(5), item(6), item(7), item(8)]);
    store.fetchHook = (n) => {
      if (n === 3) throw Object.assign(new Error('canceling statement due to user request'), { code: '57014' });
    };
    await assert.rejects(runGeneration(store, feed()), /canceling statement/);
    assert.deepEqual(listFiles(), [], 'no chunk finals or .chunk-*.part left');
  });

  it('failure injection: previous successful generation and its files stay untouched', async () => {
    const store = new FakeStore();
    store.items.set(25, [item(1), item(2), item(3), item(4)]);
    const first = await runGeneration(store, feed());
    const before = listFiles();
    const beforeBytes = Object.fromEntries(before.map((rel) => [rel, fs.readFileSync(path.join(root, rel), 'utf8')]));

    // New data changes some chunks (new files) while others are reused byte-for-byte.
    store.items.set(25, [item(1), item(2), item(3), item(4), item(9), item(10)]);
    await assert.rejects(
      runGeneration(store, feed(), { expectedItemCount: 999 }),
      (err) => err.code === 'CHUNK_MANIFEST_COUNT_MISMATCH'
    );

    assert.deepEqual(listFiles(), before, 'only files created by the failed generation are removed');
    for (const rel of before) assert.equal(fs.readFileSync(path.join(root, rel), 'utf8'), beforeBytes[rel]);
    const active = store.committed.active.find((a) => a.feed_id === 25);
    assert.equal(active.generation_id, first.generationId, 'no newly active generation');
    assert.equal(store.committed.generations.length, 1);
    assertDbAndFilesConsistent(store);
  });

  it('repeated failures do not accumulate files', async () => {
    const store = new FakeStore();
    store.items.set(25, [item(1), item(2), item(3), item(4)]);
    await runGeneration(store, feed());
    const baseline = listFiles();
    for (let i = 0; i < 5; i += 1) {
      store.items.set(25, [item(1), item(2), item(3), item(4), item(20 + i)]);
      // eslint-disable-next-line no-await-in-loop
      await assert.rejects(runGeneration(store, feed(), { failAt: 'after_manifest' }));
    }
    assert.deepEqual(listFiles(), baseline);
  });
});

describe('orphan GC', () => {
  const OLD = 48 * HOUR;
  const gc = (store, opts = {}) => runPublishedFeedOrphanGc(store, { minAgeMinutes: 360, storageDir: root, ...opts });

  it('dry-run reports an orphan and deletes nothing', async () => {
    const store = new FakeStore();
    writeFile(orphanChunk(), 'orphan', OLD);
    const report = await gc(store);
    assert.equal(report.mode, 'dry_run');
    assert.equal(report.delete_eligible.files, 1);
    assert.equal(report.orphan_reasons.chunk_file_without_chunk_row, 1);
    assert.equal(report.deleted.files, 0);
    assert.deepEqual(listFiles(), [orphanChunk()]);
  });

  it('apply deletes an eligible orphan', async () => {
    const store = new FakeStore();
    writeFile(orphanChunk(), 'orphan', OLD);
    const report = await gc(store, { apply: true });
    assert.equal(report.deleted.files, 1);
    assert.equal(report.deleted.bytes, 6);
    assert.deepEqual(listFiles(), []);
  });

  it('never deletes DB-referenced chunk files or files of the active generation', async () => {
    const store = new FakeStore();
    store.items.set(25, [item(1), item(2), item(3), item(4)]);
    await runGeneration(store, feed());
    ageAllFiles(OLD);
    const before = listFiles();
    const report = await gc(store, { apply: true });
    assert.equal(report.deleted.files, 0);
    assert.equal(report.referenced.files, before.length);
    assert.deepEqual(listFiles(), before);
  });

  it('keeps an unreferenced recency head while its generation row exists', async () => {
    const store = new FakeStore();
    store.committed.generations.push({ id: 'mujgen-1', feed_id: 25, state: 'building' });
    writeFile('generations/feed-25/mujgen-1.txt-head', 'h', OLD);
    writeFile('generations/feed-25/mujgen-2.txt-head', 'h', OLD);
    const report = await gc(store, { apply: true });
    assert.deepEqual(listFiles(), ['generations/feed-25/mujgen-1.txt-head']);
    assert.equal(report.orphan_reasons.recency_head_without_generation, 1);
  });

  it('protects recent unreferenced files', async () => {
    const store = new FakeStore();
    writeFile(orphanChunk(), 'fresh');
    const report = await gc(store, { apply: true });
    assert.equal(report.protected.files, 1);
    assert.equal(report.protected_reasons.younger_than_min_age, 1);
    assert.equal(listFiles().length, 1);
  });

  it('protects every file of a feed whose generation is in progress', async () => {
    const store = new FakeStore();
    store.locked.add(25);
    writeFile(orphanChunk(), 'x', OLD);
    writeFile('25/mujabc-1.json.body', 'x', OLD);
    const report = await gc(store, { apply: true });
    assert.equal(report.protected_reasons.generation_in_progress, 2);
    assert.equal(report.deleted.files, 0);
    assert.equal(listFiles().length, 2);
  });

  it('never deletes unknown files or files of feeds that no longer exist', async () => {
    const store = new FakeStore({ feedIds: [25] });
    writeFile('README.txt', 'x', OLD);
    writeFile(`${CHUNK_DIR}/not-a-chunk.bin`, 'x', OLD);
    writeFile('chunks/feed-77/all/v1/n4/txt/1-' + 'b'.repeat(64) + '.txt', 'x', OLD);
    writeFile(`${CHUNK_DIR}/2-${'c'.repeat(64)}.json`, 'x', OLD); // extension/dir mismatch
    const report = await gc(store, { apply: true });
    assert.equal(report.unknown.files, 4);
    assert.equal(report.unknown_reasons.feed_not_found, 1);
    assert.equal(report.deleted.files, 0);
    assert.equal(listFiles().length, 4);
  });

  it('does not cross feeds: an orphan in one feed never affects another feed', async () => {
    const store = new FakeStore({ feedIds: [25, 26] });
    store.items.set(26, [item(1), item(2)]);
    await runGeneration(store, feed({ id: 26 }));
    const feed26 = listFiles();
    writeFile(orphanChunk(), 'x', OLD);
    ageAllFiles(OLD);
    const report = await gc(store, { apply: true });
    assert.equal(report.by_feed[25].deleted.files, 1);
    assert.equal(report.by_feed[26].deleted.files, 0);
    assert.deepEqual(listFiles(), feed26);
  });

  it('reclaims artifacts abandoned by a killed process (no cleanup ran)', async () => {
    const store = new FakeStore();
    store.items.set(25, [item(1), item(2), item(3), item(4)]);
    await runGeneration(store, feed());
    const kept = listFiles();
    // Simulated crash: chunk finals, chunk .part, recency head and monolithic temps were
    // written but the process died before any row committed.
    writeFile(orphanChunk(3, 'd'), 'x', OLD);
    writeFile(`${CHUNK_DIR}/.chunk-3-0123abcd.part`, 'x', OLD);
    writeFile('generations/feed-25/mujdead-1.txt-head', 'x', OLD);
    writeFile('25/mujdead-1.json.body', 'x', OLD);
    writeFile('25/mujdead-1.stix.part', '', OLD);
    ageAllFiles(OLD);
    const dry = await gc(store);
    assert.equal(dry.delete_eligible.files, 5);
    assert.equal(listFiles().length, kept.length + 5, 'dry-run deletes nothing');
    const report = await gc(store, { apply: true });
    assert.equal(report.deleted.files, 5);
    assert.deepEqual(listFiles(), kept);
    assertDbAndFilesConsistent(store);
  });

  it('keeps snapshot artifacts referenced by a snapshot row', async () => {
    const store = new FakeStore();
    store.committed.snapshots.push({ feed_id: 25, storage_path: '25/mujlive-1.txt' });
    writeFile('25/mujlive-1.txt', 'x', OLD);
    writeFile('25/mujold-1.txt', 'x', OLD);
    await gc(store, { apply: true });
    assert.deepEqual(listFiles(), ['25/mujlive-1.txt']);
  });

  it('path classification only accepts the known layouts', () => {
    assert.equal(describeArtifactPath(orphanChunk()).kind, 'chunk');
    assert.equal(describeArtifactPath('generations/feed-25/abc-1.txt-head').kind, 'recency_head');
    assert.equal(describeArtifactPath('25/abc-1.stix.body').kind, 'snapshot_body_temp');
    assert.equal(describeArtifactPath('../25/abc-1.txt'), null);
    assert.equal(describeArtifactPath('chunks/feed-25/all/v1/n4/txt/../../x.txt'), null);
    assert.equal(describeArtifactPath('chunks/feed-25/all/v1/n4/txt/1-short.txt'), null);
  });

  it('minimum age never drops below artifact retention', () => {
    assert.equal(resolveOrphanGcMinAgeMinutes('1'), 60);
    assert.equal(resolveOrphanGcMinAgeMinutes(undefined), 360);
  });
});

describe('retry backoff for a failing feed', () => {
  const row = (failures) => ({ enabled: true, refresh_interval_minutes: 5, consecutive_failures: failures });

  it('healthy feeds and the first failure keep the configured cadence', () => {
    assert.equal(publishedFeedScheduleIntervalMs(row(0)), 5 * 60 * 1000);
    assert.equal(publishedFeedScheduleIntervalMs(row(1)), 5 * 60 * 1000);
  });

  it('consecutive failures back off exponentially up to the cap', () => {
    assert.equal(publishedFeedScheduleIntervalMs(row(2)), 10 * 60 * 1000);
    assert.equal(publishedFeedScheduleIntervalMs(row(4)), 40 * 60 * 1000);
    assert.equal(publishedFeedScheduleIntervalMs(row(50)), 360 * 60 * 1000);
  });

  it('a permanently failing feed attempts far fewer generations per day', () => {
    const start = Date.parse('2026-09-27T00:00:00Z');
    let now = start;
    let attempts = 0;
    const feedRow = { ...row(0), last_generated_at: new Date(start).toISOString(), last_refresh_ms: 0 };
    while (now < start + 24 * HOUR) {
      if (isPublishedFeedDue(feedRow, now)) {
        attempts += 1;
        feedRow.consecutive_failures += 1;
        feedRow.last_generated_at = new Date(now).toISOString();
      }
      now += 60 * 1000;
    }
    // Previously: every 5 minutes = 288 attempts/day.
    assert.ok(attempts <= 12, `attempts=${attempts}`);
    assert.ok(attempts >= 4, 'still retries and stays recoverable');
  });
});
