import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateFeedArtifact, generateEmptyFeedArtifact } from './publishedFeedStreamGenerator.js';
import { buildFeedContent } from './feedPublisherService.js';
import { normalizePublishedIoc } from './publishedFeedJson.js';

let dir;
const cfg = () => ({ storageDir: dir, supersededRetentionMinutes: 60, stalePartMinutes: 30 });
before(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfgen-')); });
after(() => { fs.rmSync(dir, { recursive: true, force: true }); });

/**
 * Mock generation client that emulates a server-side cursor over canned base rows plus
 * sibling-id resolve + id-keyed enrichment queries. `failOn` (a SQL substring) makes the
 * matching query throw, to exercise the atomicity/rollback path.
 *
 * @param {object[]} baseRows cursor rows (already deduped winners)
 * @param {{ tags?: object, sources?: object, siblings?: object[], failOn?: string|null }} opts
 *   tags/sources keyed by ioc id (including non-selected siblings).
 *   siblings defaults to baseRows themselves (id/obs/type/created_at).
 */
function mockDb(baseRows, { tags = {}, sources = {}, siblings = null, failOn = null } = {}) {
  let pos = 0;
  const log = [];
  const siblingRows = (siblings || baseRows).map((r) => ({
    id: Number(r.id),
    obs: String(r.obs || r.observable).toLowerCase(),
    otype: r.otype || r.observable_type,
    created_at: r.created_at,
    ioc_source_id: r.ioc_source_id ?? null
  }));
  return {
    log,
    async query(sql, params) {
      const s = String(sql).replace(/\s+/g, ' ');
      log.push(s.slice(0, 80));
      if (failOn && s.includes(failOn)) throw new Error(`injected failure on ${failOn}`);
      if (s.startsWith('BEGIN') || s.startsWith('COMMIT') || s.startsWith('ROLLBACK')) return { rows: [] };
      if (s.startsWith('DECLARE')) { pos = 0; return { rows: [] }; }
      if (s.startsWith('CLOSE')) return { rows: [] };
      if (s.startsWith('FETCH FORWARD')) {
        const n = Number(s.match(/FETCH FORWARD (\d+)/)[1]);
        const slice = baseRows.slice(pos, pos + n);
        pos += slice.length;
        return { rows: slice };
      }
      // Sibling resolve for duplicate-observable metadata aggregation.
      if (s.includes('lower(i.observable) = ANY') && s.includes('FROM ioc_items i') && !s.includes('ioc_sources')) {
        return { rows: siblingRows };
      }
      if (s.includes('FROM ioc_feed_memberships m JOIN integration_feeds')) {
        const ids = new Set((params?.[0] || []).map(Number));
        const rows = [];
        for (const [id, arr] of Object.entries(sources)) {
          if (!ids.has(Number(id))) continue;
          for (const src of arr) rows.push({ ioc_item_id: Number(id), ...src });
        }
        return { rows };
      }
      if (s.includes('FROM ioc_items i LEFT JOIN ioc_sources s')) return { rows: [] };
      if (s.includes('FROM ioc_tags it')) {
        const ids = new Set((params?.[0] || []).map(Number));
        const rows = [];
        for (const [id, names] of Object.entries(tags)) {
          if (!ids.has(Number(id))) continue;
          for (const name of names) rows.push({ ioc_id: Number(id), name });
        }
        return { rows };
      }
      return { rows: [] }; // enrichment tables etc.
    }
  };
}

const feedBase = (over = {}) => ({
  id: 42, name: 'Test', format: 'json', filter_mode: 'basic', advanced_query: null,
  ioc_types: ['domain'], include_feed_keys: null, include_tags: null, exclude_tags: null,
  exclude_false_positive: true, exclude_expired: true, min_confidence: null, time_window: 'all',
  max_items: null, include_source_metadata: true, include_classification: true, include_enrichment: false,
  ...over
});

describe('generateFeedArtifact — JSON', () => {
  it('streams a valid JSON artifact with exact item_count, sources, tags, normalized value', async () => {
    const rows = [
      { id: 1, observable: 'Evil.COM', observable_type: 'domain', confidence: 'high', category: 'malware', created_at: '2026-08-07T00:00:00Z', ioc_source_id: null, source_name: 'x', recency_ts: '2026-08-09T00:00:00Z' },
      { id: 2, observable: 'bad.com', observable_type: 'domain', confidence: 'low', category: null, created_at: '2026-08-01T00:00:00Z', ioc_source_id: null, source_name: 'y', recency_ts: '2026-08-08T00:00:00Z' }
    ];
    const db = mockDb(rows, {
      tags: { 1: ['c2', 'C2'] },
      sources: { 1: [{ feed_key: 'threatfox', feed_name: 'ThreatFox', first_seen_in_feed: '2026-08-05T00:00:00Z', last_seen_in_feed: '2026-08-09T00:00:00Z' }] }
    });
    const art = await generateFeedArtifact(db, feedBase(), 'all', { formatTypes: ['domain'], maxItems: null, cfg: cfg() });
    assert.equal(art.itemCount, 2);
    const parsed = JSON.parse(fs.readFileSync(art.absolutePath, 'utf8'));
    assert.equal(parsed.schema_version, '1.0');
    assert.equal(parsed.feed.item_count, 2);
    assert.equal(parsed.items.length, 2);
    const evil = parsed.items.find((i) => i.value === 'evil.com'); // normalized lowercase
    assert.ok(evil);
    assert.deepEqual(evil.sources.map((x) => x.feed_key), ['threatfox']);
    assert.deepEqual(evil.classification.tags, ['c2']); // dedup
    assert.equal(evil.timestamps.imported_at, '2026-08-07T00:00:00.000Z');
    assert.equal(fs.existsSync(`${art.absolutePath}.part`), false);
    assert.equal(fs.existsSync(`${art.absolutePath}.body`), false);
  });

  it('honors max_items and stops early (Node processes only the cap)', async () => {
    const rows = Array.from({ length: 20 }, (_, i) => ({ id: i + 1, observable: `d${i}.com`, observable_type: 'domain', confidence: 'medium', category: null, created_at: '2026-08-01T00:00:00Z', ioc_source_id: null, source_name: 's', recency_ts: `2026-08-0${(i % 9) + 1}T00:00:00Z` }));
    const art = await generateFeedArtifact(mockDb(rows), feedBase({ max_items: 5 }), 'all', { formatTypes: ['domain'], maxItems: 5, cfg: cfg() });
    assert.equal(art.itemCount, 5);
    assert.equal(JSON.parse(fs.readFileSync(art.absolutePath, 'utf8')).items.length, 5);
  });

  it('drops private/reserved IPs (same as in-memory path)', async () => {
    const rows = [
      { id: 1, observable: '8.8.8.8', observable_type: 'ip', confidence: 'high', category: null, created_at: '2026-08-01T00:00:00Z', ioc_source_id: null, source_name: 's', recency_ts: '2026-08-09T00:00:00Z' },
      { id: 2, observable: '10.0.0.1', observable_type: 'ip', confidence: 'high', category: null, created_at: '2026-08-01T00:00:00Z', ioc_source_id: null, source_name: 's', recency_ts: '2026-08-08T00:00:00Z' }
    ];
    const art = await generateFeedArtifact(mockDb(rows), feedBase({ ioc_types: ['ip'] }), 'all', { formatTypes: ['ip'], maxItems: null, cfg: cfg() });
    const parsed = JSON.parse(fs.readFileSync(art.absolutePath, 'utf8'));
    assert.equal(art.itemCount, 1);
    assert.equal(parsed.items[0].value, '8.8.8.8');
  });

  it('streams canonical hash rows (sha256) without requiring a special fallback', async () => {
    const sha = 'a'.repeat(64);
    const rows = [
      { id: 10, observable: sha, observable_type: 'sha256', confidence: 'high', category: 'malware', created_at: '2026-08-07T00:00:00Z', ioc_source_id: null, source_name: 'mb', recency_ts: '2026-08-09T00:00:00Z' }
    ];
    const art = await generateFeedArtifact(
      mockDb(rows, { tags: { 10: ['malware'] }, sources: { 10: [{ feed_key: 'malwarebazaar', feed_name: 'MalwareBazaar', first_seen_in_feed: '2026-08-01T00:00:00Z', last_seen_in_feed: '2026-08-09T00:00:00Z' }] } }),
      feedBase({ ioc_types: ['hash'] }),
      'all',
      { formatTypes: ['hash'], maxItems: null, cfg: cfg() }
    );
    const parsed = JSON.parse(fs.readFileSync(art.absolutePath, 'utf8'));
    assert.equal(art.itemCount, 1);
    assert.equal(parsed.items[0].value, sha);
    assert.equal(parsed.items[0].type, 'sha256');
    assert.deepEqual(parsed.items[0].sources.map((s) => s.feed_key), ['malwarebazaar']);
  });
});

describe('generateFeedArtifact — duplicate observable sibling metadata', () => {
  it('aggregates sources+tags across sibling IOC rows (legacy parity)', async () => {
    // Cursor winner is row 1; row 2 is a sibling with the same lower(observable).
    const winner = {
      id: 1, observable: 'Evil.COM', observable_type: 'domain', confidence: 'high', category: 'malware',
      created_at: '2026-08-07T00:00:00Z', ioc_source_id: null, source_name: 'threatfox', recency_ts: '2026-08-09T00:00:00Z'
    };
    const siblings = [
      { id: 1, observable: 'Evil.COM', observable_type: 'domain', created_at: '2026-08-07T00:00:00Z', ioc_source_id: null },
      { id: 2, observable: 'evil.com', observable_type: 'domain', created_at: '2026-08-01T00:00:00Z', ioc_source_id: null }
    ];
    const db = mockDb([winner], {
      siblings,
      sources: {
        1: [{ feed_key: 'threatfox', feed_name: 'ThreatFox', first_seen_in_feed: '2026-08-05T00:00:00Z', last_seen_in_feed: '2026-08-09T00:00:00Z' }],
        2: [{ feed_key: 'otx', feed_name: 'OTX', first_seen_in_feed: '2026-08-02T00:00:00Z', last_seen_in_feed: '2026-08-08T00:00:00Z' }]
      },
      tags: {
        1: ['c2'],
        2: ['phishing']
      }
    });
    const art = await generateFeedArtifact(db, feedBase(), 'all', { formatTypes: ['domain'], maxItems: null, cfg: cfg() });
    const parsed = JSON.parse(fs.readFileSync(art.absolutePath, 'utf8'));
    assert.equal(parsed.items.length, 1);
    const item = parsed.items[0];
    assert.equal(item.value, 'evil.com');
    assert.deepEqual(item.sources.map((s) => s.feed_key), ['otx', 'threatfox']); // sorted, both present
    assert.deepEqual(item.classification.tags, ['c2', 'phishing']);
    // imported_at = MIN(sibling created_at)
    assert.equal(item.timestamps.imported_at, '2026-08-01T00:00:00.000Z');
    assert.equal(item.timestamps.first_seen_in_source, '2026-08-02T00:00:00.000Z');
    assert.equal(item.timestamps.last_confirmed_in_source, '2026-08-09T00:00:00.000Z');
    // classification/confidence come from the selected canonical row
    assert.equal(item.classification.category, 'malware');
    assert.equal(item.classification.confidence, 100);
  });

  it('matches legacy buildFeedContent item semantics for the same fixture', async () => {
    const winnerRow = {
      observable: 'evil.com', observable_type: 'domain', confidence: 'high', category: 'malware',
      source_name: 'threatfox', recency_ts: '2026-08-09T00:00:00Z'
    };
    // Legacy metadata path (keyed by lower(observable)+type) already aggregates siblings.
    const legacyDb = {
      async query(sql) {
        const s = String(sql).replace(/\s+/g, ' ');
        if (s.includes('FROM ioc_items i LEFT JOIN ioc_feed_memberships m')) {
          return { rows: [{ obs: 'evil.com', otype: 'domain', imported_at: '2026-08-01T00:00:00Z', first_seen_in_source: '2026-08-02T00:00:00Z', last_confirmed_in_source: '2026-08-09T00:00:00Z' }] };
        }
        if (s.includes('FROM ioc_feed_memberships m JOIN ioc_items i')) {
          return { rows: [
            { obs: 'evil.com', otype: 'domain', feed_key: 'threatfox', feed_name: 'ThreatFox', first_seen_in_source: '2026-08-05T00:00:00Z', last_confirmed_in_source: '2026-08-09T00:00:00Z' },
            { obs: 'evil.com', otype: 'domain', feed_key: 'otx', feed_name: 'OTX', first_seen_in_source: '2026-08-02T00:00:00Z', last_confirmed_in_source: '2026-08-08T00:00:00Z' }
          ] };
        }
        if (s.includes('FROM ioc_items i LEFT JOIN ioc_sources s')) return { rows: [] };
        if (s.includes('FROM ioc_tags it')) {
          return { rows: [
            { obs: 'evil.com', otype: 'domain', tag_name: 'c2' },
            { obs: 'evil.com', otype: 'domain', tag_name: 'phishing' }
          ] };
        }
        return { rows: [] };
      }
    };
    const legacy = JSON.parse((await buildFeedContent(
      legacyDb,
      { name: 'Test', format: 'json', include_source_metadata: true, include_classification: true, include_enrichment: false },
      [winnerRow],
      ['domain'],
      null
    )).content).items[0];

    const winner = {
      id: 1, observable: 'evil.com', observable_type: 'domain', confidence: 'high', category: 'malware',
      created_at: '2026-08-07T00:00:00Z', ioc_source_id: null, source_name: 'threatfox', recency_ts: '2026-08-09T00:00:00Z'
    };
    const streamDb = mockDb([winner], {
      siblings: [
        { id: 1, observable: 'evil.com', observable_type: 'domain', created_at: '2026-08-07T00:00:00Z' },
        { id: 2, observable: 'evil.com', observable_type: 'domain', created_at: '2026-08-01T00:00:00Z' }
      ],
      sources: {
        1: [{ feed_key: 'threatfox', feed_name: 'ThreatFox', first_seen_in_feed: '2026-08-05T00:00:00Z', last_seen_in_feed: '2026-08-09T00:00:00Z' }],
        2: [{ feed_key: 'otx', feed_name: 'OTX', first_seen_in_feed: '2026-08-02T00:00:00Z', last_seen_in_feed: '2026-08-08T00:00:00Z' }]
      },
      tags: { 1: ['c2'], 2: ['phishing'] }
    });
    const art = await generateFeedArtifact(streamDb, feedBase({ name: 'Test' }), 'all', { formatTypes: ['domain'], maxItems: null, cfg: cfg() });
    const streamed = JSON.parse(fs.readFileSync(art.absolutePath, 'utf8')).items[0];

    // Compare normalized public fields (ignore envelope generated_at).
    const pick = (it) => ({
      value: it.value,
      type: it.type,
      sources: it.sources,
      classification: it.classification,
      timestamps: it.timestamps
    });
    assert.deepEqual(pick(streamed), pick(legacy));
    // Sanity: normalizer would collapse duplicate sources if re-fed.
    assert.deepEqual(
      normalizePublishedIoc(
        { value: streamed.value, observable_type: 'domain', category: 'malware', confidence: 'high' },
        { sources: [...streamed.sources, ...streamed.sources], tags: [...streamed.classification.tags, 'C2'], imported_at: streamed.timestamps.imported_at, first_seen_in_source: streamed.timestamps.first_seen_in_source, last_confirmed_in_source: streamed.timestamps.last_confirmed_in_source },
        { includeSourceMetadata: true, includeClassification: true, includeEnrichment: false }
      ).sources,
      streamed.sources
    );
  });
});

describe('generateFeedArtifact — TXT', () => {
  it('writes newline-terminated values, recency order preserved from SQL', async () => {
    const rows = [
      { id: 1, observable: 'a.com', observable_type: 'domain', confidence: 'high', category: null, created_at: '2026-08-01T00:00:00Z', ioc_source_id: null, source_name: 's', recency_ts: '2026-08-09T00:00:00Z' },
      { id: 2, observable: 'b.com', observable_type: 'domain', confidence: 'low', category: null, created_at: '2026-08-01T00:00:00Z', ioc_source_id: null, source_name: 's', recency_ts: '2026-08-08T00:00:00Z' }
    ];
    const art = await generateFeedArtifact(mockDb(rows), feedBase({ format: 'txt' }), 'all', { formatTypes: ['domain'], maxItems: null, cfg: cfg() });
    assert.equal(fs.readFileSync(art.absolutePath, 'utf8'), 'a.com\nb.com\n');
    assert.equal(art.itemCount, 2);
  });
});

describe('generateEmptyFeedArtifact', () => {
  it('produces a valid empty JSON artifact', async () => {
    const art = await generateEmptyFeedArtifact(feedBase(), { cfg: cfg() });
    const parsed = JSON.parse(fs.readFileSync(art.absolutePath, 'utf8'));
    assert.deepEqual(parsed.items, []);
    assert.equal(parsed.feed.item_count, 0);
    assert.equal(art.itemCount, 0);
  });
  it('produces a valid empty TXT artifact', async () => {
    const art = await generateEmptyFeedArtifact(feedBase({ format: 'txt' }), { cfg: cfg() });
    assert.equal(fs.readFileSync(art.absolutePath, 'utf8'), '');
  });
  it('dual empty produces both artifacts with shared generationId', async () => {
    const art = await generateEmptyFeedArtifact(
      feedBase({ formats: ['txt', 'json'] }),
      { cfg: cfg() }
    );
    assert.equal(art.artifacts.length, 2);
    assert.equal(art.artifacts[0].generationId, art.artifacts[1].generationId);
    assert.equal(art.itemCount, 0);
  });
  it('produces a valid empty STIX bundle', async () => {
    const art = await generateEmptyFeedArtifact(feedBase({ formats: ['stix'], slug: 'empty-stix' }), { cfg: cfg() });
    const parsed = JSON.parse(fs.readFileSync(art.absolutePath, 'utf8'));
    assert.equal(parsed.type, 'bundle');
    assert.equal(parsed.spec_version, '2.1');
    assert.deepEqual(parsed.objects, []);
    assert.equal(art.itemCount, 0);
  });
});

describe('generateFeedArtifact — dual format one-pass', () => {
  it('writes TXT+JSON from a single cursor (one DECLARE)', async () => {
    const rows = [
      { id: 1, observable: 'a.com', observable_type: 'domain', confidence: 'high', category: null, created_at: '2026-08-01T00:00:00Z', ioc_source_id: null, source_name: 's', recency_ts: '2026-08-09T00:00:00Z' },
      { id: 2, observable: 'b.com', observable_type: 'domain', confidence: 'low', category: null, created_at: '2026-08-01T00:00:00Z', ioc_source_id: null, source_name: 's', recency_ts: '2026-08-08T00:00:00Z' }
    ];
    const db = mockDb(rows);
    const art = await generateFeedArtifact(
      db,
      feedBase({ formats: ['txt', 'json'], format: undefined }),
      'all',
      { formatTypes: ['domain'], maxItems: null, cfg: cfg() }
    );
    assert.equal(art.artifacts.length, 2);
    assert.equal(art.itemCount, 2);
    assert.equal(art.artifacts[0].itemCount, art.artifacts[1].itemCount);
    assert.equal(art.artifacts[0].generationId, art.artifacts[1].generationId);
    const declares = db.log.filter((l) => l.startsWith('DECLARE'));
    assert.equal(declares.length, 1, 'dual format must use one base cursor');
    const txtPath = art.artifacts.find((a) => a.format === 'txt').absolutePath;
    const jsonPath = art.artifacts.find((a) => a.format === 'json').absolutePath;
    assert.equal(fs.readFileSync(txtPath, 'utf8').trim().split('\n').length, 2);
    assert.equal(JSON.parse(fs.readFileSync(jsonPath, 'utf8')).feed.item_count, 2);
  });

  it('writes STIX bundle alongside TXT without changing TXT bytes', async () => {
    const rows = [
      { id: 1, observable: 'a.com', observable_type: 'domain', confidence: 'high', category: null, created_at: '2026-08-01T00:00:00Z', ioc_source_id: null, source_name: 's', recency_ts: '2026-08-09T00:00:00Z' },
      { id: 2, observable: 'b.com', observable_type: 'domain', confidence: 'low', category: null, created_at: '2026-08-01T00:00:00Z', ioc_source_id: null, source_name: 's', recency_ts: '2026-08-08T00:00:00Z' }
    ];
    const db = mockDb(rows);
    const art = await generateFeedArtifact(
      db,
      feedBase({ formats: ['txt', 'stix'], format: undefined, slug: 'stix-test' }),
      'all',
      { formatTypes: ['domain'], maxItems: null, cfg: cfg() }
    );
    assert.equal(art.artifacts.length, 2);
    const txtPath = art.artifacts.find((a) => a.format === 'txt').absolutePath;
    const stixPath = art.artifacts.find((a) => a.format === 'stix').absolutePath;
    assert.equal(fs.readFileSync(txtPath, 'utf8'), 'a.com\nb.com\n');
    const bundle = JSON.parse(fs.readFileSync(stixPath, 'utf8'));
    assert.equal(bundle.type, 'bundle');
    assert.equal(bundle.spec_version, '2.1');
    assert.equal(bundle.objects.length, 2);
    assert.equal(bundle.objects[0].type, 'indicator');
    assert.equal(bundle.objects[0].pattern, "[domain-name:value = 'a.com']");
    assert.equal(bundle.objects[1].pattern, "[domain-name:value = 'b.com']");
  });
});

describe('generateFeedArtifact — atomicity', () => {
  it('mid-stream failure rolls back, leaves no artifact/.part, and preserves the previous file', async () => {
    // Isolated feed id so this dir contains only our pre-existing artifact.
    const feedDir = path.join(dir, '4242');
    fs.mkdirSync(feedDir, { recursive: true });
    const prev = path.join(feedDir, 'previous.json');
    fs.writeFileSync(prev, '{"prev":true}');

    const rows = [{ id: 1, observable: 'a.com', observable_type: 'domain', confidence: 'high', category: null, created_at: '2026-08-01T00:00:00Z', ioc_source_id: null, source_name: 's', recency_ts: '2026-08-09T00:00:00Z' }];
    const db = mockDb(rows, { failOn: 'FROM ioc_tags it' }); // enrichment throws mid-stream

    await assert.rejects(
      generateFeedArtifact(db, feedBase({ id: 4242 }), 'all', { formatTypes: ['domain'], maxItems: null, cfg: cfg() }),
      /injected failure/
    );
    assert.ok(db.log.some((l) => l.startsWith('ROLLBACK')));
    // No new final/.part/.body leaked; previous artifact intact.
    const remaining = fs.readdirSync(feedDir);
    assert.deepEqual(remaining, ['previous.json']);
    assert.equal(fs.readFileSync(prev, 'utf8'), '{"prev":true}');
  });

  it('hash TXT+JSON+STIX force rebuild survives concurrent retention sweep of zero-byte .body', async () => {
    // Reproduces production ENOENT: cleanupSupersededArtifacts unlinked in-flight
    // *.json.body while the write FD was still open; pipeFileInto then failed.
    const { cleanupSupersededArtifacts } = await import('./publishedFeedArtifact/store.js');
    const feedId = 2525;
    const sha = (i) => i.toString(16).padStart(64, '0');
    const rows = Array.from({ length: 120 }, (_, i) => ({
      id: i + 1,
      observable: sha(i + 1),
      observable_type: 'sha256',
      confidence: 'high',
      category: 'malware',
      created_at: '2026-08-01T00:00:00Z',
      ioc_source_id: null,
      source_name: 'mb',
      recency_ts: '2026-08-09T00:00:00Z'
    }));
    const base = mockDb(rows);
    let swept = false;
    const db = {
      log: base.log,
      async query(sql, params) {
        const s = String(sql).replace(/\s+/g, ' ');
        if (s.startsWith('FETCH FORWARD') && !swept) {
          swept = true;
          // Writers already opened zero-byte .body files; mimic scheduler retention.
          await cleanupSupersededArtifacts(cfg(), feedId, [`${feedId}/stale-old.json`]);
        }
        return base.query(sql, params);
      }
    };
    const art = await generateFeedArtifact(
      db,
      feedBase({
        id: feedId,
        name: 'hash',
        ioc_types: ['hash'],
        formats: ['txt', 'json', 'stix'],
        format: undefined,
        slug: 'hash-enoent-probe'
      }),
      'all',
      { formatTypes: ['hash'], maxItems: null, cfg: cfg() }
    );
    assert.equal(art.itemCount, 120);
    assert.equal(art.artifacts.length, 3);
    for (const a of art.artifacts) {
      assert.ok(fs.existsSync(a.absolutePath), `missing ${a.format}`);
      assert.equal(fs.existsSync(`${a.absolutePath}.body`), false);
      assert.equal(fs.existsSync(`${a.absolutePath}.part`), false);
    }
    assert.ok(swept, 'retention sweep must have run mid-generation');
  });
});
