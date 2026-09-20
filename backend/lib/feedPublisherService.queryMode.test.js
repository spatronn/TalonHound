import { describe, it, before, after, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  resolveFeedFilterMode,
  isQueryModeFeed,
  filtersHash,
  fetchQueryModeIocRows,
  fetchQueryModeFingerprint,
  generatePublishedFeedSnapshot,
  FEED_FILTER_MODES,
  QUERY_FEED_SNAPSHOT_KEY
} from './feedPublisherService.js';
import { parseSearchQuery, buildWhereClause } from './iocSearchDsl/index.js';

function isPublishedFeedSessionSetupQuery(sql) {
  const s = String(sql).trim();
  return s.startsWith('SET statement_timeout')
    || s.startsWith('SET lock_timeout')
    || s.startsWith('RESET statement_timeout')
    || s.startsWith('RESET lock_timeout');
}

function normalizeSql(sql) {
  return String(sql).replace(/\s+/g, ' ').trim();
}

describe('resolveFeedFilterMode', () => {
  it('defaults to basic for legacy rows with no filter_mode', () => {
    assert.equal(resolveFeedFilterMode({}), FEED_FILTER_MODES.BASIC);
    assert.equal(resolveFeedFilterMode({ filter_mode: null }), FEED_FILTER_MODES.BASIC);
  });

  it('is query only when filter_mode=query AND advanced_query is non-empty', () => {
    assert.equal(resolveFeedFilterMode({ filter_mode: 'query', advanced_query: 'ioc contains "x"' }), FEED_FILTER_MODES.QUERY);
    // filter_mode=query but empty query is not a usable query feed.
    assert.equal(resolveFeedFilterMode({ filter_mode: 'query', advanced_query: '' }), FEED_FILTER_MODES.BASIC);
  });

  it('a basic feed ignores any stored advanced_query', () => {
    const feed = { filter_mode: 'basic', advanced_query: 'source equals "USOM"' };
    assert.equal(isQueryModeFeed(feed), false);
  });
});

describe('filtersHash respects the active mode only', () => {
  it('basic feed hash is unaffected by advanced_query', () => {
    const a = filtersHash({ filter_mode: 'basic', ioc_types: ['ip'], advanced_query: null }, 'all');
    const b = filtersHash({ filter_mode: 'basic', ioc_types: ['ip'], advanced_query: 'ioc contains "x"' }, 'all');
    assert.equal(a, b);
  });

  it('query feed hash is unaffected by ioc_types / window / threat feeds', () => {
    const base = { filter_mode: 'query', advanced_query: 'ioc contains "x"' };
    const a = filtersHash({ ...base, ioc_types: ['ip'], include_feed_keys: null }, '1d');
    const b = filtersHash({ ...base, ioc_types: ['domain', 'url'], include_feed_keys: ['usom'] }, '7d');
    assert.equal(a, b);
    // But it does change with the query text.
    const c = filtersHash({ ...base, advanced_query: 'ioc contains "y"' }, 'all');
    assert.notEqual(a, c);
  });
});

describe('fetchQueryModeIocRows uses the canonical DSL predicate + safety filters', () => {
  it('SQL embeds buildWhereClause output and its params, ignoring ioc_types/window/threat feeds', async () => {
    const query = 'source equals "MalwareBazaar" AND type equals "domain"';
    const { sql: dslSql, params: dslParams } = buildWhereClause(parseSearchQuery(query).ast);

    let captured = { sql: '', params: [] };
    const pool = {
      async query(sql, params = []) {
        captured = { sql: normalizeSql(sql), params: [...params] };
        return { rows: [] };
      }
    };

    await fetchQueryModeIocRows(pool, {
      filter_mode: 'query',
      advanced_query: query,
      // Basic selectors present but must NOT reach the SQL for a query-mode feed.
      ioc_types: ['ip'],
      time_window: '1d',
      include_feed_keys: ['usom-trcert'],
      exclude_expired: true
    });

    // The exact compiled DSL predicate appears verbatim in the query-mode WHERE.
    assert.ok(captured.sql.includes(normalizeSql(dslSql)), 'DSL where clause is reused verbatim');
    // The DSL bound params lead the positional param list (same interpretation as IOC List).
    for (let i = 0; i < dslParams.length; i += 1) {
      assert.deepEqual(captured.params[i], dslParams[i]);
    }
    // Base-set selectors from Basic mode are absent.
    assert.doesNotMatch(captured.sql, /observable_type IN/);
    assert.doesNotMatch(captured.sql, /NOW\(\) - \$\d+::interval/);
    assert.ok(!captured.params.includes('usom-trcert'), 'threat feed keys not applied');
    // Suppressed IOCs excluded and expired safety filter applied.
    assert.match(captured.sql, /COALESCE\(i\.status, 'active'\) <> 'suppressed'/);
    assert.match(captured.sql, /COALESCE\(i\.status, 'active'\) = 'active'/);
  });

  it('applies Include Tags / Exclude false positives as post-filters in query mode', async () => {
    let captured = { sql: '', params: [] };
    const pool = {
      async query(sql, params = []) {
        captured = { sql: normalizeSql(sql), params: [...params] };
        return { rows: [] };
      }
    };
    await fetchQueryModeIocRows(pool, {
      filter_mode: 'query',
      advanced_query: 'ioc contains "example"',
      exclude_false_positive: true,
      exclude_expired: true,
      include_tags: ['mozi']
    });
    assert.match(captured.sql, /NOT ILIKE '%false%positive%'/);
    assert.match(captured.sql, /FROM ioc_tags it/);
    // Tag lists are bound as a single text[] param.
    assert.ok(captured.params.some((p) => Array.isArray(p) && p.includes('mozi')));
  });
});

describe('fetchQueryModeFingerprint', () => {
  it('counts distinct observables of the query result set', async () => {
    let captured = '';
    const pool = {
      async query(sql) {
        captured = normalizeSql(sql);
        return { rows: [{ item_count: 3, max_recency: null }] };
      }
    };
    const fp = await fetchQueryModeFingerprint(pool, {
      filter_mode: 'query',
      advanced_query: 'ioc contains "example"'
    });
    assert.equal(fp.itemCount, 3);
    assert.match(captured, /COUNT\(DISTINCT lower\(i\.observable\)\)/);
    assert.doesNotMatch(captured, /observable_type IN/);
  });
});

describe('generatePublishedFeedSnapshot in query mode', () => {
  let prevStreaming;

  before(() => {
    prevStreaming = process.env.PUBLISHED_FEED_STREAMING_ENABLED;
    process.env.PUBLISHED_FEED_STREAMING_ENABLED = 'false';
  });

  after(() => {
    if (prevStreaming == null) delete process.env.PUBLISHED_FEED_STREAMING_ENABLED;
    else process.env.PUBLISHED_FEED_STREAMING_ENABLED = prevStreaming;
  });

  function makeQueryModePool(feedRow, capture) {
    const client = {
      async query(sql, params = []) {
        const s = String(sql);
        if (isPublishedFeedSessionSetupQuery(s)) return { rows: [] };
        if (s.includes('pg_try_advisory_lock')) return { rows: [{ ok: true }] };
        if (s.includes('pg_advisory_unlock')) return { rows: [] };
        if (s.includes('FROM published_feeds WHERE id')) return { rows: [feedRow] };
        if (s.includes('COUNT(DISTINCT lower(i.observable))')) return { rows: [{ item_count: 1, max_recency: null }] };
        if (s.includes('DISTINCT ON (lower(i.observable))')) {
          return { rows: [{ observable: 'evil.example', observable_type: 'domain', confidence: 'high', category: null, source_name: 'X', recency_ts: new Date() }] };
        }
        if (s.includes('FROM published_feed_snapshots')) return { rows: [] };
        if (s === 'BEGIN' || s === 'COMMIT' || s === 'ROLLBACK') return { rows: [] };
        if (s.includes('pg_advisory_xact_lock')) return { rows: [] };
        if (s.includes('INSERT INTO published_feed_snapshots')) {
          capture.inserts.push({ sql: normalizeSql(s), params: [...params] });
          return { rows: [] };
        }
        if (s.includes('UPDATE published_feeds')) return { rows: [] };
        // Basic-mode-only helpers must NOT be reached in query mode.
        if (s.includes('FROM ioc_ip') || s.includes('FROM ioc_domain') || s.includes('FROM ioc_url') || s.includes('FROM ioc_file_hash')) {
          capture.watermarkHit = true;
          return { rows: [{ max_id: 0, max_ts: null, active_count: 0 }] };
        }
        if (s.includes('FROM integration_runs') || s.includes('FROM custom_threat_feed_runs')) return { rows: [{ latest_finished_at: null }] };
        if (s.includes('FROM integration_feeds') || s.includes('FROM ioc_sources') || s.includes('FROM custom_threat_feeds')) return { rows: [] };
        throw new Error(`unexpected: ${normalizeSql(s).slice(0, 120)}`);
      },
      release() {}
    };
    return { async connect() { return client; }, async query(sql, params) { return client.query(sql, params); } };
  }

  const baseFeedRow = {
    id: 55,
    name: 'adv',
    filter_mode: 'query',
    advanced_query: 'source equals "MalwareBazaar"',
    ioc_types: ['ip'],
    ioc_type: 'ip',
    time_window: '1d',
    max_items: null,
    exclude_false_positive: true,
    exclude_expired: true,
    include_feed_keys: null,
    include_tags: null,
    exclude_tags: null,
    min_confidence: null,
    updated_at: '2026-08-01T00:00:00.000Z',
    enabled: true,
    format: 'txt',
    refresh_interval_minutes: 15
  };

  it('generates a single query-keyed snapshot from the DSL result', async () => {
    const capture = { inserts: [], watermarkHit: false };
    const pool = makeQueryModePool(baseFeedRow, capture);
    const result = await generatePublishedFeedSnapshot(pool, 55, { force: true });
    assert.equal(result.feed_id, 55);
    assert.equal(result.results.length, 1, 'exactly one window-agnostic snapshot');
    assert.equal(result.results[0].window, 'all');
    assert.equal(result.results[0].item_count, 1);
    // Snapshot is keyed by the query sentinel, window "all".
    const insert = capture.inserts.at(-1);
    const paramsJson = JSON.parse(insert.params.find((p) => typeof p === 'string' && p.startsWith('{')));
    assert.equal(paramsJson.ioc_type, QUERY_FEED_SNAPSHOT_KEY);
    assert.equal(paramsJson.window, 'all');
    assert.equal(paramsJson.filter_mode, 'query');
    // The generated content is the DSL-selected domain.
    assert.equal(insert.params[3], 'evil.example\n');
  });
});

// ---------------------------------------------------------------------------
// Relative-date (rolling window) query feeds
// ---------------------------------------------------------------------------

describe('query-mode feed with a relative date literal (rolling window)', () => {
  const HOUR = 60 * 60 * 1000;
  const DAY = 24 * HOUR;
  const T0 = Date.UTC(2026, 8, 20, 12, 0, 0); // 2026-09-20T12:00:00Z
  const QUERY = 'ioc contains "raw.githubusercontent.com" AND created_at after "now-5d"';

  let prevStreaming;
  let prevIncremental;
  let prevAllow;
  before(() => {
    prevStreaming = process.env.PUBLISHED_FEED_STREAMING_ENABLED;
    prevIncremental = process.env.PUBLISHED_FEED_INCREMENTAL_ENABLED;
    prevAllow = process.env.PUBLISHED_FEED_INCREMENTAL_FEED_IDS;
    process.env.PUBLISHED_FEED_STREAMING_ENABLED = 'false';
    // Deliberately "enable" incremental for every feed: correctness must come from code,
    // not from the production allowlist.
    process.env.PUBLISHED_FEED_INCREMENTAL_ENABLED = 'true';
    delete process.env.PUBLISHED_FEED_INCREMENTAL_FEED_IDS;
  });
  after(() => {
    const restore = (k, v) => { if (v == null) delete process.env[k]; else process.env[k] = v; };
    restore('PUBLISHED_FEED_STREAMING_ENABLED', prevStreaming);
    restore('PUBLISHED_FEED_INCREMENTAL_ENABLED', prevIncremental);
    restore('PUBLISHED_FEED_INCREMENTAL_FEED_IDS', prevAllow);
  });
  afterEach(() => mock.timers.reset());

  // Extract the bound cutoff for `i.created_at > $N::timestamptz` from a compiled query.
  function createdAtCutoff(sql, params) {
    const m = /i\.created_at > \$(\d+)::timestamptz/.exec(sql);
    assert.ok(m, `expected a bound created_at cutoff in: ${normalizeSql(sql).slice(0, 200)}`);
    return new Date(params[Number(m[1]) - 1]);
  }

  /**
   * Minimal in-memory "database": one immutable IOC row and a snapshot store. The only
   * predicate it evaluates is the created_at cutoff bound by the DSL builder, so the
   * result set can change ONLY because the cutoff moved -- no IOC write ever happens.
   */
  function makeRollingWindowPool(feedRow, ioc, capture) {
    let snapshot = null;
    let nextId = 1;
    const client = {
      async query(sql, params = []) {
        const s = String(sql);
        if (isPublishedFeedSessionSetupQuery(s)) return { rows: [] };
        if (s.includes('pg_try_advisory_lock')) return { rows: [{ ok: true }] };
        if (s.includes('pg_advisory_unlock') || s.includes('pg_advisory_xact_lock')) return { rows: [] };
        if (s === 'BEGIN' || s === 'COMMIT' || s === 'ROLLBACK') return { rows: [] };
        if (s.includes('FROM published_feeds WHERE id')) return { rows: [feedRow] };
        if (s.includes('COUNT(DISTINCT lower(i.observable))')) {
          const cutoff = createdAtCutoff(s, params);
          capture.cutoffs.push(cutoff);
          const hit = ioc.created_at > cutoff;
          return { rows: [{ item_count: hit ? 1 : 0, max_recency: hit ? ioc.created_at : null }] };
        }
        if (s.includes('DISTINCT ON (lower(i.observable))')) {
          const cutoff = createdAtCutoff(s, params);
          capture.cutoffs.push(cutoff);
          return { rows: ioc.created_at > cutoff ? [{ ...ioc, recency_ts: ioc.created_at }] : [] };
        }
        if (s.includes('FROM published_feed_snapshots')) {
          return { rows: snapshot ? [{ ...snapshot }] : [] };
        }
        if (s.includes('INSERT INTO published_feed_snapshots')) {
          snapshot = {
            id: nextId++, item_count: params[1], content_hash: params[2], content: params[3],
            params: JSON.parse(params[4]), artifact_format: params[5], generated_at: new Date()
          };
          capture.writes.push({ kind: 'insert', item_count: params[1], content: params[3] });
          return { rows: [] };
        }
        if (s.includes('UPDATE published_feed_snapshots')) {
          // Content changed -> full row rewrite; identical content -> params refresh only.
          if (s.includes('content_hash = $3')) {
            snapshot = { ...snapshot, item_count: params[1], content_hash: params[2], content: params[3], params: JSON.parse(params[4]), generated_at: new Date() };
            capture.writes.push({ kind: 'update', item_count: params[1], content: params[3] });
          } else {
            snapshot = { ...snapshot, params: JSON.parse(params[1]) };
            capture.writes.push({ kind: 'params_only' });
          }
          return { rows: [] };
        }
        if (s.includes('UPDATE published_feeds')) return { rows: [] };
        if (s.includes('FROM ioc_ip') || s.includes('FROM ioc_domain') || s.includes('FROM ioc_url') || s.includes('FROM ioc_file_hash')) {
          return { rows: [{ max_id: 0, max_ts: null, active_count: 0 }] };
        }
        if (s.includes('FROM integration_runs') || s.includes('FROM custom_threat_feed_runs')) return { rows: [{ latest_finished_at: null }] };
        if (s.includes('FROM integration_feeds') || s.includes('FROM ioc_sources') || s.includes('FROM custom_threat_feeds')) return { rows: [] };
        // Any dirty-poll / projection query here would mean the incremental path was entered.
        if (s.includes('published_feed_items') || s.includes('published_feed_global_watermarks') || s.includes('published_feed_ioc_deletes')) {
          capture.incrementalHit = true;
          return { rows: [] };
        }
        throw new Error(`unexpected: ${normalizeSql(s).slice(0, 120)}`);
      },
      release() {}
    };
    return { async connect() { return client; }, async query(sql, params) { return client.query(sql, params); } };
  }

  const feedRow = {
    id: 15,
    name: 'Github_Hunting',
    filter_mode: 'query',
    advanced_query: QUERY,
    ioc_types: ['url'],
    ioc_type: 'url',
    time_window: 'all',
    max_items: null,
    exclude_false_positive: false,
    exclude_expired: false,
    include_feed_keys: null,
    include_tags: null,
    exclude_tags: null,
    min_confidence: null,
    updated_at: '2026-09-01T00:00:00.000Z',
    enabled: true,
    format: 'txt',
    formats: ['txt'],
    refresh_interval_minutes: 15,
    // Pretend a projection exists and is ready: the strongest temptation for the
    // incremental path. It must still be refused for a relative-date query.
    projection_status: 'ready'
  };

  it('ages an IOC out of the feed with ZERO IOC writes when the clock advances 2h past the 5d cutoff', async () => {
    mock.timers.enable({ apis: ['Date'], now: T0 });
    const ioc = Object.freeze({
      observable: 'https://raw.githubusercontent.com/x/y/payload.sh',
      observable_type: 'url',
      confidence: 'high',
      category: null,
      source_name: 'X',
      created_at: new Date(T0 - (4 * DAY + 23 * HOUR)) // imported 4d23h before T0
    });
    const capture = { cutoffs: [], writes: [], incrementalHit: false };
    const pool = makeRollingWindowPool(feedRow, ioc, capture);

    // T0: first generation (no prior snapshot). IOC is 4d23h old -> inside the window.
    const r0 = await generatePublishedFeedSnapshot(pool, 15, { force: false });
    assert.equal(r0.results.length, 1);
    assert.equal(r0.results[0].window, 'all');
    assert.equal(r0.results[0].skipped, undefined, `T0 must generate, got ${JSON.stringify(r0.results[0])}`);
    assert.equal(r0.results[0].item_count, 1);
    assert.equal(capture.writes.at(-1).content, `${ioc.observable}\n`);
    const t0Cutoffs = capture.cutoffs.splice(0);
    assert.ok(t0Cutoffs.length >= 1);
    for (const c of t0Cutoffs) assert.equal(c.toISOString(), new Date(T0 - 5 * DAY).toISOString());

    // T1 = T0 + 2h: nothing touched the IOC row; only the clock moved. IOC is now 5d1h old.
    mock.timers.setTime(T0 + 2 * HOUR);
    const r1 = await generatePublishedFeedSnapshot(pool, 15, { force: false });
    assert.equal(r1.results[0].skipped, undefined, `T1 must NOT be skipped as unchanged: ${JSON.stringify(r1.results[0])}`);
    assert.equal(r1.results[0].item_count, 0, 'IOC must have aged out');
    assert.equal(capture.writes.at(-1).content, '', 'published content is now empty');
    const t1Cutoffs = capture.cutoffs.splice(0);
    for (const c of t1Cutoffs) assert.equal(c.toISOString(), new Date(T0 + 2 * HOUR - 5 * DAY).toISOString());
    // Two executions -> two different bound cutoffs, same stored query text.
    assert.notEqual(t0Cutoffs[0].getTime(), t1Cutoffs[0].getTime());
    assert.equal(t1Cutoffs[0].getTime() - t0Cutoffs[0].getTime(), 2 * HOUR);

    // Never entered the dirty-row incremental machinery despite incremental being "on".
    assert.equal(capture.incrementalHit, false);

    // T2 = T1 + 1h, still nothing changed and the IOC is still out: fingerprint is stable,
    // so the unchanged-fingerprint skip may apply (no needless rewrite), but never via
    // the incremental path.
    mock.timers.setTime(T0 + 3 * HOUR);
    const r2 = await generatePublishedFeedSnapshot(pool, 15, { force: false });
    assert.equal(r2.results[0].item_count, 0);
    assert.equal(capture.incrementalHit, false);
  });

  it('the relative cutoff is evaluated at execution time (not at save time) via the stored normalized query', async () => {
    mock.timers.enable({ apis: ['Date'], now: T0 });
    const { normalizedQuery } = parseSearchQuery(QUERY);
    assert.equal(normalizedQuery, QUERY, 'normalized text keeps now-5d');
    // A feed row holding the normalized text compiles to a cutoff derived from the CURRENT clock.
    let captured = null;
    const pool = { async query(sql, params) { captured = { sql, params }; return { rows: [] }; } };
    await fetchQueryModeIocRows(pool, { filter_mode: 'query', advanced_query: normalizedQuery });
    assert.equal(createdAtCutoff(captured.sql, captured.params).toISOString(), new Date(T0 - 5 * DAY).toISOString());
    mock.timers.setTime(T0 + 7 * DAY);
    await fetchQueryModeIocRows(pool, { filter_mode: 'query', advanced_query: normalizedQuery });
    assert.equal(createdAtCutoff(captured.sql, captured.params).toISOString(), new Date(T0 + 2 * DAY).toISOString());
    // The column is compared bare against the bound constant (index-friendly).
    assert.match(normalizeSql(captured.sql), /i\.created_at > \$\d+::timestamptz/);
    assert.doesNotMatch(captured.sql, /NOW\(\) - /);
  });

  it('an absolute-date query feed is unaffected: same cutoff regardless of the clock', async () => {
    mock.timers.enable({ apis: ['Date'], now: T0 });
    let captured = null;
    const pool = { async query(sql, params) { captured = { sql, params }; return { rows: [] }; } };
    const feed = { filter_mode: 'query', advanced_query: 'ioc contains "raw.githubusercontent.com" AND created_at after "2026-09-15"' };
    await fetchQueryModeIocRows(pool, feed);
    const first = [...captured.params];
    mock.timers.setTime(T0 + 30 * DAY);
    await fetchQueryModeIocRows(pool, feed);
    assert.deepEqual(captured.params, first);
    assert.match(normalizeSql(captured.sql), /i\.created_at > \(\$\d+::timestamp AT TIME ZONE \$\d+\)/);
  });
});

describe('rolling-window query feed on the STREAMING path never uses projection-incremental refresh', () => {
  const HOUR = 60 * 60 * 1000;
  const DAY = 24 * HOUR;
  const T0 = Date.UTC(2026, 8, 20, 12, 0, 0);
  const QUERY = 'ioc contains "raw.githubusercontent.com" AND imported_at after "now-5d"';

  let dir;
  const saved = {};
  const ENV = ['PUBLISHED_FEED_STREAMING_ENABLED', 'PUBLISHED_FEED_INCREMENTAL_ENABLED', 'PUBLISHED_FEED_INCREMENTAL_FEED_IDS', 'PUBLISHED_FEED_STORAGE_DIR'];
  before(() => {
    for (const k of ENV) saved[k] = process.env[k];
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-rolling-'));
    process.env.PUBLISHED_FEED_STREAMING_ENABLED = 'true';
    process.env.PUBLISHED_FEED_INCREMENTAL_ENABLED = 'true';
    delete process.env.PUBLISHED_FEED_INCREMENTAL_FEED_IDS; // every feed allowed
    process.env.PUBLISHED_FEED_STORAGE_DIR = dir;
  });
  after(() => {
    for (const k of ENV) { if (saved[k] == null) delete process.env[k]; else process.env[k] = saved[k]; }
    fs.rmSync(dir, { recursive: true, force: true });
  });
  afterEach(() => mock.timers.reset());

  function cutoffFrom(sql, params) {
    const m = /i\.created_at > \$(\d+)::timestamptz/.exec(sql);
    assert.ok(m, `expected bound created_at cutoff in: ${normalizeSql(sql).slice(0, 200)}`);
    return new Date(params[Number(m[1]) - 1]);
  }

  function makeStreamingPool(feedRow, ioc, capture) {
    let snapshot = null;
    let cursorRows = [];
    let pos = 0;
    const client = {
      async query(sql, params = []) {
        const s = String(sql);
        const n = normalizeSql(s);
        if (isPublishedFeedSessionSetupQuery(s)) return { rows: [] };
        if (n.includes('pg_try_advisory_lock')) return { rows: [{ ok: true }] };
        if (n.includes('pg_advisory_unlock') || n.includes('pg_advisory_xact_lock')) return { rows: [] };
        if (n === 'BEGIN' || n === 'COMMIT' || n === 'ROLLBACK') return { rows: [] };
        if (n.includes('FROM published_feeds WHERE id')) return { rows: [feedRow] };
        // Incremental / projection machinery: must never be touched for this feed.
        if (n.includes('published_feed_items') || n.includes('published_feed_global_watermarks')
          || n.includes('published_feed_ioc_deletes') || n.includes('pf_proj_cur')) {
          capture.incrementalHit = true;
          return { rows: [] };
        }
        if (n.includes('COUNT(DISTINCT lower(i.observable))')) {
          const cutoff = cutoffFrom(s, params);
          capture.cutoffs.push(cutoff);
          const hit = ioc.created_at > cutoff;
          return { rows: [{ item_count: hit ? 1 : 0, max_recency: hit ? ioc.created_at : null }] };
        }
        if (n.startsWith('DECLARE pf_cur')) {
          const cutoff = cutoffFrom(s, params);
          capture.cutoffs.push(cutoff);
          cursorRows = ioc.created_at > cutoff ? [{ ...ioc, recency_ts: ioc.created_at }] : [];
          pos = 0;
          return { rows: [] };
        }
        if (n.startsWith('FETCH FORWARD')) {
          const k = Number(/FETCH FORWARD (\d+)/.exec(n)[1]);
          const slice = cursorRows.slice(pos, pos + k);
          pos += slice.length;
          return { rows: slice };
        }
        if (n.startsWith('CLOSE')) return { rows: [] };
        if (n.includes('FROM published_feed_snapshots')) return { rows: snapshot ? [{ ...snapshot }] : [] };
        if (n.includes('INSERT INTO published_feed_snapshots')) {
          if (n.includes("'failed'")) throw new Error(`generation failed: ${params[1]}`);
          snapshot = {
            id: 1, item_count: params[1], content_hash: params[2], params: JSON.parse(params[3]),
            storage_path: params[4], file_size: params[5], artifact_format: params[6], generated_at: new Date()
          };
          capture.writes.push({ kind: 'insert', item_count: params[1], storage_path: params[4] });
          return { rows: [] };
        }
        if (n.includes('UPDATE published_feed_snapshots')) {
          if (n.includes('storage_path = ')) {
            const idx = { itemCount: 1, hash: 2, params: 3, storage: 4 };
            snapshot = { ...snapshot, item_count: params[idx.itemCount], content_hash: params[idx.hash], params: JSON.parse(params[idx.params]), storage_path: params[idx.storage], generated_at: new Date() };
            capture.writes.push({ kind: 'update', item_count: params[idx.itemCount], storage_path: params[idx.storage] });
          } else {
            capture.writes.push({ kind: 'params_only' });
          }
          return { rows: [] };
        }
        if (n.includes('UPDATE published_feeds')) {
          if (n.includes('projection_status')) capture.projectionStateWrites.push(n.slice(0, 80));
          return { rows: [] };
        }
        if (n.includes('FROM ioc_ip') || n.includes('FROM ioc_domain') || n.includes('FROM ioc_url') || n.includes('FROM ioc_file_hash')) {
          return { rows: [{ max_id: 0, max_ts: null, active_count: 0 }] };
        }
        if (n.includes('FROM integration_runs') || n.includes('FROM custom_threat_feed_runs')) return { rows: [{ latest_finished_at: null }] };
        // Sibling/source/tag/enrichment/active-generation lookups: nothing to add.
        return { rows: [] };
      },
      release() {}
    };
    return { async connect() { return client; }, async query(sql, params) { return client.query(sql, params); } };
  }

  // Streams a real artifact through publishedFeedArtifact/store.js, whose finalizeStream fsyncs a
  // read handle — EPERM on Windows (same env limitation as publishedFeedStreamGenerator.test.js).
  // CI / production are Linux, where this runs.
  const WIN_SKIP = process.platform === 'win32' ? 'artifact fsync unsupported on win32' : false;

  it('full streaming re-evaluation every tick; IOC ages out with zero IOC writes; no dirty poll, no projection populate', { skip: WIN_SKIP }, async () => {
    mock.timers.enable({ apis: ['Date'], now: T0 });
    const ioc = Object.freeze({
      id: 901,
      observable: 'https://raw.githubusercontent.com/x/y/payload.sh',
      observable_type: 'url',
      confidence: 'high',
      category: null,
      source_name: 'X',
      ioc_source_id: null,
      created_at: new Date(T0 - (4 * DAY + 23 * HOUR))
    });
    const feedRow = {
      id: 15, name: 'Github_Hunting', filter_mode: 'query', advanced_query: QUERY,
      ioc_types: ['url'], ioc_type: 'url', time_window: 'all', max_items: null,
      exclude_false_positive: false, exclude_expired: false, include_feed_keys: null,
      include_tags: null, exclude_tags: null, min_confidence: null,
      updated_at: '2026-09-01T00:00:00.000Z', enabled: true, format: 'txt', formats: ['txt'],
      refresh_interval_minutes: 15,
      // A READY projection + incremental "on" for every feed is exactly the state in which
      // an ungated feed would take the dirty-poll path.
      projection_status: 'ready', projection_cutoff: new Date(T0 - HOUR).toISOString()
    };
    const capture = { cutoffs: [], writes: [], incrementalHit: false, projectionStateWrites: [] };
    const pool = makeStreamingPool(feedRow, ioc, capture);

    const r0 = await generatePublishedFeedSnapshot(pool, 15, { force: false });
    assert.equal(r0.results[0].skipped, undefined, JSON.stringify(r0.results[0]));
    assert.equal(r0.results[0].item_count, 1);
    assert.equal(r0.results[0].refresh_mode, 'full');
    const t0Cutoffs = capture.cutoffs.splice(0);
    for (const c of t0Cutoffs) assert.equal(c.toISOString(), new Date(T0 - 5 * DAY).toISOString());
    const art0 = capture.writes.at(-1);
    assert.equal(fs.readFileSync(path.join(dir, art0.storage_path), 'utf8'), `${ioc.observable}\n`);

    mock.timers.setTime(T0 + 2 * HOUR);
    const r1 = await generatePublishedFeedSnapshot(pool, 15, { force: false });
    assert.equal(r1.results[0].skipped, undefined, JSON.stringify(r1.results[0]));
    assert.equal(r1.results[0].item_count, 0, 'IOC aged out on the streaming path');
    assert.equal(r1.results[0].refresh_mode, 'full');
    const t1Cutoffs = capture.cutoffs.splice(0);
    for (const c of t1Cutoffs) assert.equal(c.toISOString(), new Date(T0 + 2 * HOUR - 5 * DAY).toISOString());
    const art1 = capture.writes.at(-1);
    assert.equal(fs.readFileSync(path.join(dir, art1.storage_path), 'utf8'), '');

    assert.equal(capture.incrementalHit, false, 'dirty poll / projection scan / projection populate must not run');
    assert.deepEqual(capture.projectionStateWrites, [], 'no bootstrap / projection state transitions');
  });
});
