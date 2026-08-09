import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
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
  function makeQueryModePool(feedRow, capture) {
    const client = {
      async query(sql, params = []) {
        const s = String(sql);
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
