import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MANUAL_IOC_ORIGIN,
  clampRecentManualIocLimit,
  buildRecentManualIocsQuery,
  mapRecentManualIocRow,
  fetchRecentManualIocs
} from './recentManualIocs.js';

// ---------------------------------------------------------------------------
// Query builder: filtering / sorting / limiting must live in SQL.
// ---------------------------------------------------------------------------

test('buildRecentManualIocsQuery filters on the authoritative origin marker only', () => {
  const { text, values } = buildRecentManualIocsQuery(10);
  const normalized = text.replace(/\s+/g, ' ').trim();

  assert.match(normalized, /WHERE i\.created_origin = \$1/);
  assert.equal(values[0], MANUAL_IOC_ORIGIN);
  assert.equal(MANUAL_IOC_ORIGIN, 'manual_add');
  // Must NOT lean on a visible source label such as "Manual".
  assert.doesNotMatch(normalized, /source_name/i);
  assert.doesNotMatch(normalized, /'Manual'/);
});

test('buildRecentManualIocsQuery orders newest first and limits in SQL', () => {
  const { text, values } = buildRecentManualIocsQuery(10);
  const normalized = text.replace(/\s+/g, ' ').trim();

  assert.match(normalized, /ORDER BY i\.created_at DESC/);
  assert.match(normalized, /LIMIT \$2/);
  assert.equal(values[1], 10);
});

test('clampRecentManualIocLimit caps at 10 and defaults safely', () => {
  assert.equal(clampRecentManualIocLimit(50), 10);
  assert.equal(clampRecentManualIocLimit(10), 10);
  assert.equal(clampRecentManualIocLimit(3), 3);
  assert.equal(clampRecentManualIocLimit(0), 1);
  assert.equal(clampRecentManualIocLimit(-5), 1);
  assert.equal(clampRecentManualIocLimit(undefined), 10);
  assert.equal(clampRecentManualIocLimit('not-a-number'), 10);
});

test('mapRecentManualIocRow shapes rows and normalizes a missing creator', () => {
  const mapped = mapRecentManualIocRow({
    id: '42',
    public_id: 'pub-42',
    observable: '1.2.3.4',
    observable_type: 'ip',
    created_at: '2026-08-01T00:00:00.000Z',
    created_by_user_id: 'u-1',
    added_by: null
  });
  assert.deepEqual(mapped, {
    id: 42,
    public_id: 'pub-42',
    observable: '1.2.3.4',
    observable_type: 'ip',
    added_by: null,
    created_at: '2026-08-01T00:00:00.000Z'
  });
});

// ---------------------------------------------------------------------------
// Behavioral coverage via a fixture-driven fake pool that replicates the
// intended WHERE / ORDER BY / LIMIT + users join semantics of the SQL.
// ---------------------------------------------------------------------------

function createFakePool({ items = [], users = {} } = {}) {
  return {
    lastQuery: null,
    async query(text, values) {
      this.lastQuery = { text, values };
      const [origin, limit] = values;
      const rows = items
        .filter((it) => it.created_origin === origin)
        .sort((a, b) => {
          const at = new Date(a.created_at).getTime();
          const bt = new Date(b.created_at).getTime();
          if (bt !== at) return bt - at;
          return Number(b.id) - Number(a.id);
        })
        .slice(0, limit)
        .map((it) => ({
          id: it.id,
          public_id: it.public_id,
          observable: it.observable,
          observable_type: it.observable_type,
          created_at: it.created_at,
          created_by_user_id: it.created_by_user_id,
          added_by: users[it.created_by_user_id] || null
        }));
      return { rows };
    }
  };
}

const MIXED_FIXTURE = [
  // Feed-imported (customThreatFeedSync) — no origin marker.
  { id: 1, public_id: 'p1', observable: 'feed.example.com', observable_type: 'domain', created_at: '2026-08-03T10:00:00.000Z', created_origin: null, created_by_user_id: null },
  // External API ingestion — no origin marker.
  { id: 2, public_id: 'p2', observable: '9.9.9.9', observable_type: 'ip', created_at: '2026-08-03T09:00:00.000Z', created_origin: 'api_ingest', created_by_user_id: null },
  // Background worker / migration backfill — no manual marker.
  { id: 3, public_id: 'p3', observable: 'worker.example.com', observable_type: 'domain', created_at: '2026-08-03T08:00:00.000Z', created_origin: 'backfill', created_by_user_id: null },
  // Manually added via Add IOC.
  { id: 4, public_id: 'p4', observable: '5.5.5.5', observable_type: 'ip', created_at: '2026-08-01T00:00:00.000Z', created_origin: 'manual_add', created_by_user_id: 'user-analyst' },
  { id: 5, public_id: 'p5', observable: 'manual.example.com', observable_type: 'domain', created_at: '2026-08-02T00:00:00.000Z', created_origin: 'manual_add', created_by_user_id: 'user-admin' }
];

const USERS = { 'user-analyst': 'analyst@corp.local', 'user-admin': 'admin@corp.local' };

test('fetchRecentManualIocs excludes feed, API, and worker/backfill IOCs; includes only manual', async () => {
  const pool = createFakePool({ items: MIXED_FIXTURE, users: USERS });
  const result = await fetchRecentManualIocs(pool, { limit: 10 });

  const observables = result.map((r) => r.observable);
  assert.deepEqual(observables, ['manual.example.com', '5.5.5.5']);
  assert.ok(!observables.includes('feed.example.com'), 'feed IOC excluded');
  assert.ok(!observables.includes('9.9.9.9'), 'API-ingested IOC excluded');
  assert.ok(!observables.includes('worker.example.com'), 'worker/backfill IOC excluded');
  // The exclusion is enforced by the query itself, not the client.
  assert.equal(pool.lastQuery.values[0], MANUAL_IOC_ORIGIN);
});

test('fetchRecentManualIocs orders manual IOCs newest first', async () => {
  const pool = createFakePool({ items: MIXED_FIXTURE, users: USERS });
  const result = await fetchRecentManualIocs(pool, { limit: 10 });
  const times = result.map((r) => new Date(r.created_at).getTime());
  assert.deepEqual(times, [...times].sort((a, b) => b - a));
});

test('fetchRecentManualIocs returns at most 10 records even when more exist', async () => {
  const many = Array.from({ length: 15 }, (_, idx) => ({
    id: 100 + idx,
    public_id: `pm${idx}`,
    observable: `m${idx}.example.com`,
    observable_type: 'domain',
    created_at: new Date(Date.UTC(2026, 7, 1, 0, idx)).toISOString(),
    created_origin: 'manual_add',
    created_by_user_id: 'user-admin'
  }));
  const pool = createFakePool({ items: many, users: USERS });
  const result = await fetchRecentManualIocs(pool, { limit: 50 });
  assert.equal(result.length, 10);
  assert.equal(pool.lastQuery.values[1], 10, 'limit clamped to 10 in the query');
});

test('fetchRecentManualIocs surfaces the creating user as added_by', async () => {
  const pool = createFakePool({ items: MIXED_FIXTURE, users: USERS });
  const result = await fetchRecentManualIocs(pool, { limit: 10 });
  const byObservable = Object.fromEntries(result.map((r) => [r.observable, r.added_by]));
  assert.equal(byObservable['5.5.5.5'], 'analyst@corp.local');
  assert.equal(byObservable['manual.example.com'], 'admin@corp.local');
});

test('fetchRecentManualIocs returns an empty list when no manual IOCs exist', async () => {
  const feedOnly = MIXED_FIXTURE.filter((it) => it.created_origin !== 'manual_add');
  const pool = createFakePool({ items: feedOnly, users: USERS });
  const result = await fetchRecentManualIocs(pool, { limit: 10 });
  assert.deepEqual(result, []);
});
