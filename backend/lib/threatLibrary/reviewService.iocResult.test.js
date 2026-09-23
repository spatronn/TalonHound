/**
 * Create IOCs result feedback: existing-only selections create nothing and
 * write nothing on preview; mixed selections create only the new rows; the
 * report detail resolves the linked IOC's public id by exact primary key.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { applyCandidateReviewActions } from './reviewService.js';
import { loadMatchedIocPublicIds } from './store.js';

const report = { id: 9, public_id: 'rep-1', analysis_status: 'review_required', source_url: null };

function fakePool(candidates) {
  const writes = [];
  return {
    writes,
    async query(sql, params) {
      if (/FROM threat_reports WHERE id = \$1/.test(sql) && /^\s*SELECT/i.test(sql)) return { rows: [report] };
      if (/FROM threat_report_candidates/.test(sql) && /^\s*SELECT/i.test(sql)) {
        const ids = Array.isArray(params?.[1]) ? params[1].map(Number) : null;
        return { rows: ids ? candidates.filter((c) => ids.includes(Number(c.id))) : candidates };
      }
      if (/FROM ioc_sources WHERE name/.test(sql)) return { rows: [{ id: 4 }] };
      writes.push({ sql, params });
      return { rows: [] };
    }
  };
}

function approved(id, overrides = {}) {
  return {
    id,
    candidate_type: 'sha256',
    original_value: `${id}`.padStart(64, 'a'),
    normalized_value: `${id}`.padStart(64, 'a'),
    assessment: 'malicious',
    review_status: 'approved',
    match_state: 'new',
    matched_ioc_id: null,
    confidence: 0.9,
    role: 'payload',
    is_ioc: true,
    evidence: {},
    ...overrides
  };
}

const existing = (id, iocId) => approved(id, { matched_ioc_id: iocId, match_state: 'existing', matched_ioc_observable_type: 'sha256' });

test('existing-only selection: preview reports 0 createable, 4 existing, and writes nothing', async () => {
  const candidates = [existing(1, 101), existing(2, 102), existing(3, 103), existing(4, 104)];
  const pool = fakePool(candidates);
  const result = await applyCandidateReviewActions(pool, 9, { action: 'create_iocs', candidateIds: [1, 2, 3, 4], confirm: false });
  assert.equal(result.ok, true);
  assert.equal(result.preview, true);
  assert.equal(result.summary.selected, 4);
  assert.equal(result.summary.eligible, 0);
  assert.equal(result.summary.already_existing, 4);
  assert.deepEqual(result.results.map((r) => [r.outcome, r.ioc_id]), [
    ['already_existing', 101], ['already_existing', 102], ['already_existing', 103], ['already_existing', 104]
  ]);
  assert.equal(pool.writes.length, 0, 'preview never mutates');
});

test('existing-only selection never creates a duplicate IOC even if confirmed directly', async () => {
  const candidates = [existing(1, 101), existing(2, 102), existing(3, 103), existing(4, 104)];
  const pool = fakePool(candidates);
  let creates = 0;
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [1, 2, 3, 4],
    confirm: true,
    createIoc: async () => { creates += 1; return { status: 201, body: { id: 999 } }; },
    findExistingIoc: async () => null
  });
  assert.equal(creates, 0);
  assert.equal(result.summary.created, 0);
  assert.equal(result.summary.already_existing, 4);
});

test('mixed selection (2 new + 3 existing): only the 2 new rows are created, 3 existing are not duplicated', async () => {
  const candidates = [approved(1), approved(2), existing(3, 103), existing(4, 104), existing(5, 105)];
  const pool = fakePool(candidates);
  const preview = await applyCandidateReviewActions(pool, 9, { action: 'create_iocs', candidateIds: [1, 2, 3, 4, 5], confirm: false });
  assert.equal(preview.summary.eligible, 2);
  assert.equal(preview.summary.already_existing, 3);

  const created = [];
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [1, 2, 3, 4, 5],
    confirm: true,
    createIoc: async (_pool, body) => {
      created.push(body.observable);
      return { status: 201, body: { id: 500 + created.length, public_id: `ioc-${created.length}`, observable_type: 'sha256' } };
    },
    findExistingIoc: async () => null
  });
  assert.equal(created.length, 2);
  assert.deepEqual(created, [candidates[0].normalized_value, candidates[1].normalized_value]);
  assert.equal(result.summary.created, 2);
  assert.equal(result.summary.already_existing, 3);
  const outcome = Object.fromEntries(result.results.map((r) => [r.candidate_id, [r.outcome, r.ioc_id]]));
  assert.deepEqual(outcome, {
    1: ['created', 501],
    2: ['created', 502],
    3: ['already_existing', 103],
    4: ['already_existing', 104],
    5: ['already_existing', 105]
  });
});

test('new-only selection: create succeeds and records Created', async () => {
  const pool = fakePool([approved(1)]);
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [1],
    confirm: true,
    createIoc: async () => ({ status: 201, body: { id: 700, public_id: 'ioc-700', observable_type: 'sha256' } }),
    findExistingIoc: async () => null
  });
  assert.equal(result.summary.created, 1);
  assert.deepEqual(result.results, [{ candidate_id: 1, outcome: 'created', ioc_id: 700 }]);
  const persisted = pool.writes.find((w) => /promotion_outcome = \$3/.test(w.sql));
  assert.equal(persisted.params[2], 'created');
  assert.equal(persisted.params[4], 700, 'the created IOC id is persisted as the candidate link');
});

test('loadMatchedIocPublicIds resolves by exact (observable_type, id) in one query; unknown ids stay null', async () => {
  const queries = [];
  const pool = {
    async query(sql, params) {
      queries.push({ sql, params });
      // Only 103 exists; 104 was deleted.
      return { rows: [{ observable_type: 'sha256', id: '103', public_id: 'ioc-pub-103' }] };
    }
  };
  const rows = [
    existing(3, 103),
    existing(4, 104),
    approved(1),
    // Same numeric id under another type must not borrow sha256's public id.
    approved(6, { candidate_type: 'domain', matched_ioc_id: 103, matched_ioc_observable_type: 'domain' })
  ];
  const resolve = await loadMatchedIocPublicIds(pool, rows);
  assert.equal(queries.length, 1);
  assert.match(queries[0].sql, /JOIN unnest\(\$1::text\[\], \$2::bigint\[\]\)/);
  assert.match(queries[0].sql, /i\.observable_type = m\.observable_type AND i\.id = m\.ioc_id/);
  assert.doesNotMatch(queries[0].sql, /observable\s*=/, 'never resolved by value');
  assert.deepEqual(queries[0].params, [['sha256', 'sha256', 'domain'], [103, 104, 103]]);
  assert.equal(resolve(rows[0]), 'ioc-pub-103');
  assert.equal(resolve(rows[1]), null);
  assert.equal(resolve(rows[2]), null);
  assert.equal(resolve(rows[3]), null);
});

test('loadMatchedIocPublicIds skips the query when nothing is linked', async () => {
  let calls = 0;
  const resolve = await loadMatchedIocPublicIds({ async query() { calls += 1; return { rows: [] }; } }, [approved(1)]);
  assert.equal(calls, 0);
  assert.equal(resolve(approved(1)), null);
});
