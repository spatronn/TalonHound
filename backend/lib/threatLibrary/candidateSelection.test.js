/**
 * Across-pages indicator selection: filter parity with the review table,
 * exclusions, eligibility, stale scope tokens, and the existing explicit-id path.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { applyCandidateReviewActions } from './reviewService.js';
import {
  filterCandidatesForSelection,
  parseReviewSelection,
  selectionScopeToken
} from './candidateSelection.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const frontendCandidates = [
  path.resolve(here, '../../test-fixtures/candidateReview.frontend.js'),
  path.resolve(here, '../../../../frontend/src/components/threatLibrary/candidateReview.js'),
  '/opt/TalonHound/frontend/src/components/threatLibrary/candidateReview.js'
].filter((p) => existsSync(p));
if (!frontendCandidates.length) {
  throw new Error('frontend candidateReview.js not found for selection parity');
}
const frontend = await import(pathToFileURL(frontendCandidates[0]).href);

const report = { id: 9, public_id: 'rep-1', analysis_status: 'review_required', source_url: null };

function member(overrides = {}) {
  return {
    id: 1,
    report_id: 9,
    candidate_type: 'ip',
    original_value: '203.0.113.10',
    normalized_value: '203.0.113.10',
    assessment: 'malicious',
    review_status: 'pending',
    match_state: 'new',
    matched_ioc_id: null,
    is_ioc: true,
    confidence: 0.5,
    role: 'c2',
    evidence: {},
    updated_at: '2026-10-01T00:00:00.000Z',
    ...overrides
  };
}

function narrative(overrides = {}) {
  return member({
    id: 50,
    normalized_value: '198.51.100.50',
    original_value: '198.51.100.50',
    source_assertion: 'body_mention',
    evidence: {
      document_has_authoritative_scope: true,
      source_assertion: 'body_mention',
      occurrences: [{ zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }]
    },
    ...overrides
  });
}

function contextOnly(overrides = {}) {
  return member({
    id: 60,
    candidate_type: 'domain',
    normalized_value: 'example.com',
    original_value: 'example.com',
    assessment: 'context_only',
    match_state: 'context_only',
    review_status: 'context_only',
    ...overrides
  });
}

function selectionPool(candidates, { reportRow = report } = {}) {
  const writes = [];
  const queries = [];
  return {
    writes,
    queries,
    candidates,
    async query(sql, params) {
      queries.push({ sql, params });
      if (/FROM threat_reports WHERE id = \$1/.test(sql) && /^\s*SELECT/i.test(sql)) {
        return { rows: reportRow ? [reportRow] : [] };
      }
      if (/FROM ioc_sources WHERE name/.test(sql)) {
        return { rows: [{ id: 4 }] };
      }
      if (/FROM threat_report_candidates/.test(sql) && /^\s*SELECT/i.test(sql)) {
        const ids = Array.isArray(params?.[1]) ? params[1].map(Number) : null;
        const rows = ids ? candidates.filter((c) => ids.includes(Number(c.id))) : candidates;
        return { rows: rows.map((r) => ({ ...r })) };
      }
      const setClause = String(sql).split(/WHERE/i)[0];
      if (/SET review_status = 'approved'/.test(setClause) || /SET review_status = 'ignored'/.test(setClause) || /SET review_status = 'context_only'/.test(setClause)) {
        const ids = (params?.[1] || []).map(Number);
        const nextStatus = /SET review_status = 'ignored'/.test(setClause)
          ? 'ignored'
          : /SET review_status = 'context_only'/.test(setClause)
            ? 'context_only'
            : 'approved';
        for (const row of candidates) {
          if (ids.includes(Number(row.id))) {
            row.review_status = nextStatus;
            if (nextStatus === 'context_only') {
              row.assessment = 'context_only';
              row.match_state = 'context_only';
            }
            row.updated_at = '2026-10-02T00:00:00.000Z';
          }
        }
        writes.push({ sql, params });
        return { rows: [], rowCount: ids.length };
      }
      writes.push({ sql, params });
      return { rows: [], rowCount: Array.isArray(params?.[1]) ? params[1].length : 0 };
    }
  };
}

function allMatching(filters, extra = {}) {
  return {
    action: 'approve',
    selection: {
      mode: 'all_matching',
      filters,
      excluded_candidate_ids: extra.excluded || [],
      scope_token: extra.token
    },
    preview: extra.preview === true,
    confirm: extra.confirm === true,
    ...extra.opts
  };
}

const FILTERS = [
  { tab: 'needs_review', type: 'all', result: 'all', search: '' },
  { tab: 'indicators', type: 'ip', result: 'all', search: '' },
  { tab: 'all', type: 'all', result: 'all', search: '198.51' },
  { tab: 'context_only', type: 'domain', result: 'all', search: '' },
  { tab: 'new', type: 'all', result: 'not_created', search: '' },
  { tab: 'existing', type: 'all', result: 'already_existing', search: '' }
];

test('selection filters match the review table, including MODE A narrative rows', () => {
  const rows = [
    member({ id: 1, source_assertion: 'explicit_ioc', evidence: { document_has_authoritative_scope: true, source_assertion: 'explicit_ioc', occurrences: [{ zone: 'explicit_ioc_section', asserted: true }] } }),
    narrative({ id: 2 }),
    contextOnly({ id: 3 }),
    member({ id: 4, review_status: 'approved', match_state: 'existing', matched_ioc_id: 9, promotion_outcome: 'already_existing' }),
    member({ id: 5, candidate_type: 'domain', normalized_value: 'evil.example', original_value: 'evil.example' })
  ];
  for (const filters of FILTERS) {
    const fe = frontend.filterReviewCandidates(rows, {
      tab: filters.tab,
      q: filters.search,
      type: filters.type,
      result: filters.result
    }).map((c) => c.id).sort((a, b) => a - b);
    const be = filterCandidatesForSelection(rows, {
      mode: 'all_matching',
      filters,
      excludedIds: []
    }).map((c) => c.id).sort((a, b) => a - b);
    assert.deepEqual(be, fe, JSON.stringify(filters));
  }
  const needs = filterCandidatesForSelection(rows, {
    mode: 'all_matching',
    filters: { tab: 'needs_review', type: 'all', result: 'all', search: '' },
    excludedIds: [1]
  });
  assert.equal(needs.some((c) => c.id === 1), false);
  assert.equal(needs.some((c) => c.id === 2), false, 'MODE A narrative is not Needs Review');
});

test('malformed all-matching selection is rejected before any candidate read', async () => {
  const pool = selectionPool([member()]);
  const badTab = await applyCandidateReviewActions(pool, 9, {
    action: 'approve',
    selection: { mode: 'all_matching', filters: { tab: 'approved' } }
  });
  assert.equal(badTab.ok, false);
  assert.equal(badTab.status, 400);
  assert.equal(badTab.code, 'selection_malformed');
  const both = await applyCandidateReviewActions(pool, 9, {
    action: 'approve',
    candidateIds: [1],
    selection: { mode: 'all_matching', filters: { tab: 'needs_review', type: 'all', result: 'all', search: '' } }
  });
  assert.equal(both.code, 'selection_malformed');
  const mode = await applyCandidateReviewActions(pool, 9, {
    action: 'approve',
    selection: { mode: 'everything' }
  });
  assert.equal(mode.code, 'selection_malformed');
  const token = parseReviewSelection({
    selection: {
      mode: 'all_matching',
      filters: { tab: 'needs_review', type: 'all', result: 'all', search: '' },
      scope_token: 'not-a-token'
    }
  });
  assert.equal(token.ok, false);
  assert.equal(pool.writes.length, 0);
  assert.equal(pool.queries.some((q) => /threat_report_candidates/.test(q.sql)), false);
});

test('unknown report and a not-ready report reject all-matching without writing', async () => {
  const missing = selectionPool([member()], { reportRow: null });
  const gone = await applyCandidateReviewActions(missing, 9, allMatching({
    tab: 'needs_review', type: 'all', result: 'all', search: ''
  }, { preview: true }));
  assert.equal(gone.status, 404);
  const early = selectionPool([member()], { reportRow: { ...report, analysis_status: 'analyzing' } });
  const blocked = await applyCandidateReviewActions(early, 9, allMatching({
    tab: 'needs_review', type: 'all', result: 'all', search: ''
  }, { preview: true }));
  assert.equal(blocked.ok, false);
  assert.equal(early.writes.length, 0);
});

test('explicit candidate ids still update only those rows', async () => {
  const pool = selectionPool([
    member({ id: 1 }),
    member({ id: 2, normalized_value: '203.0.113.11', original_value: '203.0.113.11' }),
    member({ id: 3, normalized_value: '203.0.113.12', original_value: '203.0.113.12' })
  ]);
  const result = await applyCandidateReviewActions(pool, 9, { action: 'approve', candidateIds: [1, 3] });
  assert.equal(result.ok, true);
  const update = pool.writes.find((w) => /review_status = 'approved'/.test(w.sql));
  assert.deepEqual(update.params[1].map(Number).sort((a, b) => a - b), [1, 3]);
  assert.equal(pool.candidates.find((c) => c.id === 2).review_status, 'pending');
});

test('all-matching approve uses one set-based update, exclusions, and the report id', async () => {
  const rows = Array.from({ length: 1200 }, (_, i) => member({
    id: i + 1,
    normalized_value: `203.0.113.${(i % 200) + 1}`,
    original_value: `203.0.113.${(i % 200) + 1}`
  }));
  rows.push(narrative({ id: 5000 }));
  rows.push(contextOnly({ id: 5001 }));
  rows.push(member({ id: 5002, report_id: 10, normalized_value: '203.0.113.250', original_value: '203.0.113.250' }));
  const pool = selectionPool(rows);
  const filters = { tab: 'needs_review', type: 'all', result: 'all', search: '' };
  const preview = await applyCandidateReviewActions(pool, 9, allMatching(filters, { preview: true, excluded: [1, 2] }));
  assert.equal(preview.preview, true);
  assert.equal(preview.matching, 1198);
  assert.equal(preview.eligible, 1198);
  assert.equal(pool.writes.length, 0);
  const loads = pool.queries.filter((q) => /FROM threat_report_candidates/.test(q.sql) && /report_id = \$1/.test(q.sql) && !/ANY/.test(q.sql));
  assert.equal(loads.length, 1);
  assert.equal(loads[0].params[0], 9);

  const applied = await applyCandidateReviewActions(pool, 9, allMatching(filters, {
    excluded: [1, 2],
    token: preview.scope_token
  }));
  assert.equal(applied.ok, true);
  assert.equal(applied.updated, 1198);
  const updates = pool.writes.filter((w) => /review_status = 'approved'/.test(w.sql));
  assert.equal(updates.length, 1);
  const ids = updates[0].params[1].map(Number);
  assert.equal(ids.length, 1198);
  assert.equal(ids.includes(1), false);
  assert.equal(ids.includes(2), false);
  assert.equal(ids.includes(5000), false, 'MODE A narrative is not approved');
  assert.equal(ids.includes(5001), false, 'context-only is not approved');
  assert.equal(ids.includes(5002), false, 'another report is not approved');
  assert.equal(pool.candidates.find((c) => c.id === 5000).review_status, 'pending');
  assert.equal(pool.candidates.find((c) => c.id === 5000).source_assertion, 'body_mention');
  const setClause = updates[0].sql.split(/WHERE/i)[0];
  assert.match(setClause, /SET review_status = 'approved', updated_at = NOW\(\)/);
  assert.doesNotMatch(setClause, /source_assertion|assessment|match_state/);
});

test('all-matching on All does not turn MODE A narrative or context-only rows into indicators', async () => {
  const explicit = member({
    id: 1,
    source_assertion: 'explicit_ioc',
    evidence: {
      document_has_authoritative_scope: true,
      source_assertion: 'explicit_ioc',
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row' }]
    }
  });
  const story = narrative({ id: 2 });
  const ctx = contextOnly({ id: 3 });
  const pool = selectionPool([explicit, story, ctx]);
  const filters = { tab: 'all', type: 'all', result: 'all', search: '' };
  const preview = await applyCandidateReviewActions(pool, 9, allMatching(filters, { preview: true }));
  assert.equal(preview.matching, 3);
  assert.equal(preview.eligible, 1);
  assert.equal(preview.ineligible, 2);
  const applied = await applyCandidateReviewActions(pool, 9, allMatching(filters, { token: preview.scope_token }));
  assert.equal(applied.updated, 1);
  assert.equal(pool.candidates.find((c) => c.id === 2).review_status, 'pending');
  assert.equal(pool.candidates.find((c) => c.id === 3).assessment, 'context_only');
  const update = pool.writes.find((w) => /review_status = 'approved'/.test(w.sql));
  assert.deepEqual(update.params[1].map(Number), [1]);
});

test('MODE B narrative remains approvable when the document has no publisher IOC section', async () => {
  const row = member({
    id: 7,
    source_assertion: 'body_mention',
    evidence: {
      source_assertion: 'body_mention',
      document_has_authoritative_scope: false,
      occurrences: [{ zone: 'report_body', asserted: false, occurrence_kind: 'narrative_mention' }]
    }
  });
  const pool = selectionPool([row]);
  const filters = { tab: 'needs_review', type: 'all', result: 'all', search: '' };
  const preview = await applyCandidateReviewActions(pool, 9, allMatching(filters, { preview: true }));
  assert.equal(preview.eligible, 1);
  const applied = await applyCandidateReviewActions(pool, 9, allMatching(filters, { token: preview.scope_token }));
  assert.equal(applied.ok, true);
  assert.equal(pool.candidates[0].review_status, 'approved');
});

test('a stale scope token conflicts and does not write; a fresh token can be retried', async () => {
  const rows = [member({ id: 1 }), member({ id: 2, normalized_value: '203.0.113.20', original_value: '203.0.113.20' })];
  const pool = selectionPool(rows);
  const filters = { tab: 'needs_review', type: 'all', result: 'all', search: '' };
  const preview = await applyCandidateReviewActions(pool, 9, allMatching(filters, { preview: true }));
  rows[0].updated_at = '2026-10-03T00:00:00.000Z';
  rows[0].review_status = 'ignored';
  const conflict = await applyCandidateReviewActions(pool, 9, allMatching(filters, { token: preview.scope_token }));
  assert.equal(conflict.ok, false);
  assert.equal(conflict.status, 409);
  assert.equal(conflict.code, 'selection_conflict');
  assert.notEqual(conflict.scope_token, preview.scope_token);
  assert.equal(pool.writes.length, 0);
  assert.equal(rows[1].review_status, 'pending');
  const retried = await applyCandidateReviewActions(pool, 9, allMatching(filters, { token: conflict.scope_token }));
  assert.equal(retried.ok, true);
  assert.equal(pool.writes.filter((w) => /review_status = 'approved'/.test(w.sql)).length, 1);
  const ids = pool.writes.find((w) => /review_status = 'approved'/.test(w.sql)).params[1].map(Number);
  assert.deepEqual(ids, [2], 'the ignored row is no longer in Needs Review');
});

test('committing all-matching without a scope token is rejected', async () => {
  const pool = selectionPool([member()]);
  const result = await applyCandidateReviewActions(pool, 9, allMatching({
    tab: 'needs_review', type: 'all', result: 'all', search: ''
  }));
  assert.equal(result.code, 'selection_token_required');
  assert.equal(pool.writes.length, 0);
});

test('type and search filters bound the all-matching update', async () => {
  const pool = selectionPool([
    member({ id: 1, normalized_value: '203.0.113.5', original_value: '203.0.113.5' }),
    member({ id: 2, candidate_type: 'domain', normalized_value: 'evil.example', original_value: 'evil.example' })
  ]);
  const filters = { tab: 'needs_review', type: 'ip', result: 'all', search: '203.0.113.5' };
  const preview = await applyCandidateReviewActions(pool, 9, allMatching(filters, { preview: true }));
  assert.equal(preview.matching, 1);
  const applied = await applyCandidateReviewActions(pool, 9, allMatching(filters, { token: preview.scope_token }));
  assert.deepEqual(pool.writes.find((w) => /approved/.test(w.sql)).params[1].map(Number), [1]);
});

test('context-only and ignore keep their existing eligibility', async () => {
  const pool = selectionPool([
    member({ id: 1 }),
    contextOnly({ id: 2 }),
    narrative({ id: 3 })
  ]);
  const filters = { tab: 'all', type: 'all', result: 'all', search: '' };
  const preview = await applyCandidateReviewActions(pool, 9, {
    action: 'context_only',
    selection: { mode: 'all_matching', filters, excluded_candidate_ids: [] },
    preview: true
  });
  assert.equal(preview.matching, 3);
  assert.equal(preview.eligible, 2, 'the row that is already context-only is not eligible');
  const applied = await applyCandidateReviewActions(pool, 9, {
    action: 'ignore',
    selection: {
      mode: 'all_matching',
      filters: { tab: 'context_only', type: 'all', result: 'all', search: '' },
      excluded_candidate_ids: [],
      scope_token: (await applyCandidateReviewActions(pool, 9, {
        action: 'ignore',
        selection: {
          mode: 'all_matching',
          filters: { tab: 'context_only', type: 'all', result: 'all', search: '' },
          excluded_candidate_ids: []
        },
        preview: true
      })).scope_token
    }
  });
  assert.equal(applied.ok, true);
  assert.equal(pool.candidates.find((c) => c.id === 2).review_status, 'ignored');
  assert.equal(pool.candidates.find((c) => c.id === 1).review_status, 'pending');
  const ignoreSql = pool.writes.find((w) => /review_status = 'ignored'/.test(w.sql)).sql;
  assert.doesNotMatch(ignoreSql, /source_assertion/);
});

test('all-matching create does not duplicate an IOC that already exists', async () => {
  const rows = [
    member({ id: 1, review_status: 'approved', assessment: 'malicious' }),
    member({ id: 2, review_status: 'approved', assessment: 'malicious', normalized_value: '203.0.113.66', original_value: '203.0.113.66' })
  ];
  const pool = selectionPool(rows);
  const filters = { tab: 'indicators', type: 'all', result: 'all', search: '' };
  const created = [];
  const run = (token, confirm, findExisting) => applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    confirm,
    selection: {
      mode: 'all_matching',
      filters,
      excluded_candidate_ids: [],
      scope_token: token
    },
    createIoc: async (_pool, body) => {
      if (body.observable === '203.0.113.66') throw new Error('duplicate create');
      created.push(body.observable);
      return { status: 201, body: { id: 70, public_id: 'ioc-70', observable_type: 'ip' } };
    },
    findExistingIoc: findExisting
  });
  const preview = await run(undefined, false, async () => null);
  assert.equal(preview.preview, true);
  assert.equal(preview.summary.eligible, 2);
  const first = await run(preview.scope_token, true, async (_pool, _type, value) => (
    value === '203.0.113.66' ? { id: 88, public_id: 'ioc-88', observable_type: 'ip' } : null
  ));
  assert.equal(first.ok, true);
  assert.equal(first.summary.created, 1);
  assert.equal(first.summary.already_existing, 1);
  assert.deepEqual(created, ['203.0.113.10']);
  const again = await run(selectionScopeToken(pool.candidates), true, async () => (
    { id: 88, public_id: 'ioc-88', observable_type: 'ip' }
  ));
  assert.equal(again.summary.created, 0);
  assert.equal(again.summary.already_existing, 2);
  assert.deepEqual(created, ['203.0.113.10']);
});

test('all-matching create scales past one page without a client id list', async () => {
  const rows = Array.from({ length: 320 }, (_, i) => {
    const value = `198.51.${Math.floor(i / 256)}.${i % 256}`;
    return member({
      id: i + 1,
      review_status: 'approved',
      assessment: 'malicious',
      candidate_type: 'ip',
      normalized_value: value,
      original_value: value
    });
  });
  const pool = selectionPool(rows);
  const filters = { tab: 'indicators', type: 'all', result: 'all', search: '' };
  const excluded = [10, 11];
  const preview = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    confirm: false,
    selection: { mode: 'all_matching', filters, excluded_candidate_ids: excluded }
  });
  assert.equal(preview.matching, 318);
  assert.equal(preview.eligible, 318);
  assert.ok(preview.scope_token);
  const created = [];
  let nextId = 1000;
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    confirm: true,
    selection: {
      mode: 'all_matching',
      filters,
      excluded_candidate_ids: excluded,
      scope_token: preview.scope_token
    },
    findExistingIoc: async () => null,
    createIoc: async (_pool, body) => {
      created.push(body.observable);
      nextId += 1;
      return { status: 201, body: { id: nextId, public_id: `ioc-${nextId}`, observable_type: 'ip' } };
    }
  });
  assert.equal(result.ok, true);
  assert.equal(result.summary.created, 318);
  assert.equal(created.length, 318);
  assert.equal(created.includes('198.51.0.9'), false, 'excluded id 10');
  assert.equal(created.includes('198.51.0.10'), false, 'excluded id 11');
  // The client never sent the matching id list — only filters + exclusions.
  assert.equal(Object.hasOwn(result, 'candidate_ids'), false);
});

test('create records a per-candidate failure without aborting the rest', async () => {
  const pool = selectionPool([
    member({ id: 1, review_status: 'approved' }),
    member({ id: 2, review_status: 'approved', normalized_value: '203.0.113.77', original_value: '203.0.113.77' })
  ]);
  const filters = { tab: 'indicators', type: 'all', result: 'all', search: '' };
  const preview = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    confirm: false,
    selection: { mode: 'all_matching', filters, excluded_candidate_ids: [] },
    findExistingIoc: async () => null,
    createIoc: async () => ({ status: 201, body: { id: 1, public_id: 'x', observable_type: 'ip' } })
  });
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    confirm: true,
    selection: { mode: 'all_matching', filters, excluded_candidate_ids: [], scope_token: preview.scope_token },
    findExistingIoc: async () => null,
    createIoc: async (_pool, body) => {
      if (body.observable === '203.0.113.77') throw new Error('provider down');
      return { status: 201, body: { id: 71, public_id: 'ioc-71', observable_type: 'ip' } };
    }
  });
  assert.equal(result.ok, true);
  assert.equal(result.summary.created, 1);
  assert.equal(result.summary.failed, 1);
  assert.equal(result.errors.length, 1);
});

test('approve writes one grouped audit event for the resolved selection', async () => {
  const pool = selectionPool([member({ id: 1 }), member({ id: 2, normalized_value: '203.0.113.8', original_value: '203.0.113.8' })]);
  const events = [];
  const filters = { tab: 'needs_review', type: 'all', result: 'all', search: '' };
  const preview = await applyCandidateReviewActions(pool, 9, allMatching(filters, { preview: true }));
  const result = await applyCandidateReviewActions(pool, 9, {
    ...allMatching(filters, { token: preview.scope_token }),
    user: { email: 'analyst@example' },
    audit: { auditLog: async (event) => { events.push(event); } }
  });
  assert.equal(result.ok, true);
  assert.equal(events.length, 1);
  assert.equal(events[0].metadata.review_action, 'approve');
  assert.equal(events[0].metadata.selected, 2);
  assert.equal(events[0].metadata.changed, 2);
});

test('approve high-confidence malicious stays inside the all-matching filter', async () => {
  const hc = (id, type, value) => member({
    id,
    candidate_type: type,
    normalized_value: value,
    original_value: value,
    assessment: 'malicious',
    confidence: 0.95,
    review_status: 'pending',
    section: 'c2_section',
    evidence: {
      occurrences: [{ zone: 'c2_section', section_kind: 'c2_section' }],
      policy_decision: 'pass'
    }
  });
  const pool = selectionPool([
    hc(1, 'ip', '217.60.36.94'),
    hc(2, 'domain', 'evil.example')
  ]);
  const filters = { tab: 'needs_review', type: 'ip', result: 'all', search: '' };
  const preview = await applyCandidateReviewActions(pool, 9, {
    action: 'approve_high_confidence_malicious',
    selection: { mode: 'all_matching', filters, excluded_candidate_ids: [] },
    preview: true
  });
  assert.equal(preview.matching, 1);
  assert.equal(preview.eligible, 1);
  const applied = await applyCandidateReviewActions(pool, 9, {
    action: 'approve_high_confidence_malicious',
    selection: {
      mode: 'all_matching',
      filters,
      excluded_candidate_ids: [],
      scope_token: preview.scope_token
    }
  });
  assert.equal(applied.ok, true);
  assert.equal(applied.updated, 1);
  const update = pool.writes.find((w) => /SET review_status = 'approved'/.test(w.sql));
  assert.deepEqual(update.params[1].map(Number), [1]);
  assert.equal(pool.candidates.find((c) => c.id === 2).review_status, 'pending');
});

test('promote stays single-row when the client asks for all-matching', async () => {
  const pool = selectionPool([contextOnly({ id: 2 }), contextOnly({ id: 3, normalized_value: 'other.example', original_value: 'other.example' })]);
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'promote_to_ioc',
    selection: {
      mode: 'all_matching',
      filters: { tab: 'context_only', type: 'all', result: 'all', search: '' },
      excluded_candidate_ids: []
    },
    preview: true
  });
  assert.equal(result.code, 'promote_single_row_only');
  assert.equal(pool.writes.length, 0);
});

test('scope token changes when candidate state changes and ignores order', () => {
  const a = [member({ id: 1 }), member({ id: 2 })];
  const b = [member({ id: 2 }), member({ id: 1 })];
  assert.equal(selectionScopeToken(a), selectionScopeToken(b));
  a[0].review_status = 'approved';
  assert.notEqual(selectionScopeToken(a), selectionScopeToken(b));
});
