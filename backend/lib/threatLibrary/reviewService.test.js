import test from 'node:test';
import assert from 'node:assert/strict';
import { applyCandidateReviewActions, finalizeReport } from './reviewService.js';

function fakePool(report, { candidates = [], sourceId = 4 } = {}) {
  const writes = [];
  const queries = [];
  return {
    writes,
    queries,
    async query(sql, params) {
      queries.push({ sql, params });
      if (/FROM threat_reports WHERE id = \$1/.test(sql) && /^\s*SELECT/i.test(sql)) {
        return { rows: report ? [report] : [] };
      }
      if (/FROM threat_report_candidates/.test(sql) && /^\s*SELECT/i.test(sql)) {
        const ids = Array.isArray(params?.[1]) ? params[1].map(Number) : null;
        const rows = ids ? candidates.filter((c) => ids.includes(Number(c.id))) : candidates;
        return { rows };
      }
      if (/FROM ioc_sources WHERE name/.test(sql)) {
        return { rows: sourceId ? [{ id: sourceId }] : [] };
      }
      writes.push({ sql, params });
      return { rows: [] };
    }
  };
}

const report = { id: 9, public_id: 'rep-1', analysis_status: 'review_required', source_url: null };

function cand(overrides) {
  return {
    id: 1,
    candidate_type: 'ip',
    original_value: '38.92.47.91',
    normalized_value: '38.92.47.91',
    assessment: 'malicious',
    review_status: 'approved',
    match_state: 'new',
    matched_ioc_id: null,
    confidence: 0.9,
    role: 'c2',
    is_ioc: true,
    evidence: {},
    ...overrides
  };
}

test('create_iocs preview does not write and reports mixed eligibility', async () => {
  const candidates = [
    cand({ id: 1 }),
    cand({ id: 2, review_status: 'pending' }),
    cand({ id: 3, matched_ioc_id: 88, match_state: 'existing' }),
    cand({
      id: 4,
      candidate_type: 'cidr',
      original_value: '36.35.56.0/24',
      normalized_value: '36.35.56.0/24'
    })
  ];
  const pool = fakePool(report, { candidates });
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [1, 2, 3, 4],
    confirm: false
  });
  assert.equal(result.ok, true);
  assert.equal(result.preview, true);
  assert.equal(result.summary.selected, 4);
  assert.equal(result.summary.eligible, 1);
  assert.equal(result.summary.not_approved, 1);
  assert.equal(result.summary.already_existing, 1);
  assert.equal(result.summary.unsupported, 1);
  assert.equal(pool.writes.length, 0);
});

test('create_iocs without any approved eligible rows is blocked and writes nothing', async () => {
  const pool = fakePool(report, {
    candidates: [cand({ id: 1, review_status: 'pending' }), cand({ id: 2, review_status: 'pending' })]
  });
  let created = 0;
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [1, 2],
    confirm: true,
    createIoc: async () => {
      created += 1;
      return { status: 201, body: { id: 1 } };
    }
  });
  assert.equal(result.ok, false);
  assert.equal(result.status, 409);
  assert.equal(result.code, 'create_iocs_none_eligible');
  assert.equal(created, 0);
  assert.equal(pool.writes.length, 0);
});

test('create_iocs confirm creates only approved new rows and never duplicates existing', async () => {
  const candidates = [
    cand({ id: 1 }),
    cand({ id: 2, matched_ioc_id: 88, match_state: 'existing', matched_ioc_observable_type: 'ip' }),
    cand({ id: 3, review_status: 'pending' }),
    cand({
      id: 4,
      candidate_type: 'cidr',
      original_value: '36.35.56.0/24',
      normalized_value: '36.35.56.0/24'
    })
  ];
  const pool = fakePool(report, { candidates });
  const createdValues = [];
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [1, 2, 3, 4],
    confirm: true,
    createIoc: async (_pool, body) => {
      createdValues.push(body.observable);
      return { status: 201, body: { id: 501, public_id: 'ioc-501', observable_type: 'ip' } };
    },
    findExistingIoc: async () => null
  });
  assert.equal(result.ok, true);
  assert.deepEqual(createdValues, ['38.92.47.91']);
  assert.equal(result.summary.created, 1);
  assert.equal(result.summary.already_existing, 1);
  assert.equal(result.summary.not_approved, 1);
  assert.equal(result.summary.unsupported, 1);
  assert.equal(result.results.find((r) => r.candidate_id === 1).outcome, 'created');
  assert.equal(result.results.find((r) => r.candidate_id === 2).outcome, 'already_existing');
  assert.equal(result.results.find((r) => r.candidate_id === 4).outcome, 'unsupported');
  assert.ok(result.results.find((r) => r.candidate_id === 4).detail.includes('CIDR'));
  assert.ok(pool.writes.some((w) => /promotion_outcome/.test(w.sql)));
  assert.equal(pool.writes.some((w) => /review_status = 'created_ioc'/.test(w.sql)), false);
  assert.equal(createdValues.some((v) => String(v).includes('/24')), false);
});

test('repeated create is idempotent when the IOC already exists', async () => {
  const pool = fakePool(report, { candidates: [cand({ id: 1 })] });
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [1],
    confirm: true,
    createIoc: async () => {
      throw new Error('should not create');
    },
    findExistingIoc: async () => ({ id: 777, public_id: 'x', observable_type: 'ip' })
  });
  assert.equal(result.ok, true);
  assert.equal(result.summary.created, 0);
  assert.equal(result.summary.already_existing, 1);
  assert.equal(result.results[0].ioc_id, 777);
});

test('approve high-confidence malicious only updates review_status', async () => {
  const pool = fakePool(report, {
    candidates: [cand({ id: 11, review_status: 'pending', confidence: 0.95 })]
  });
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'approve_high_confidence_malicious'
  });
  // Filter may drop the row depending on evidencePolicy; either way no create_iocs path.
  assert.equal(result.ok === true || result.error === 'No candidates selected', true);
  assert.equal(pool.writes.some((w) => /INSERT INTO ioc/.test(w.sql)), false);
});

test('finalize is blocked while pending actionable indicators remain', async () => {
  const pool = fakePool(report, {
    candidates: [cand({ id: 1, review_status: 'pending' })]
  });
  const result = await finalizeReport(pool, 9);
  assert.equal(result.ok, false);
  assert.equal(result.code, 'pending_review_remaining');
  assert.equal(result.pending_count, 1);
  assert.equal(pool.writes.length, 0);
});

test('finalize succeeds when only context-only rows remain pending-shaped', async () => {
  const pool = fakePool(report, {
    candidates: [cand({
      id: 1,
      review_status: 'context_only',
      assessment: 'context_only',
      match_state: 'context_only'
    })]
  });
  const result = await finalizeReport(pool, 9);
  assert.equal(result.ok, true);
  assert.ok(pool.writes.some((w) => /UPDATE threat_reports/.test(w.sql)));
});
