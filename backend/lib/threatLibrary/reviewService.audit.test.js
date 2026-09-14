/**
 * Threat Library audit trail: Create IOCs / review / finalize emit committed,
 * actor-attributed, TLP-safe events (one per user action).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { applyCandidateReviewActions, finalizeReport } from './reviewService.js';
import { AUDIT_ACTION, AUDIT_STATUS } from '../auditConstants.js';

const USER = { id: 7, publicId: '2f1c9d0e-5a6b-4c7d-8e9f-0a1b2c3d4e5f', email: 'safa@safa.com', username: 'safa@safa.com', role: 'analyst' };
const REQ = { user: USER, authVia: 'cookie', headers: {}, ip: '10.0.0.5', requestId: 'req_1' };

const REPORT = {
  id: 10,
  public_id: 'c9e28440-a25f-4149-a993-c78d8b458805',
  title: 'PurpleBravo’s Targeting of the IT Software Supply Chain',
  source_type: 'pdf',
  tlp: 'amber',
  analysis_status: 'review_required',
  source_url: null,
  summary: 'SECRET REPORT BODY MUST NOT LEAK'
};

function fakeAudit() {
  const events = [];
  return {
    events,
    async auditLog(event) { events.push(event); },
    async auditSuccess(event) { events.push({ ...event, status: 'success' }); },
    async auditFailure(event) { events.push({ ...event, status: 'failed' }); }
  };
}

function fakePool(report, { candidates = [], sourceId = 4 } = {}) {
  const writes = [];
  return {
    writes,
    async query(sql, params) {
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

let nextId = 1;
function cand(overrides) {
  const id = overrides.id ?? nextId++;
  return {
    id,
    candidate_type: 'ip',
    original_value: `38.92.47.${id}`,
    normalized_value: `38.92.47.${id}`,
    assessment: 'malicious',
    review_status: 'approved',
    match_state: 'new',
    matched_ioc_id: null,
    confidence: 0.9,
    role: 'c2',
    is_ioc: true,
    evidence: { occurrences: [{ surrounding_text: 'EVIDENCE PARAGRAPH MUST NOT LEAK' }] },
    evidence_text: 'EVIDENCE TEXT MUST NOT LEAK',
    ...overrides
  };
}

function createIocsScenario() {
  // 10 approved + new, 5 already existing, 2 not approved, 1 CIDR unsupported = 18 selected.
  const candidates = [];
  for (let i = 0; i < 10; i += 1) candidates.push(cand({ id: 100 + i }));
  for (let i = 0; i < 5; i += 1) candidates.push(cand({ id: 200 + i, matched_ioc_id: 500 + i, match_state: 'existing', matched_ioc_observable_type: 'ip' }));
  for (let i = 0; i < 2; i += 1) candidates.push(cand({ id: 300 + i, review_status: 'pending' }));
  candidates.push(cand({ id: 400, candidate_type: 'cidr', original_value: '36.35.56.0/24', normalized_value: '36.35.56.0/24' }));
  return candidates;
}

function createIocStub(store) {
  return async (_pool, body, opts) => {
    const id = 1000 + store.length;
    store.push({ body, opts, id });
    // Mirror createManualIoc: emit ioc.created only with a request context.
    if (opts?.audit?.auditSuccess && opts.req) {
      await opts.audit.auditSuccess({
        req: opts.req,
        action: AUDIT_ACTION.IOC_CREATED,
        entityType: 'ioc',
        entityId: String(id),
        metadata: { source_id: body.source_id, ...(opts.auditMetadata || {}) }
      });
    }
    return { status: 201, body: { id, public_id: `ioc-${id}`, observable_type: 'ip' } };
  };
}

test('Create IOCs emits one parent event with backend-authoritative counts and the initiating actor', async () => {
  const candidates = createIocsScenario();
  const pool = fakePool(REPORT, { candidates });
  const audit = fakeAudit();
  const createdStore = [];
  const result = await applyCandidateReviewActions(pool, REPORT.id, {
    action: 'create_iocs',
    candidateIds: candidates.map((c) => c.id),
    confirm: true,
    user: USER,
    audit,
    req: REQ,
    createIoc: createIocStub(createdStore),
    findExistingIoc: async () => null
  });
  assert.equal(result.ok, true);
  assert.deepEqual(
    { selected: result.summary.selected, created: result.summary.created, already_existing: result.summary.already_existing, not_approved: result.summary.not_approved, unsupported: result.summary.unsupported },
    { selected: 18, created: 10, already_existing: 5, not_approved: 2, unsupported: 1 }
  );

  const parents = audit.events.filter((e) => e.action === AUDIT_ACTION.THREAT_LIBRARY_IOCS_CREATED);
  assert.equal(parents.length, 1, 'exactly one bulk event');
  const parent = parents[0];
  assert.equal(parent.req, REQ);
  assert.equal(parent.actor, USER);
  assert.equal(parent.entityType, 'threat_report');
  assert.equal(parent.entityId, REPORT.public_id);
  assert.equal(parent.entityDisplay, REPORT.title);
  assert.equal(parent.status, AUDIT_STATUS.SUCCESS);
  const m = parent.metadata;
  assert.equal(m.report_public_id, REPORT.public_id);
  assert.equal(m.report_title, REPORT.title);
  assert.equal(m.initiated_by, 'safa@safa.com');
  assert.equal(m.selected, 18);
  assert.equal(m.eligible, 10);
  assert.equal(m.created, 10);
  assert.equal(m.already_existing, 5);
  assert.equal(m.not_approved, 2);
  assert.equal(m.unsupported, 1);
  assert.equal(m.failed, 0);
  assert.deepEqual(m.candidate_types, { ip: 17, cidr: 1 });
  assert.equal(m.results_total, 18);
  assert.equal(m.results_shown, 18);
  assert.equal(m.results_omitted, 0);
  assert.equal(m.created_ioc_ids.length, 10);
  assert.equal(m.operation_id, result.operation_id);
  const existingRow = m.results.find((r) => r.candidate_id === 200);
  assert.deepEqual(existingRow, { candidate_id: 200, type: 'ip', value: '38.92.47.200', outcome: 'already_existing', ioc_id: 500 });
  const cidrRow = m.results.find((r) => r.candidate_id === 400);
  assert.equal(cidrRow.outcome, 'unsupported');
  assert.equal(cidrRow.value, '36.35.56.0/24');
});

test('ioc.created rows are emitted only for new IOCs and carry the report / candidate / operation origin', async () => {
  const candidates = createIocsScenario();
  const pool = fakePool(REPORT, { candidates });
  const audit = fakeAudit();
  const createdStore = [];
  const result = await applyCandidateReviewActions(pool, REPORT.id, {
    action: 'create_iocs',
    candidateIds: candidates.map((c) => c.id),
    confirm: true,
    user: USER,
    audit,
    req: REQ,
    createIoc: createIocStub(createdStore),
    findExistingIoc: async () => null
  });
  const iocCreated = audit.events.filter((e) => e.action === AUDIT_ACTION.IOC_CREATED);
  assert.equal(iocCreated.length, 10, 'no ioc.created for already-existing / skipped rows');
  for (const ev of iocCreated) {
    assert.equal(ev.req, REQ, 'ioc.created is written with the request (actor, IP, request id)');
    assert.equal(ev.metadata.origin, 'threat_library');
    assert.equal(ev.metadata.threat_report_public_id, REPORT.public_id);
    assert.equal(ev.metadata.threat_report_title, REPORT.title);
    assert.equal(ev.metadata.threat_library_operation_id, result.operation_id);
    assert.equal(ev.metadata.initiated_by, 'safa@safa.com');
    assert.ok(ev.metadata.threat_report_candidate_id >= 100 && ev.metadata.threat_report_candidate_id < 110);
  }
  // createManualIoc received the resolved actor (stamps created_by_user_id).
  assert.ok(createdStore.every((c) => c.opts.user === USER && c.opts.req === REQ));
});

test('second run is idempotent: created = 0 and every row is already_existing', async () => {
  const candidates = createIocsScenario().filter((c) => c.review_status === 'approved' && c.candidate_type !== 'cidr');
  const pool = fakePool(REPORT, { candidates });
  const audit = fakeAudit();
  let creates = 0;
  const result = await applyCandidateReviewActions(pool, REPORT.id, {
    action: 'create_iocs',
    candidateIds: candidates.map((c) => c.id),
    confirm: true,
    user: USER,
    audit,
    req: REQ,
    createIoc: async () => { creates += 1; return { status: 201, body: { id: 1 } }; },
    // Previously created rows now resolve to existing IOC records.
    findExistingIoc: async (_p, _t, value) => ({ id: 9000 + Number(String(value).split('.').pop()), observable_type: 'ip' })
  });
  assert.equal(creates, 0);
  assert.equal(result.summary.created, 0);
  assert.equal(result.summary.already_existing, 15);
  const parent = audit.events.filter((e) => e.action === AUDIT_ACTION.THREAT_LIBRARY_IOCS_CREATED);
  assert.equal(parent.length, 1);
  assert.equal(parent[0].metadata.created, 0);
  assert.equal(parent[0].metadata.already_existing, 15);
  assert.equal(parent[0].status, AUDIT_STATUS.SUCCESS);
  assert.equal(audit.events.filter((e) => e.action === AUDIT_ACTION.IOC_CREATED).length, 0);
});

test('partial failure: failed count, partial status, safe error category — no stack, SQL or paths', async () => {
  const candidates = [cand({ id: 1 }), cand({ id: 2 }), cand({ id: 3 })];
  const pool = fakePool(REPORT, { candidates });
  const audit = fakeAudit();
  const result = await applyCandidateReviewActions(pool, REPORT.id, {
    action: 'create_iocs',
    candidateIds: [1, 2, 3],
    confirm: true,
    user: USER,
    audit,
    req: REQ,
    createIoc: async (_pool, body) => {
      if (body.observable.endsWith('.2')) {
        const err = new Error('relation "ioc_items" does not exist at /srv/app/lib/db.js:42 password=hunter2');
        err.code = '42P01';
        throw err;
      }
      return { status: 201, body: { id: Number(body.observable.split('.').pop()), observable_type: 'ip' } };
    },
    findExistingIoc: async () => null
  });
  assert.equal(result.ok, true);
  assert.equal(result.summary.created, 2);
  assert.equal(result.summary.failed, 1);
  const parent = audit.events.find((e) => e.action === AUDIT_ACTION.THREAT_LIBRARY_IOCS_CREATED);
  assert.equal(parent.status, AUDIT_STATUS.PARTIAL);
  assert.equal(parent.severity, 'warning');
  assert.equal(parent.metadata.failed, 1);
  const failedRow = parent.metadata.results.find((r) => r.candidate_id === 2);
  assert.equal(failedRow.outcome, 'failed');
  assert.equal(failedRow.error, 'create failed (42p01)');
  const json = JSON.stringify(parent);
  assert.equal(json.includes('/srv/app'), false);
  assert.equal(json.includes('hunter2'), false);
  assert.equal(json.includes('does not exist'), false);
});

test('all attempted rows failing yields status failed (nothing committed)', async () => {
  const pool = fakePool(REPORT, { candidates: [cand({ id: 1 })] });
  const audit = fakeAudit();
  await applyCandidateReviewActions(pool, REPORT.id, {
    action: 'create_iocs',
    candidateIds: [1],
    confirm: true,
    user: USER,
    audit,
    req: REQ,
    createIoc: async () => ({ status: 400, body: { message: 'Could not infer IOC type from value' } }),
    findExistingIoc: async () => null
  });
  const parent = audit.events.find((e) => e.action === AUDIT_ACTION.THREAT_LIBRARY_IOCS_CREATED);
  assert.equal(parent.status, AUDIT_STATUS.FAILED);
  assert.equal(parent.metadata.created, 0);
  assert.equal(parent.metadata.failed, 1);
});

test('TLP:AMBER: audit metadata never contains evidence text, report body, document or AI content', async () => {
  const candidates = createIocsScenario();
  const pool = fakePool({ ...REPORT, canonical_document: { blocks: [{ text: 'DOCUMENT BLOCK MUST NOT LEAK' }] }, ai_result: { prompt: 'AI PROMPT MUST NOT LEAK', raw: 'AI RAW MUST NOT LEAK' } }, { candidates });
  const audit = fakeAudit();
  await applyCandidateReviewActions(pool, REPORT.id, {
    action: 'create_iocs',
    candidateIds: candidates.map((c) => c.id),
    confirm: true,
    user: USER,
    audit,
    req: REQ,
    createIoc: createIocStub([]),
    findExistingIoc: async () => null
  });
  await applyCandidateReviewActions(pool, REPORT.id, {
    action: 'approve', candidateIds: [300, 301], user: USER, audit, req: REQ
  });
  // finalize is blocked here (fake pool keeps 300/301 pending) — covered separately.
  await finalizeReport(pool, REPORT.id, { user: USER, audit, req: REQ });
  const json = JSON.stringify(audit.events.map(({ req, actor, ...rest }) => rest));
  for (const banned of ['MUST NOT LEAK', 'evidence_text', 'surrounding_text', 'canonical_document', 'ai_result', 'prompt']) {
    assert.equal(json.includes(banned), false, `audit payload must not contain ${banned}`);
  }
  const tlEvents = audit.events.filter((e) => String(e.action).startsWith('threat_library.'));
  assert.equal(tlEvents.length, 2);
  assert.ok(tlEvents.every((e) => e.metadata?.tlp === 'amber'));
});

test('bulk outcomes are bounded to 100 rows with explicit total/shown/omitted counts (never silent)', async () => {
  const candidates = [];
  for (let i = 0; i < 130; i += 1) candidates.push(cand({ id: 1000 + i }));
  const pool = fakePool(REPORT, { candidates });
  const audit = fakeAudit();
  await applyCandidateReviewActions(pool, REPORT.id, {
    action: 'create_iocs',
    candidateIds: candidates.map((c) => c.id),
    confirm: true,
    user: USER,
    audit,
    req: REQ,
    createIoc: createIocStub([]),
    findExistingIoc: async () => null
  });
  const parent = audit.events.find((e) => e.action === AUDIT_ACTION.THREAT_LIBRARY_IOCS_CREATED);
  assert.equal(parent.metadata.created, 130);
  assert.equal(parent.metadata.results_total, 130);
  assert.equal(parent.metadata.results_shown, 100);
  assert.equal(parent.metadata.results_omitted, 30);
  assert.equal(parent.metadata.results.length, 100);
  assert.equal(parent.metadata.created_ioc_ids.length, 100);
});

test('preview (confirm=false) and blocked selections write no audit event', async () => {
  const candidates = createIocsScenario();
  const pool = fakePool(REPORT, { candidates });
  const audit = fakeAudit();
  await applyCandidateReviewActions(pool, REPORT.id, {
    action: 'create_iocs', candidateIds: candidates.map((c) => c.id), confirm: false, user: USER, audit, req: REQ
  });
  await applyCandidateReviewActions(pool, REPORT.id, {
    action: 'create_iocs', candidateIds: [300, 301], confirm: true, user: USER, audit, req: REQ
  });
  assert.equal(audit.events.length, 0);
});

test('review actions emit one grouped event per request with changed / already-in-state counts', async () => {
  const candidates = [
    cand({ id: 1, review_status: 'pending' }),
    cand({ id: 2, review_status: 'pending', candidate_type: 'domain' }),
    cand({ id: 3, review_status: 'approved' })
  ];
  const pool = fakePool(REPORT, { candidates });
  const audit = fakeAudit();
  const result = await applyCandidateReviewActions(pool, REPORT.id, {
    action: 'approve', candidateIds: [1, 2, 3, 999], user: USER, audit, req: REQ
  });
  assert.equal(result.ok, true);
  assert.equal(audit.events.length, 1);
  const ev = audit.events[0];
  assert.equal(ev.action, AUDIT_ACTION.THREAT_LIBRARY_CANDIDATES_APPROVED);
  assert.equal(ev.actor, USER);
  assert.equal(ev.entityDisplay, REPORT.title);
  assert.equal(ev.metadata.selected, 4);
  assert.equal(ev.metadata.matched, 3);
  assert.equal(ev.metadata.changed, 2);
  assert.equal(ev.metadata.already_in_state, 1);
  assert.deepEqual(ev.metadata.candidate_types, { ip: 2, domain: 1 });
  assert.deepEqual(ev.metadata.candidate_ids, [1, 2, 3]);

  audit.events.length = 0;
  await applyCandidateReviewActions(pool, REPORT.id, { action: 'context_only', candidateIds: [1], user: USER, audit, req: REQ });
  await applyCandidateReviewActions(pool, REPORT.id, { action: 'ignore', candidateIds: [2], user: USER, audit, req: REQ });
  assert.deepEqual(audit.events.map((e) => e.action), [
    AUDIT_ACTION.THREAT_LIBRARY_CANDIDATES_CONTEXT_ONLY,
    AUDIT_ACTION.THREAT_LIBRARY_CANDIDATES_IGNORED
  ]);
});

test('finalize emits the final review summary', async () => {
  const candidates = [
    cand({ id: 1, review_status: 'approved', promotion_outcome: 'created' }),
    cand({ id: 2, review_status: 'approved', promotion_outcome: 'already_existing', matched_ioc_id: 5 }),
    cand({ id: 3, review_status: 'context_only', assessment: 'context_only', match_state: 'context_only' }),
    cand({ id: 4, review_status: 'ignored' }),
    cand({ id: 5, review_status: 'approved', candidate_type: 'cidr', promotion_outcome: 'unsupported' })
  ];
  const pool = fakePool({ ...REPORT, analysis_status: 'review_required' }, { candidates });
  const audit = fakeAudit();
  const result = await finalizeReport(pool, REPORT.id, { user: USER, audit, req: REQ });
  assert.equal(result.ok, true);
  assert.equal(audit.events.length, 1);
  const ev = audit.events[0];
  assert.equal(ev.action, AUDIT_ACTION.THREAT_LIBRARY_REPORT_FINALIZED);
  assert.equal(ev.actor, USER);
  assert.equal(ev.entityId, REPORT.public_id);
  assert.equal(ev.entityDisplay, REPORT.title);
  assert.deepEqual(
    { total: ev.metadata.total_candidates, approved: ev.metadata.approved, context_only: ev.metadata.context_only, ignored: ev.metadata.ignored, created: ev.metadata.created, already_existing: ev.metadata.already_existing, unsupported: ev.metadata.unsupported, pending: ev.metadata.pending },
    { total: 5, approved: 3, context_only: 1, ignored: 1, created: 1, already_existing: 1, unsupported: 1, pending: 0 }
  );
});

test('finalize blocked by pending review writes no audit event', async () => {
  const pool = fakePool(REPORT, { candidates: [cand({ id: 1, review_status: 'pending' })] });
  const audit = fakeAudit();
  const result = await finalizeReport(pool, REPORT.id, { user: USER, audit, req: REQ });
  assert.equal(result.ok, false);
  assert.equal(audit.events.length, 0);
});
