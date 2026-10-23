/**
 * MCP Threat Library post-import review tools.
 *
 * Tools must call the same reviewService / finalizeReport paths as the UI:
 * approve persists review_status only; Create IOCs materializes approved rows;
 * finalize is blocked while pending actionable Indicators remain; Context Only
 * and ignored rows are never created; retries reuse existing IOCs.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { registerMcpTools } from './mcpTools.js';
import { authorizeMcpTool, MCP_TOOL_SCOPES } from './mcpPermissions.js';
import { ACCESS_PROFILE, API_SCOPE, scopesForAccessProfile } from './apiKeyProfiles.js';
import {
  applyCandidateReviewActions,
  finalizeReport
} from './threatLibrary/reviewService.js';
import {
  mcpThreatLibraryGetReview,
  mcpThreatLibraryGetWorkflowStatus,
  mcpThreatLibraryReviewIocs,
  mcpThreatLibraryCreateIocs,
  mcpThreatLibraryFinalizeReport,
  reportRevision
} from './threatLibrary/mcpThreatLibraryReviewService.js';
import { withLinkedSourceProvenance } from './threatLibrary/mcpThreatReport.js';

const REPORT_PUBLIC = '11111111-1111-4111-8111-111111111111';
const CAND_PUBLIC = {
  1: '22222222-2222-4222-8222-222222222201',
  2: '22222222-2222-4222-8222-222222222202',
  3: '22222222-2222-4222-8222-222222222203',
  4: '22222222-2222-4222-8222-222222222204'
};
const ANALYST_SCOPES = scopesForAccessProfile(ACCESS_PROFILE.MCP_ANALYST);
const READ_SCOPES = scopesForAccessProfile(ACCESS_PROFILE.MCP_READ);
const USER = { id: 2, role: 'analyst', username: 'analyst', email: 'analyst@example.com', publicId: '00000000-0000-4000-8000-00000000aaaa' };

function baseReport(overrides = {}) {
  return {
    id: 9,
    public_id: REPORT_PUBLIC,
    title: 'Vendor APT Report',
    source_name: 'Vendor',
    source_type: 'url',
    source_url: 'https://vendor.example/apt',
    tlp: 'amber',
    import_status: 'review_required',
    analysis_status: 'review_required',
    created_at: new Date('2026-10-01T10:00:00Z'),
    updated_at: new Date('2026-10-01T12:00:00Z'),
    finalized_at: null,
    summary: 'Summary',
    ...overrides
  };
}

function cand(overrides = {}) {
  const id = overrides.id ?? 1;
  return {
    id,
    public_id: CAND_PUBLIC[id] || `22222222-2222-4222-8222-${String(id).padStart(12, '0')}`,
    candidate_type: 'ip',
    original_value: '203.0.113.10',
    normalized_value: '203.0.113.10',
    assessment: 'malicious',
    role: 'c2',
    confidence: 0.9,
    review_status: 'pending',
    match_state: 'new',
    matched_ioc_id: null,
    matched_ioc_observable_type: null,
    is_ioc: true,
    source_assertion: 'explicit_ioc',
    document_has_authoritative_scope: true,
    has_original_document_occurrence: true,
    evidence: {
      document_has_authoritative_scope: true,
      source_assertion: 'explicit_ioc',
      policy_decision: 'publisher_asserted',
      decision_source: 'publisher',
      occurrence_count: 1,
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true }]
    },
    section: 'Indicators',
    page_number: 1,
    evidence_text: '203.0.113.10',
    promotion_outcome: null,
    promotion_detail: null,
    ...overrides
  };
}

function createPool({ report = baseReport(), candidates = [], iocs = [], sourceId = 4 } = {}) {
  const state = {
    report: { ...report },
    candidates: candidates.map((c) => ({ ...c })),
    iocs: [...iocs],
    writes: [],
    nextIocId: 500
  };
  const pool = {
    state,
    async query(sql, params = []) {
      const flat = String(sql).replace(/\s+/g, ' ').trim();
      if (/FROM threat_reports WHERE public_id = \$1::uuid/.test(flat)) {
        return { rows: state.report?.public_id === params[0] && !state.report.deleted_at ? [state.report] : [] };
      }
      if (/FROM threat_reports WHERE id = \$1/.test(flat) && /^\s*SELECT/i.test(flat)) {
        return { rows: state.report?.id === params[0] ? [state.report] : [] };
      }
      if (/UPDATE threat_reports SET/.test(flat)) {
        state.writes.push({ sql: flat, params });
        if (params[7] != null) state.report.import_status = params[7];
        if (params[8] != null) state.report.analysis_status = params[8];
        if (params[16] === true) state.report.finalized_at = new Date();
        state.report.updated_at = new Date();
        return { rows: [state.report], rowCount: 1 };
      }
      if (/FROM threat_report_candidates/.test(flat) && /public_id = ANY/.test(flat)) {
        const uuids = params[1] || [];
        return {
          rows: state.candidates
            .filter((c) => c.report_id == null || c.report_id === state.report.id)
            .filter((c) => uuids.includes(c.public_id))
            .map((c) => ({ id: c.id, public_id: c.public_id }))
        };
      }
      if (/FROM threat_report_candidates/.test(flat) && /^\s*SELECT/i.test(flat)) {
        let rows = state.candidates.filter((c) => (c.report_id ?? state.report.id) === (params[0] ?? state.report.id));
        if (Array.isArray(params[1])) {
          const ids = params[1].map(Number);
          rows = rows.filter((c) => ids.includes(Number(c.id)));
        }
        return { rows: rows.map((c) => ({ ...c })) };
      }
      if (/UPDATE threat_report_candidates SET review_status = 'approved'/.test(flat)) {
        state.writes.push({ sql: flat, params });
        const ids = new Set((params[1] || []).map(Number));
        let n = 0;
        for (const c of state.candidates) {
          if (!ids.has(Number(c.id))) continue;
          if (c.is_ioc === false) continue;
          if (String(c.review_status) === 'context_only' || String(c.assessment) === 'context_only') continue;
          c.review_status = 'approved';
          c.updated_at = new Date();
          n += 1;
        }
        return { rows: [], rowCount: n };
      }
      if (/UPDATE threat_report_candidates[\s\S]*review_status = 'context_only'/.test(flat)
        || /SET review_status = 'context_only'/.test(flat)) {
        state.writes.push({ sql: flat, params });
        const ids = new Set((params[1] || []).map(Number));
        for (const c of state.candidates) {
          if (!ids.has(Number(c.id))) continue;
          c.review_status = 'context_only';
          c.assessment = 'context_only';
          c.match_state = 'context_only';
        }
        return { rows: [], rowCount: ids.size };
      }
      if (/SET review_status = 'ignored'/.test(flat)) {
        state.writes.push({ sql: flat, params });
        const ids = new Set((params[1] || []).map(Number));
        for (const c of state.candidates) {
          if (ids.has(Number(c.id))) c.review_status = 'ignored';
        }
        return { rows: [], rowCount: ids.size };
      }
      if (/promotion_outcome/.test(flat) && /UPDATE threat_report_candidates/.test(flat)) {
        state.writes.push({ sql: flat, params });
        const id = Number(params[1]);
        const c = state.candidates.find((x) => Number(x.id) === id);
        if (c) {
          c.promotion_outcome = params[2];
          c.promotion_detail = params[3];
          if (params[4] != null) {
            c.matched_ioc_id = params[4];
            c.matched_ioc_observable_type = params[5];
            c.match_state = 'existing';
          }
        }
        return { rows: [], rowCount: 1 };
      }
      if (/FROM ioc_items/.test(flat) && /observable_type = \$1 AND observable = \$2/.test(flat)) {
        const hit = state.iocs.find((i) => i.observable_type === params[0] && i.observable === params[1]);
        return { rows: hit ? [hit] : [] };
      }
      if (/FROM ioc_sources WHERE name/.test(flat) || /getThreatLibraryIocSourceId|Threat Library/.test(flat)) {
        return { rows: sourceId ? [{ id: sourceId }] : [] };
      }
      if (/SELECT id FROM ioc_sources/.test(flat) || /threat_library.*ioc_sources/i.test(flat)) {
        return { rows: sourceId ? [{ id: sourceId }] : [] };
      }
      if (/pg_try_advisory_lock/.test(flat)) {
        return { rows: [{ ok: true }], rowCount: 1 };
      }
      if (/pg_advisory_unlock/.test(flat)) {
        return { rows: [{ pg_advisory_unlock: true }], rowCount: 1 };
      }
      if (/FROM threat_library_jobs/.test(flat)) {
        return { rows: [] };
      }
      if (/FROM threat_report_ioc_sources/.test(flat)) {
        return { rows: [] };
      }
      if (/threat_report_candidate_source_links|loadReportLinkedSourceCandidateIds/.test(flat)
        || /SELECT candidate_id FROM threat_report_candidate_source_links/.test(flat)) {
        return { rows: [] };
      }
      if (/FROM threat_report_entities|FROM threat_relationships|FROM threat_report_tags/.test(flat)) {
        return { rows: [] };
      }
      if (/UPDATE threat_relationships SET/.test(flat)) {
        state.writes.push({ sql: flat, params });
        return { rows: [], rowCount: 0 };
      }
      // loadReportSnapshot-style: return candidates for report
      if (/FROM threat_report_candidates c/.test(flat) || /SELECT \* FROM threat_report_candidates WHERE report_id/.test(flat)) {
        return { rows: state.candidates.map((c) => ({ ...c })) };
      }
      state.writes.push({ sql: flat, params });
      return { rows: [], rowCount: 0 };
    }
  };
  // Advisory lock shim used by createIocsLock
  pool.connect = async () => ({
    query: pool.query.bind(pool),
    release() {}
  });
  return pool;
}

/** Minimal loadReportSnapshot substitute via monkeypatch-friendly pool + stubs. */
async function withSnapshotStubs(pool, fn) {
  const store = await import('./threatLibrary/store.js');
  const linked = await import('./threatLibrary/iocSources/linkedSourceStatus.js');
  const iocStore = await import('./threatLibrary/iocSources/store.js');
  const origSnap = store.loadReportSnapshot;
  const origLinkedIds = store.loadReportLinkedSourceCandidateIds;
  const origLinkedSum = linked.loadLinkedIocSourceSummary;
  const origList = iocStore.listIocSourcesForReport;
  const origSum = iocStore.summarizeIocSources;
  const origSourceId = store.getThreatLibraryIocSourceId;
  store.loadReportSnapshot = async () => ({
    report: pool.state.report,
    candidates: pool.state.candidates.map((c) => ({ ...c })),
    entities: [],
    relationships: []
  });
  store.loadReportLinkedSourceCandidateIds = async () => new Set(
    pool.state.candidates.filter((c) => c.has_linked_source_occurrence).map((c) => String(c.id))
  );
  linked.loadLinkedIocSourceSummary = async () => ({ declared: 0, extracted: 0, pending: 0, unresolved: 0, dismissed: 0 });
  iocStore.listIocSourcesForReport = async () => [];
  iocStore.summarizeIocSources = async () => ({ total: 0, discovered_pending: 0, attached: 0, extracted: 0, failed: 0 });
  store.getThreatLibraryIocSourceId = async () => 4;
  try {
    return await fn();
  } finally {
    store.loadReportSnapshot = origSnap;
    store.loadReportLinkedSourceCandidateIds = origLinkedIds;
    linked.loadLinkedIocSourceSummary = origLinkedSum;
    iocStore.listIocSourcesForReport = origList;
    iocStore.summarizeIocSources = origSum;
    store.getThreatLibraryIocSourceId = origSourceId;
  }
}

async function callTool(name, args, { scopes = ANALYST_SCOPES, role = 'analyst', pool } = {}) {
  const tools = new Map();
  const server = {
    registerTool(toolName, def, handler) {
      tools.set(toolName, { ...def, handler });
    }
  };
  registerMcpTools(server, {
    pool,
    audit: { auditLog: async () => {}, auditSuccess: async () => {}, auditFailure: async () => {} },
    getRequestContext: () => ({
      req: {
        user: { ...USER, role },
        mcpAuth: { scopes, ownerRole: role, apiKeyId: 7, apiKeyName: 'test', keyType: 'mcp_analyst' }
      }
    }),
    threatLibraryQueue: null
  });
  const tool = tools.get(name);
  assert.ok(tool, `tool ${name} registered`);
  return tool.handler(args);
}

function parseTool(result) {
  if (result.isError) {
    return { error: result.structuredContent?.error || JSON.parse(result.content[0].text).error };
  }
  return { data: result.structuredContent };
}

test('MCP review tool scopes: write tools need mcp:threat_library:write; reads need mcp:ioc:read', () => {
  assert.deepEqual(MCP_TOOL_SCOPES.threat_library_get_review, [API_SCOPE.MCP_IOC_READ]);
  assert.deepEqual(MCP_TOOL_SCOPES.threat_library_review_iocs, [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_THREAT_LIBRARY_WRITE]);
  assert.deepEqual(MCP_TOOL_SCOPES.threat_library_create_iocs, [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_THREAT_LIBRARY_WRITE]);
  assert.deepEqual(MCP_TOOL_SCOPES.threat_library_finalize_report, [API_SCOPE.MCP_IOC_READ, API_SCOPE.MCP_THREAT_LIBRARY_WRITE]);
  assert.equal(authorizeMcpTool('threat_library_review_iocs', { scopes: READ_SCOPES, ownerRole: 'analyst' }).code, 'MISSING_SCOPE');
  assert.equal(authorizeMcpTool('threat_library_get_review', { scopes: READ_SCOPES, ownerRole: 'readonly' }).ok, true);
});

test('threat_library_get_review matches backend decision counts and gates', async () => {
  const candidates = [
    cand({ id: 1, review_status: 'pending' }),
    cand({ id: 2, review_status: 'approved', normalized_value: '203.0.113.11', original_value: '203.0.113.11' }),
    cand({
      id: 3,
      review_status: 'context_only',
      assessment: 'context_only',
      match_state: 'context_only',
      normalized_value: 'example.com',
      original_value: 'example.com',
      candidate_type: 'domain'
    }),
    cand({
      id: 4,
      review_status: 'ignored',
      normalized_value: '203.0.113.12',
      original_value: '203.0.113.12'
    })
  ];
  const pool = createPool({ candidates });
  await withSnapshotStubs(pool, async () => {
    const out = await mcpThreatLibraryGetReview(pool, { report_id: REPORT_PUBLIC });
    assert.equal(out.status, 200);
    assert.equal(out.body.counts.pending, 1);
    assert.equal(out.body.counts.approved, 1);
    assert.equal(out.body.counts.ignored, 1);
    assert.ok(out.body.counts.pending_actionable >= 1);
    assert.equal(out.body.gates.create_iocs_permitted, true);
    assert.equal(out.body.gates.finalize_permitted, false);
    assert.ok(out.body.gates.finalize_blockers.some((b) => b.code === 'pending_review_remaining'));
    assert.ok(out.body.report_revision);
    assert.equal(out.body.candidates.items.length, 4);
    assert.equal(out.body.candidates.items[0].candidate_id, 1);
  });
});

test('individual approve via MCP persists the same as reviewService', async () => {
  const candidates = [cand({ id: 1, review_status: 'pending' })];
  const pool = createPool({ candidates });
  const ctx = {
    user: USER,
    mcpAuth: { scopes: ANALYST_SCOPES, ownerRole: 'analyst', apiKeyId: 1 },
    audit: { auditLog: async () => {} }
  };
  const preview = await mcpThreatLibraryReviewIocs(pool, {
    report_id: REPORT_PUBLIC,
    action: 'approve',
    candidate_ids: [CAND_PUBLIC[1]],
    dry_run: true
  }, ctx);
  assert.equal(preview.status, 200);
  assert.equal(preview.body.dry_run, true);
  assert.equal(pool.state.candidates[0].review_status, 'pending');

  const committed = await mcpThreatLibraryReviewIocs(pool, {
    report_id: REPORT_PUBLIC,
    action: 'approve',
    candidate_ids: [1]
  }, ctx);
  assert.equal(committed.status, 200);
  assert.equal(pool.state.candidates[0].review_status, 'approved');

  // Parity: same service path the UI uses.
  const pool2 = createPool({ candidates: [cand({ id: 1, review_status: 'pending' })] });
  const ui = await applyCandidateReviewActions(pool2, 9, { action: 'approve', candidateIds: [1], user: USER });
  assert.equal(ui.ok, true);
  assert.equal(pool2.state.candidates[0].review_status, 'approved');
});

test('bulk approve targets only selected eligible candidates', async () => {
  const candidates = [
    cand({ id: 1, review_status: 'pending' }),
    cand({ id: 2, review_status: 'pending', normalized_value: '203.0.113.20', original_value: '203.0.113.20' }),
    cand({
      id: 3,
      review_status: 'context_only',
      assessment: 'context_only',
      match_state: 'context_only',
      normalized_value: 'benign.example',
      original_value: 'benign.example',
      candidate_type: 'domain'
    })
  ];
  const pool = createPool({ candidates });
  const out = await mcpThreatLibraryReviewIocs(pool, {
    report_id: REPORT_PUBLIC,
    action: 'approve',
    candidate_ids: [1, 3]
  }, { user: USER, audit: { auditLog: async () => {} } });
  assert.equal(out.status, 200);
  assert.equal(pool.state.candidates.find((c) => c.id === 1).review_status, 'approved');
  assert.equal(pool.state.candidates.find((c) => c.id === 2).review_status, 'pending');
  assert.equal(pool.state.candidates.find((c) => c.id === 3).review_status, 'context_only');
});

test('context_only and ignore stay excluded from Create IOCs', async () => {
  const candidates = [
    cand({
      id: 1,
      review_status: 'context_only',
      assessment: 'context_only',
      match_state: 'context_only'
    }),
    cand({ id: 2, review_status: 'ignored', normalized_value: '203.0.113.30', original_value: '203.0.113.30' }),
    cand({ id: 3, review_status: 'approved', normalized_value: '203.0.113.40', original_value: '203.0.113.40' })
  ];
  const pool = createPool({ candidates });
  let created = 0;
  const result = await applyCandidateReviewActions(pool, 9, {
    action: 'create_iocs',
    candidateIds: [1, 2, 3],
    confirm: true,
    createIoc: async (_p, body) => {
      created += 1;
      return { status: 201, body: { id: 601, public_id: 'ioc-601', observable_type: 'ip', observable: body.observable } };
    },
    findExistingIoc: async () => null,
    user: USER
  });
  assert.equal(result.ok, true);
  assert.equal(created, 1);
  assert.equal(result.summary.created, 1);
  assert.ok(result.summary.not_applicable >= 2 || result.summary.not_approved + result.summary.not_applicable >= 2);
});

test('Create IOCs via MCP: preview then confirm; existing IOC reused; pending skipped', async () => {
  const candidates = [
    cand({ id: 1, review_status: 'approved' }),
    cand({ id: 2, review_status: 'pending', normalized_value: '203.0.113.50', original_value: '203.0.113.50' }),
    cand({
      id: 3,
      review_status: 'approved',
      normalized_value: '203.0.113.60',
      original_value: '203.0.113.60',
      matched_ioc_id: 88,
      match_state: 'existing',
      matched_ioc_observable_type: 'ip'
    })
  ];
  const pool = createPool({
    candidates,
    iocs: [{ id: 88, public_id: 'ioc-88', observable_type: 'ip', observable: '203.0.113.60' }]
  });

  const store = await import('./threatLibrary/store.js');
  const orig = store.getThreatLibraryIocSourceId;
  store.getThreatLibraryIocSourceId = async () => 4;
  try {
    const preview = await mcpThreatLibraryCreateIocs(pool, {
      report_id: REPORT_PUBLIC,
      candidate_ids: [1, 2, 3],
      dry_run: true
    }, { user: USER, audit: { auditLog: async () => {} } });
    assert.equal(preview.status, 200);
    assert.equal(preview.body.dry_run, true);
    assert.equal(preview.body.outcome, 'preview');
    assert.equal(pool.state.writes.filter((w) => /promotion_outcome/.test(w.sql)).length, 0);

    let creates = 0;
    const reviewMod = await import('./threatLibrary/reviewService.js');
    // Inject create via applyCandidateReviewActions options through MCP by
    // patching createManualIoc is heavy; call service with createIoc for confirm parity,
    // then assert MCP requires confirm.
    const noConfirm = await mcpThreatLibraryCreateIocs(pool, {
      report_id: REPORT_PUBLIC,
      candidate_ids: [1, 2, 3]
    }, { user: USER, audit: { auditLog: async () => {} } });
    assert.equal(noConfirm.body.dry_run, true);

    const committed = await applyCandidateReviewActions(pool, 9, {
      action: 'create_iocs',
      candidateIds: [1, 2, 3],
      confirm: true,
      createIoc: async (_p, body) => {
        creates += 1;
        return { status: 201, body: { id: 701, public_id: 'ioc-701', observable_type: 'ip', observable: body.observable } };
      },
      findExistingIoc: async (_p, type, value) => {
        if (value === '203.0.113.60') return { id: 88, public_id: 'ioc-88', observable_type: 'ip' };
        return null;
      },
      user: USER,
      audit: { auditLog: async () => {} }
    });
    assert.equal(committed.ok, true);
    assert.equal(creates, 1);
    assert.equal(committed.summary.created, 1);
    assert.equal(committed.summary.already_existing, 1);
    assert.equal(committed.summary.not_approved, 1);

    // Retry is safe — existing match, no second create.
    const again = await applyCandidateReviewActions(pool, 9, {
      action: 'create_iocs',
      candidateIds: [1],
      confirm: true,
      createIoc: async () => {
        throw new Error('must not create');
      },
      findExistingIoc: async () => ({ id: 701, public_id: 'ioc-701', observable_type: 'ip' }),
      user: USER
    });
    assert.equal(again.ok, true);
    assert.equal(again.summary.created, 0);
    assert.equal(again.summary.already_existing, 1);
    void reviewMod;
  } finally {
    store.getThreatLibraryIocSourceId = orig;
  }
});

test('Create IOCs MCP rejects missing selection (no silent approve-all)', async () => {
  const pool = createPool({ candidates: [cand({ id: 1, review_status: 'approved' })] });
  const out = await mcpThreatLibraryCreateIocs(pool, { report_id: REPORT_PUBLIC, confirm: true }, { user: USER });
  assert.equal(out.status, 400);
  assert.equal(out.error.code, 'CANDIDATE_SELECTION_REQUIRED');
});

test('finalize dry_run reports blockers; finalize succeeds only when eligible', async () => {
  const pendingPool = createPool({
    candidates: [cand({ id: 1, review_status: 'pending' })]
  });
  const blocked = await mcpThreatLibraryFinalizeReport(pendingPool, {
    report_id: REPORT_PUBLIC,
    dry_run: true
  }, { user: USER });
  assert.equal(blocked.status, 200);
  assert.equal(blocked.body.would_finalize, false);
  assert.ok(blocked.body.blockers.some((b) => b.code === 'pending_review_remaining'));

  const readyPool = createPool({
    candidates: [
      cand({ id: 1, review_status: 'approved' }),
      cand({
        id: 2,
        review_status: 'context_only',
        assessment: 'context_only',
        match_state: 'context_only',
        normalized_value: 'cdn.example',
        original_value: 'cdn.example',
        candidate_type: 'domain'
      })
    ]
  });
  const dryOk = await mcpThreatLibraryFinalizeReport(readyPool, {
    report_id: REPORT_PUBLIC,
    dry_run: true
  }, { user: USER });
  assert.equal(dryOk.body.would_finalize, true);

  const done = await mcpThreatLibraryFinalizeReport(readyPool, {
    report_id: REPORT_PUBLIC
  }, { user: USER, audit: { auditLog: async () => {} } });
  assert.equal(done.status, 200);
  assert.equal(done.body.finalized, true);
  assert.equal(readyPool.state.report.analysis_status, 'ready');
});

test('stale expected_revision is rejected', async () => {
  const pool = createPool({ candidates: [cand({ id: 1 })] });
  await withSnapshotStubs(pool, async () => {
    const out = await mcpThreatLibraryReviewIocs(pool, {
      report_id: REPORT_PUBLIC,
      action: 'approve',
      candidate_ids: [1],
      expected_revision: 'stale|0'
    }, { user: USER });
    assert.equal(out.status, 409);
    assert.equal(out.error.code, 'STALE_REPORT');
  });
});

test('workflow status maps stages and next steps', async () => {
  const pool = createPool({
    candidates: [cand({ id: 1, review_status: 'pending' })]
  });
  await withSnapshotStubs(pool, async () => {
    const out = await mcpThreatLibraryGetWorkflowStatus(pool, { report_id: REPORT_PUBLIC });
    assert.equal(out.status, 200);
    assert.equal(out.body.finalized, false);
    assert.ok(out.body.stages.some((s) => s.id === 'review'));
    assert.ok(out.body.remaining_actions.some((a) => a.tool === 'threat_library_review_iocs'));
  });
});

test('unauthorized MCP review tool call is denied at the tool gate', async () => {
  const pool = createPool({ candidates: [cand({ id: 1 })] });
  const { error } = parseTool(await callTool('threat_library_review_iocs', {
    report_id: REPORT_PUBLIC,
    action: 'approve',
    candidate_ids: [1]
  }, { scopes: READ_SCOPES, pool }));
  assert.equal(error.code, 'MISSING_SCOPE');
});

test('linked-source candidate appears in get_review with linked_source_member', async () => {
  const candidates = withLinkedSourceProvenance([
    cand({
      id: 1,
      review_status: 'pending',
      has_original_document_occurrence: false,
      source_assertion: 'linked_source_ioc',
      normalized_value: '198.51.100.9',
      original_value: '198.51.100.9',
      evidence: {
        source_assertion: 'linked_source_ioc',
        document_has_authoritative_scope: true,
        occurrences: []
      }
    })
  ], new Set(['1']));
  assert.equal(candidates[0].has_linked_source_occurrence, true);
  const pool = createPool({ candidates });
  await withSnapshotStubs(pool, async () => {
    const out = await mcpThreatLibraryGetReview(pool, {
      report_id: REPORT_PUBLIC,
      membership: 'linked_only'
    });
    assert.equal(out.status, 200);
    assert.equal(out.body.candidates.total, 1);
    assert.equal(out.body.candidates.items[0].linked_source_member, true);
    assert.equal(out.body.candidates.items[0].linked_only_member, true);
  });
});

test('end-to-end review → approve → create → finalize via shared services', async () => {
  const candidates = [
    cand({ id: 1, review_status: 'pending' }),
    cand({
      id: 2,
      review_status: 'pending',
      normalized_value: 'ignore.me',
      original_value: 'ignore.me',
      candidate_type: 'domain'
    })
  ];
  const pool = createPool({ candidates });
  const store = await import('./threatLibrary/store.js');
  const orig = store.getThreatLibraryIocSourceId;
  store.getThreatLibraryIocSourceId = async () => 4;
  try {
    await applyCandidateReviewActions(pool, 9, {
      action: 'approve',
      candidateIds: [1],
      user: USER
    });
    await applyCandidateReviewActions(pool, 9, {
      action: 'ignore',
      candidateIds: [2],
      user: USER
    });
    assert.equal(pool.state.candidates[0].review_status, 'approved');
    assert.equal(pool.state.candidates[1].review_status, 'ignored');

    const created = await applyCandidateReviewActions(pool, 9, {
      action: 'create_iocs',
      candidateIds: [1, 2],
      confirm: true,
      createIoc: async (_p, body) => ({
        status: 201,
        body: { id: 801, public_id: 'ioc-801', observable_type: 'ip', observable: body.observable }
      }),
      findExistingIoc: async () => null,
      user: USER,
      audit: { auditLog: async () => {} }
    });
    assert.equal(created.summary.created, 1);

    const fin = await finalizeReport(pool, 9, { user: USER, audit: { auditLog: async () => {} } });
    assert.equal(fin.ok, true);
    assert.equal(pool.state.report.import_status, 'ready');
  } finally {
    store.getThreatLibraryIocSourceId = orig;
  }
});

test('reportRevision changes when candidate roster size changes', () => {
  const report = baseReport();
  const a = reportRevision(report, [cand({ id: 1 })]);
  const b = reportRevision(report, [cand({ id: 1 }), cand({ id: 2 })]);
  assert.notEqual(a, b);
});
