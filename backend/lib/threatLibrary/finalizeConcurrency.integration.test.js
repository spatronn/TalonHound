import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { createThreatReport, reconcileReportCandidates } from './store.js';
import { finalizeReport } from './reviewService.js';
import { createManualIocSource, transitionSource } from './iocSources/store.js';
import { upsertDiscoveredSources } from './iocSources/discover.js';
import { createAuditLogService } from '../auditLogService.js';

/**
 * Two-sided real-Postgres concurrency checks of report finalization
 * (tl-report-lifecycle-lock-v1). Competing application writes are held OPEN
 * (uncommitted) on their own connection while finalization runs, in both
 * orders:
 *
 *   A  the mutation starts first; finalize must wait for it, then refuse.
 *   B  finalize holds its lock first; the mutation must wait, then refuse
 *      (the report is finalized), never land an unresolved obligation.
 *
 * Blocking is observed deterministically from pg_stat_activity (the waiting
 * backend reports wait_event_type = 'Lock'), never inferred from a delay.
 * Every scenario asserts the persisted invariant: a finalized report holds no
 * open linked IOC Source and no pending actionable Indicator introduced by the
 * competing write.
 *
 * ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database; run
 * with --test-concurrency=1 alongside the other TL itest files.
 */

const config = {
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound',
  connectionTimeoutMillis: 2000,
  max: 8
};
const pool = new pg.Pool(config);

let hasDb = false;
if (process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1') {
  try {
    await pool.query('SELECT lifecycle_status FROM threat_report_ioc_sources LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };

test.after(async () => {
  await pool.end();
});

const ANALYST = { role: 'analyst' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Resolves true once backend `pid` is waiting on a lock (polls pg_stat_activity). */
async function waitUntilLockWait(pid, timeoutMs = 8000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const { rows } = await pool.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1', [pid]);
    if (rows[0]?.wait_event_type === 'Lock') return true;
    await sleep(20);
  }
  return false;
}

/**
 * Pool for finalizeReport whose transaction is paused right before COMMIT
 * (`pauseBeforeCommit`) or whose guarded UPDATE is announced (`onGuardedUpdate`).
 * It also exposes the backend pid of the finalize connection.
 */
function instrumentedPool({ pauseBeforeCommit = null } = {}) {
  const state = { pid: null, pid$: null };
  let resolvePid;
  state.pid$ = new Promise((r) => { resolvePid = r; });
  const wrap = (client) => ({
    query: async (sql, params) => {
      const text = typeof sql === 'string' ? sql : sql?.text || '';
      if (pauseBeforeCommit && /^\s*COMMIT\b/i.test(text)) await pauseBeforeCommit();
      const res = await client.query(sql, params);
      // Pre-fix code finalizes with an autocommitted UPDATE on the pool: pause after it.
      if (pauseBeforeCommit && !client.__tx && /^\s*UPDATE threat_reports r\b/.test(text)) await pauseBeforeCommit();
      return res;
    },
    release: (...a) => client.release(...a)
  });
  return {
    state,
    query: async (sql, params) => {
      const client = await pool.connect();
      try {
        if (!state.pid) {
          state.pid = (await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
          resolvePid(state.pid);
        }
        return await wrap(client).query(sql, params);
      } finally {
        client.release();
      }
    },
    connect: async () => {
      const client = await pool.connect();
      client.__tx = true;
      state.pid = (await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      resolvePid(state.pid);
      return wrap(client);
    }
  };
}

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

async function setupReport() {
  const report = await createThreatReport(pool, {
    title: `itest-finalize-race-${crypto.randomUUID()}`,
    source_type: 'url',
    source_url: `https://vendor-research.example/${crypto.randomUUID()}`
  });
  await pool.query(`UPDATE threat_reports SET analysis_status = 'review_required', import_status = 'review_required' WHERE id = $1`, [report.id]);
  await pool.query(
    `INSERT INTO threat_report_candidates (
       report_id, candidate_type, original_value, normalized_value, assessment, role, review_status,
       match_state, is_ioc, source_assertion, evidence, has_original_document_occurrence
     ) VALUES ($1,'ip','203.0.113.10','203.0.113.10','malicious','malicious_infrastructure','approved','new',true,'explicit_ioc',
       '{"source_assertion":"explicit_ioc","document_has_authoritative_scope":true}'::jsonb, true)`,
    [report.id]
  );
  return report;
}

/** Existing approved row + one new pending explicit-IOC row (what an extract / refresh would add). */
function reconcileSet() {
  const ev = { source_assertion: 'explicit_ioc', document_has_authoritative_scope: true };
  return [
    { candidate_type: 'ip', original_value: '203.0.113.10', normalized_value: '203.0.113.10', assessment: 'malicious', role: 'malicious_infrastructure', review_status: 'approved', match_state: 'new', is_ioc: true, source_assertion: 'explicit_ioc', evidence: ev },
    { candidate_type: 'ip', original_value: '203.0.113.77', normalized_value: '203.0.113.77', assessment: 'malicious', role: 'malicious_infrastructure', review_status: 'pending', match_state: 'new', is_ioc: true, source_assertion: 'explicit_ioc', evidence: ev }
  ];
}

async function addSource(reportId, lifecycle) {
  const url = `https://github.com/vendor/iocs/tree/main/${crypto.randomUUID()}`;
  const { rows } = await pool.query(
    `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, source_type, discovery_method, discovery_evidence, lifecycle_status)
     VALUES ($1,$2,$2,'github_dir','auto','{}'::jsonb,$3) RETURNING *`,
    [reportId, url, lifecycle]
  );
  return rows[0];
}

async function cleanup(reportId) {
  await pool.query(`DELETE FROM threat_report_candidate_source_links WHERE candidate_id IN (SELECT id FROM threat_report_candidates WHERE report_id = $1)`, [reportId]);
  await pool.query(`DELETE FROM threat_report_ioc_sources WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_report_candidates WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM audit_logs WHERE entity_id = (SELECT public_id::text FROM threat_reports WHERE id = $1)`, [reportId]);
  await pool.query(`DELETE FROM threat_reports WHERE id = $1`, [reportId]);
}

async function persisted(reportId) {
  const { rows: [r] } = await pool.query(
    `SELECT analysis_status, finalized_at,
       (SELECT count(*)::int FROM threat_report_ioc_sources s WHERE s.report_id = r.id
          AND s.lifecycle_status NOT IN ('extracted','dismissed')) AS open_sources,
       (SELECT count(*)::int FROM threat_report_candidates c WHERE c.report_id = r.id AND c.review_status = 'pending') AS pending
     FROM threat_reports r WHERE id = $1`,
    [reportId]
  );
  return { finalized: r.analysis_status === 'ready', finalized_at: r.finalized_at, open_sources: r.open_sources, pending: r.pending };
}

/** The invariant: a finalized report never carries an obligation the competing write introduced. */
function assertInvariant(state, label) {
  if (state.finalized) {
    assert.equal(state.open_sources, 0, `${label}: finalized with an open linked IOC Source`);
    assert.equal(state.pending, 0, `${label}: finalized with a pending Indicator`);
  }
}

/** Order A: `mutate(client)` runs in an open transaction; finalize starts; then the mutation commits. */
async function orderA(reportId, mutate) {
  const client = await pool.connect();
  const fin = instrumentedPool();
  let finalize;
  let waited = false;
  try {
    await client.query('BEGIN');
    await mutate(client);
    finalize = finalizeReport(fin, reportId, { user: ANALYST });
    const pid = await Promise.race([fin.state.pid$, sleep(5000).then(() => null)]);
    waited = pid ? await Promise.race([waitUntilLockWait(pid, 3000), finalize.then(() => false)]) : false;
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
  return { result: await finalize, waited };
}

/** Order B: finalize holds its lock (paused before COMMIT); `mutate(client)` starts; then finalize commits. */
async function orderB(reportId, mutate) {
  const gate = deferred();
  const reached = deferred();
  const fin = instrumentedPool({ pauseBeforeCommit: async () => { reached.resolve(); await gate.promise; } });
  const finalize = finalizeReport(fin, reportId, { user: ANALYST });
  await Promise.race([reached.promise, finalize]);
  const client = await pool.connect();
  const mutPid = (await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
  let mutation;
  try {
    await client.query('BEGIN');
    mutation = mutate(client).then((v) => ({ ok: true, value: v }), (err) => ({ ok: false, err }));
    const waited = await Promise.race([waitUntilLockWait(mutPid, 3000), mutation.then(() => false)]);
    gate.resolve();
    const finResult = await finalize;
    const mut = await mutation;
    if (mut.ok) await client.query('COMMIT');
    else await client.query('ROLLBACK').catch(() => {});
    return { finResult, mut, waited };
  } finally {
    gate.resolve();
    client.release();
  }
}

test('A1 new IOC Source vs finalize: finalize waits for the open insert, then refuses', opts, async () => {
  const report = await setupReport();
  try {
    const { result, waited } = await orderA(report.id, (c) => createManualIocSource(c, report.id, { url: `https://vendor.example/${crypto.randomUUID()}/iocs.csv` }));
    assert.equal(waited, true, 'finalize must wait for the in-flight source insert');
    assert.equal(result.ok, false);
    assert.equal(result.code, 'linked_ioc_sources_unresolved');
    const s = await persisted(report.id);
    assert.equal(s.finalized, false);
    assertInvariant(s, 'A1');
  } finally {
    await cleanup(report.id);
  }
});

test('A2 IOC Source status change (extracted → inspecting) vs finalize: finalize waits, then refuses', opts, async () => {
  const report = await setupReport();
  try {
    const source = await addSource(report.id, 'extracted');
    const { result, waited } = await orderA(report.id, (c) => transitionSource(c, source, 'start_inspect'));
    assert.equal(waited, true, 'finalize must wait for the in-flight source transition');
    assert.equal(result.code, 'linked_ioc_sources_unresolved');
    const s = await persisted(report.id);
    assert.equal(s.finalized, false);
    assertInvariant(s, 'A2');
  } finally {
    await cleanup(report.id);
  }
});

test('A3 new pending Indicator (reconcile) vs finalize: finalize waits, then refuses', opts, async () => {
  const report = await setupReport();
  try {
    const { result, waited } = await orderA(report.id, (c) => reconcileReportCandidates(c, report.id, reconcileSet()));
    assert.equal(waited, true, 'finalize must wait for the in-flight candidate reconcile');
    assert.equal(result.code, 'pending_review_remaining');
    const s = await persisted(report.id);
    assert.equal(s.finalized, false);
    assertInvariant(s, 'A3');
  } finally {
    await cleanup(report.id);
  }
});

test('B1 finalize vs new IOC Source: the insert waits, then refuses on the finalized report', opts, async () => {
  const report = await setupReport();
  try {
    const { finResult, mut, waited } = await orderB(report.id, (c) => createManualIocSource(c, report.id, { url: `https://vendor.example/${crypto.randomUUID()}/iocs.csv` }));
    assert.equal(finResult.ok, true, JSON.stringify(finResult));
    assert.equal(waited, true, 'the source insert must wait for the finalize lock');
    assert.equal(mut.ok, false, 'a source cannot be added to a finalized report');
    assert.equal(mut.err?.code, 'report_finalized');
    const s = await persisted(report.id);
    assert.equal(s.finalized, true);
    assertInvariant(s, 'B1');
  } finally {
    await cleanup(report.id);
  }
});

test('B2 finalize vs automatic discovery: discovery waits, then records nothing on the finalized report', opts, async () => {
  const report = await setupReport();
  try {
    const { finResult, mut, waited } = await orderB(report.id, (c) => upsertDiscoveredSources(c, report.id, [
      { original_url: `https://github.com/vendor/iocs/tree/main/${crypto.randomUUID()}`, discovery_evidence: {} }
    ]));
    assert.equal(finResult.ok, true);
    assert.equal(waited, true, 'discovery must wait for the finalize lock');
    const s = await persisted(report.id);
    assert.equal(s.finalized, true);
    assertInvariant(s, 'B2');
    if (mut.ok) assert.equal(mut.value.inserted, 0);
  } finally {
    await cleanup(report.id);
  }
});

test('B3 finalize vs new pending Indicator (reconcile): the reconcile waits, then refuses', opts, async () => {
  const report = await setupReport();
  try {
    const { finResult, mut, waited } = await orderB(report.id, (c) => reconcileReportCandidates(c, report.id, reconcileSet()));
    assert.equal(finResult.ok, true);
    assert.equal(waited, true, 'the reconcile must wait for the finalize lock');
    assert.equal(mut.ok, false);
    assert.equal(mut.err?.code, 'report_finalized');
    const s = await persisted(report.id);
    assert.equal(s.finalized, true);
    assertInvariant(s, 'B3');
  } finally {
    await cleanup(report.id);
  }
});

test('B4 finalize vs reopening a resolved source (extracted → inspecting): refused', opts, async () => {
  const report = await setupReport();
  try {
    const source = await addSource(report.id, 'extracted');
    const { finResult, mut, waited } = await orderB(report.id, (c) => transitionSource(c, source, 'start_inspect'));
    assert.equal(finResult.ok, true);
    assert.equal(waited, true);
    assert.equal(mut.ok, false);
    assert.equal(mut.err?.code, 'report_finalized');
    assertInvariant(await persisted(report.id), 'B4');
  } finally {
    await cleanup(report.id);
  }
});

test('resolving obligations stays allowed on a finalized report (dismiss an open source)', opts, async () => {
  const report = await setupReport();
  try {
    const source = await addSource(report.id, 'discovered');
    await pool.query(`UPDATE threat_reports SET analysis_status = 'ready', import_status = 'ready', finalized_at = NOW() WHERE id = $1`, [report.id]);
    const updated = await transitionSource(pool, source, 'dismiss', {});
    assert.equal(updated.lifecycle_status, 'dismissed');
  } finally {
    await cleanup(report.id);
  }
});

test('deadlock: a mutation that also updates the report row while finalize is queued completes without 40P01', opts, async () => {
  const report = await setupReport();
  try {
    const { result } = await orderA(report.id, async (c) => {
      await reconcileReportCandidates(c, report.id, reconcileSet());
      // A refresh restores the report status in the same transaction.
      await sleep(100);
      await c.query(`UPDATE threat_reports SET analysis_progress = COALESCE(analysis_progress, '{}'::jsonb) || '{"itest":1}'::jsonb WHERE id = $1`, [report.id]);
    });
    assert.notEqual(result?.code, '40P01');
    assert.equal(result.code, 'pending_review_remaining');
    assertInvariant(await persisted(report.id), 'deadlock');
  } finally {
    await cleanup(report.id);
  }
});

test('duplicate concurrent finalize: one write, one audit, the other is a no-op', opts, async () => {
  const report = await setupReport();
  try {
    await addSource(report.id, 'failed');
    const audit = createAuditLogService(pool);
    const admin = { role: 'admin' };
    const req = { sourceOverride: { reason: 'pack duplicates the article tables exactly' }, user: admin, audit };
    const [a, b] = await Promise.all([finalizeReport(pool, report.id, req), finalizeReport(pool, report.id, req)]);
    assert.equal(a.ok && b.ok, true, JSON.stringify([a, b]));
    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM audit_logs WHERE entity_id = $1 AND metadata ? 'linked_source_override'`,
      [report.public_id]
    );
    assert.equal(rows[0].n, 1, 'exactly one override audit row');
  } finally {
    await cleanup(report.id);
  }
});

async function withAuditFailureTrigger(fn, { deferredAtCommit = false } = {}) {
  const name = `itest_audit_fail_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;
  await pool.query(`CREATE FUNCTION ${name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.metadata ? 'linked_source_override' THEN RAISE EXCEPTION 'itest audit failure'; END IF; RETURN NEW; END $$`);
  if (deferredAtCommit) {
    await pool.query(`CREATE CONSTRAINT TRIGGER ${name} AFTER INSERT ON audit_logs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ${name}()`);
  } else {
    await pool.query(`CREATE TRIGGER ${name} BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION ${name}()`);
  }
  try {
    return await fn();
  } finally {
    await pool.query(`DROP TRIGGER IF EXISTS ${name} ON audit_logs`);
    await pool.query(`DROP FUNCTION IF EXISTS ${name}()`);
  }
}

test('override audit is durable with the finalize: success commits both', opts, async () => {
  const report = await setupReport();
  try {
    await addSource(report.id, 'failed');
    const r = await finalizeReport(pool, report.id, { user: { role: 'admin' }, audit: createAuditLogService(pool), sourceOverride: { reason: 'pack duplicates the article tables exactly' } });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal((await persisted(report.id)).finalized, true);
    const { rows } = await pool.query(`SELECT severity, metadata FROM audit_logs WHERE entity_id = $1 AND metadata ? 'linked_source_override'`, [report.public_id]);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].severity, 'warning');
  } finally {
    await cleanup(report.id);
  }
});

test('override audit insert failure rolls the finalize back', opts, async () => {
  const report = await setupReport();
  try {
    await addSource(report.id, 'failed');
    const r = await withAuditFailureTrigger(() => finalizeReport(pool, report.id, {
      user: { role: 'admin' }, audit: createAuditLogService(pool), sourceOverride: { reason: 'pack duplicates the article tables exactly' }
    }).catch((err) => ({ ok: false, thrown: err.message })));
    assert.equal(r.ok, false);
    assert.equal((await persisted(report.id)).finalized, false, 'no finalize without its audit row');
  } finally {
    await cleanup(report.id);
  }
});

test('a transaction abort at COMMIT leaves neither the override nor an orphaned audit row', opts, async () => {
  const report = await setupReport();
  try {
    await addSource(report.id, 'failed');
    const r = await withAuditFailureTrigger(() => finalizeReport(pool, report.id, {
      user: { role: 'admin' }, audit: createAuditLogService(pool), sourceOverride: { reason: 'pack duplicates the article tables exactly' }
    }).catch((err) => ({ ok: false, thrown: err.message })), { deferredAtCommit: true });
    assert.equal(r.ok, false);
    assert.equal((await persisted(report.id)).finalized, false);
    const { rows } = await pool.query(`SELECT count(*)::int AS n FROM audit_logs WHERE entity_id = $1`, [report.public_id]);
    assert.equal(rows[0].n, 0, 'no orphaned audit row');
  } finally {
    await cleanup(report.id);
  }
});

test('override authorization and pending review stay enforced on real Postgres', opts, async () => {
  const report = await setupReport();
  try {
    await addSource(report.id, 'failed');
    const audit = createAuditLogService(pool);
    const reason = 'pack duplicates the article tables exactly';
    assert.equal((await finalizeReport(pool, report.id, { user: ANALYST, audit, sourceOverride: { reason } })).code, 'finalize_override_forbidden');
    assert.equal((await finalizeReport(pool, report.id, { user: { role: 'admin' }, audit, sourceOverride: { reason: 'short' } })).code, 'finalize_override_reason_required');
    await pool.query(`UPDATE threat_report_candidates SET review_status = 'pending' WHERE report_id = $1`, [report.id]);
    assert.equal((await finalizeReport(pool, report.id, { user: { role: 'admin' }, audit, sourceOverride: { reason } })).code, 'pending_review_remaining');
    assert.equal((await persisted(report.id)).finalized, false);
  } finally {
    await cleanup(report.id);
  }
});

test('reopen: an explicit reasoned reopen (durable audit) is the only way to add sources again', opts, async () => {
  const { reopenReport } = await import('./reviewService.js');
  const report = await setupReport();
  try {
    const audit = createAuditLogService(pool);
    assert.equal((await finalizeReport(pool, report.id, { user: ANALYST, audit })).ok, true);
    await assert.rejects(
      () => createManualIocSource(pool, report.id, { url: `https://vendor.example/${crypto.randomUUID()}/iocs.csv` }),
      (err) => err.code === 'report_finalized'
    );
    assert.equal((await reopenReport(pool, report.id, { user: ANALYST, audit, reason: 'short' })).code, 'reopen_reason_required');
    assert.equal((await reopenReport(pool, report.id, { user: ANALYST, reason: 'publisher added a STIX pack after finalization' })).code, 'reopen_audit_unavailable');
    const r = await reopenReport(pool, report.id, { user: ANALYST, audit, reason: 'publisher added a STIX pack after finalization' });
    assert.equal(r.ok, true, JSON.stringify(r));
    const { rows } = await pool.query(`SELECT action, severity, metadata->>'reason' AS reason FROM audit_logs WHERE entity_id = $1 AND action = 'threat_library.report.reopened'`, [report.public_id]);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].severity, 'warning');
    const s = await createManualIocSource(pool, report.id, { url: `https://vendor.example/${crypto.randomUUID()}/iocs.csv` });
    assert.equal(s.lifecycle_status, 'discovered');
    assert.equal((await finalizeReport(pool, report.id, { user: ANALYST, audit })).code, 'linked_ioc_sources_unresolved');
    assert.equal((await reopenReport(pool, report.id, { user: ANALYST, audit, reason: 'publisher added a STIX pack after finalization' })).code, 'report_not_finalized');
  } finally {
    await cleanup(report.id);
  }
});

test('reopen audit insert failure leaves the report finalized', opts, async () => {
  const { reopenReport } = await import('./reviewService.js');
  const report = await setupReport();
  try {
    const audit = createAuditLogService(pool);
    assert.equal((await finalizeReport(pool, report.id, { user: ANALYST, audit })).ok, true);
    const name = `itest_reopen_fail_${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;
    await pool.query(`CREATE FUNCTION ${name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
      IF NEW.action = 'threat_library.report.reopened' THEN RAISE EXCEPTION 'itest audit failure'; END IF; RETURN NEW; END $$`);
    await pool.query(`CREATE TRIGGER ${name} BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION ${name}()`);
    try {
      await assert.rejects(() => reopenReport(pool, report.id, { user: ANALYST, audit, reason: 'publisher added a STIX pack after finalization' }));
    } finally {
      await pool.query(`DROP TRIGGER IF EXISTS ${name} ON audit_logs`);
      await pool.query(`DROP FUNCTION IF EXISTS ${name}()`);
    }
    assert.equal((await persisted(report.id)).finalized, true);
  } finally {
    await cleanup(report.id);
  }
});

// --- Re-finalization paths (restore to a finalized status) -------------------

test('restore to ready after a refresh window re-checks obligations: an open source reopens the report', opts, async () => {
  const { restoreReportStatus } = await import('./store.js');
  const report = await setupReport();
  try {
    // A finalized report claimed by a maintenance job (Refresh extraction) is
    // out of the finalized phase; a source added in that window is allowed…
    await pool.query(`UPDATE threat_reports SET analysis_status = 'pending', import_status = 'processing' WHERE id = $1`, [report.id]);
    await createManualIocSource(pool, report.id, { url: `https://vendor.example/${crypto.randomUUID()}/iocs.csv` });
    // …and restoring the prior "ready" must not re-finalize it with that source open.
    const row = await restoreReportStatus(pool, report.id, { analysis_status: 'ready', import_status: 'ready' }, { stage: 'ready' });
    assert.equal(row.analysis_status, 'review_required');
    assert.equal(row.analysis_progress.restore_guard.open_sources, 1);
    assert.equal(row.analysis_progress.restore_guard.reopened_for_review, true);
    assertInvariant(await persisted(report.id), 'restore');
  } finally {
    await cleanup(report.id);
  }
});

test('restore to ready with nothing open stays finalized', opts, async () => {
  const { restoreReportStatus } = await import('./store.js');
  const report = await setupReport();
  try {
    await pool.query(`UPDATE threat_reports SET analysis_status = 'pending', import_status = 'processing' WHERE id = $1`, [report.id]);
    const row = await restoreReportStatus(pool, report.id, { analysis_status: 'ready', import_status: 'ready' }, { stage: 'ready' });
    assert.equal(row.analysis_status, 'ready');
    assert.equal(row.analysis_progress.restore_guard, undefined);
  } finally {
    await cleanup(report.id);
  }
});

test('race: restore to ready waits for an in-flight source insert, then reopens', opts, async () => {
  const { restoreReportStatus } = await import('./store.js');
  const report = await setupReport();
  try {
    await pool.query(`UPDATE threat_reports SET analysis_status = 'pending', import_status = 'processing' WHERE id = $1`, [report.id]);
    const client = await pool.connect();
    let restore;
    let waited = false;
    try {
      await client.query('BEGIN');
      await createManualIocSource(client, report.id, { url: `https://vendor.example/${crypto.randomUUID()}/iocs.csv` });
      const fin = instrumentedPool();
      restore = restoreReportStatus(fin, report.id, { analysis_status: 'ready', import_status: 'ready' }, { stage: 'ready' });
      const pid = await Promise.race([fin.state.pid$, sleep(5000).then(() => null)]);
      waited = pid ? await Promise.race([waitUntilLockWait(pid, 3000), restore.then(() => false)]) : false;
      await client.query('COMMIT');
    } finally {
      client.release();
    }
    const row = await restore;
    assert.equal(waited, true, 'the restore must wait for the in-flight source insert');
    assert.equal(row.analysis_status, 'review_required');
    assertInvariant(await persisted(report.id), 'restore race');
  } finally {
    await cleanup(report.id);
  }
});

test('Refresh extraction of a finalized report never re-finalizes it over an open source', opts, async () => {
  const { runExtractionRefresh } = await import('./extractionRefresh.js');
  const { buildLayoutVariant } = await import('./benchmark/layoutVariants.js');
  const { extractReportCandidates } = await import('./extractionStages.js');
  const { createJob, candidateColumns } = await import('./store.js');
  const variant = buildLayoutVariant('html_c2_then_loaders/table');
  const report = await createThreatReport(pool, { title: `itest-refresh-refinalize-${crypto.randomUUID()}`, source_type: 'url', source_url: variant.sourceUrl });
  try {
    const extracted = extractReportCandidates({ source_type: 'url', source_url: variant.sourceUrl }, variant.document);
    await pool.query(`UPDATE threat_reports SET canonical_document = $2::jsonb WHERE id = $1`, [report.id, JSON.stringify(extracted.document)]);
    for (const c of extracted.candidates) {
      const col = candidateColumns(c);
      await pool.query(
        `INSERT INTO threat_report_candidates (report_id, candidate_type, original_value, normalized_value, assessment, role, review_status, match_state, is_ioc, source_assertion, evidence, has_original_document_occurrence)
         VALUES ($1,$2,$3,$4,$5,$6,'approved',$7,$8,$9,$10::jsonb,$11)`,
        [report.id, col.candidate_type, col.original_value, col.normalized_value, col.assessment, col.role, col.match_state, col.is_ioc, col.source_assertion, JSON.stringify(col.evidence), col.has_original_document_occurrence !== false]
      );
    }
    // Claimed for maintenance (the route / CLI claim), with a source added in the window.
    await pool.query(`UPDATE threat_reports SET analysis_status = 'pending', import_status = 'processing', finalized_at = NOW() WHERE id = $1`, [report.id]);
    await createManualIocSource(pool, report.id, { url: `https://vendor.example/${crypto.randomUUID()}/iocs.csv` });
    const job = await createJob(pool, { reportId: report.id, jobType: 'refresh_extraction' });
    const res = await runExtractionRefresh(pool, { reportId: report.id, jobId: job.id, restoreStatus: { analysis_status: 'ready', import_status: 'ready' } });
    assert.equal(res.ok, true, JSON.stringify(res));
    const s = await persisted(report.id);
    assert.equal(s.finalized, false, 'an open source keeps the refreshed report in review');
    assertInvariant(s, 'refresh');
    await pool.query(`DELETE FROM threat_library_jobs WHERE report_id = $1`, [report.id]);
  } finally {
    await pool.query(`DELETE FROM threat_library_jobs WHERE report_id = $1`, [report.id]).catch(() => {});
    await cleanup(report.id);
  }
});
