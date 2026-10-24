/**
 * Guarded finalization (tl-finalize-guard-v1): linked IOC Sources must be
 * extracted or dismissed before a report is finalized; the write re-checks;
 * an administrator override is reasoned and audited; nothing is reopened.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  FINALIZE_BLOCKER_CODES,
  GUARDED_FINALIZE_SQL,
  LINKED_SOURCE_OPEN_STATUSES,
  finalizeBlockers,
  linkedSourceBlocker,
  openLinkedSources,
  validateSourceOverride
} from './finalizeGuard.js';
import { finalizeReport } from './reviewService.js';
import { summarizeLinkedIocSources } from './iocSources/linkedSourceStatus.js';
import { IOC_SOURCE_LIFECYCLE } from './iocSources/constants.js';
import { reviewActionableIndicatorSql } from './indicatorMembership.js';

const report = { id: 9, public_id: 'rep-9', analysis_status: 'review_required', title: 'Campaign', source_url: null };
const approved = { id: 1, candidate_type: 'ip', normalized_value: '203.0.113.10', original_value: '203.0.113.10', assessment: 'malicious', review_status: 'approved', match_state: 'new', is_ioc: true, has_original_document_occurrence: true, source_assertion: 'explicit_ioc', evidence: {} };

/**
 * Stub pool. `sourcesSeq` returns successive source lists (to model a source
 * appearing between the read and the write); the guarded UPDATE applies the
 * same rule against the latest list.
 */
function pool({ candidates = [approved], sourcesSeq = [[]], reportRow = report } = {}) {
  const state = { writes: [], reads: 0, report: { ...reportRow } };
  const latest = () => sourcesSeq[Math.min(state.reads, sourcesSeq.length - 1)];
  return {
    state,
    async query(sql, params) {
      if (/FROM threat_reports WHERE id = \$1/.test(sql) && /^\s*SELECT/i.test(sql)) return { rows: [state.report] };
      if (/FROM threat_report_candidates/.test(sql) && /^\s*SELECT/i.test(sql)) return { rows: candidates };
      if (/FROM threat_report_ioc_sources/.test(sql) && /^\s*SELECT/i.test(sql)) {
        const rows = sourcesSeq[Math.min(state.reads, sourcesSeq.length - 1)];
        state.reads += 1;
        return { rows };
      }
      if (/^\s*UPDATE threat_reports r/.test(sql)) {
        state.writes.push({ sql, params });
        const open = new Set(params[2]);
        if (params[1] !== true && latest().some((s) => open.has(s.lifecycle_status))) return { rows: [], rowCount: 0 };
        state.report.finalized_at = 'now';
        return { rows: [state.report], rowCount: 1 };
      }
      state.writes.push({ sql, params });
      return { rows: [] };
    }
  };
}

const auditSink = () => {
  const events = [];
  return { events, audit: { auditLog: async (e) => events.push(e), auditSuccess: async (e) => events.push(e) } };
};

test('every lifecycle status is classified: resolved, pending or unresolved', () => {
  const resolved = new Set([IOC_SOURCE_LIFECYCLE.EXTRACTED, IOC_SOURCE_LIFECYCLE.DISMISSED]);
  for (const status of Object.values(IOC_SOURCE_LIFECYCLE)) {
    const open = openLinkedSources([{ lifecycle_status: status }]).length === 1;
    assert.equal(open, !resolved.has(status), status);
    assert.equal(LINKED_SOURCE_OPEN_STATUSES.includes(status), !resolved.has(status), status);
  }
  // Read-time quality overlay and the guard agree on what is open.
  const rows = Object.values(IOC_SOURCE_LIFECYCLE).map((s) => ({ lifecycle_status: s }));
  const summary = summarizeLinkedIocSources(rows);
  assert.equal(summary.pending + summary.unresolved, openLinkedSources(rows).length);
});

test('blockers: pending, failed and unsupported sources block; extracted / dismissed do not', () => {
  assert.deepEqual(finalizeBlockers({ pendingCount: 0, sources: [{ lifecycle_status: 'extracted' }, { lifecycle_status: 'dismissed' }] }), []);
  const b = finalizeBlockers({ pendingCount: 0, sources: [{ public_id: 'a', lifecycle_status: 'discovered' }, { public_id: 'b', lifecycle_status: 'failed', error_code: 'no_indicators' }] });
  assert.equal(b.length, 1);
  assert.equal(b[0].code, FINALIZE_BLOCKER_CODES.LINKED_SOURCES);
  assert.deepEqual(b[0].sources.map((s) => [s.public_id, s.state]), [['a', 'pending'], ['b', 'unresolved']]);
  assert.equal(b[0].message, linkedSourceBlocker({ pending: 1, unresolved: 1 }).message);
  assert.equal(linkedSourceBlocker({ pending: 0, unresolved: 0 }), null);
  // Override lifts only the source rule, never pending review.
  const both = finalizeBlockers({ pendingCount: 2, sources: [{ lifecycle_status: 'discovered' }], sourceOverride: true });
  assert.deepEqual(both.map((x) => x.code), [FINALIZE_BLOCKER_CODES.PENDING_REVIEW]);
});

test('the guarded write re-checks pending review and open sources in one statement', () => {
  assert.match(GUARDED_FINALIZE_SQL, /UPDATE threat_reports r/);
  assert.match(GUARDED_FINALIZE_SQL, /finalized_at = NOW\(\)/);
  assert.ok(GUARDED_FINALIZE_SQL.includes(reviewActionableIndicatorSql('c')));
  assert.match(GUARDED_FINALIZE_SQL, /COALESCE\(c\.review_status, 'pending'\) = 'pending'/);
  assert.match(GUARDED_FINALIZE_SQL, /\$2::boolean OR NOT EXISTS[\s\S]*threat_report_ioc_sources[\s\S]*lifecycle_status = ANY\(\$3::text\[\]\)/);
});

test('finalize is refused while a linked source is pending, with no write', async () => {
  const p = pool({ sourcesSeq: [[{ public_id: 'src-1', lifecycle_status: 'discovered', original_url: 'https://github.com/v/iocs/tree/main/x' }]] });
  const r = await finalizeReport(p, 9, { user: { role: 'analyst' } });
  assert.equal(r.ok, false);
  assert.equal(r.status, 409);
  assert.equal(r.code, 'linked_ioc_sources_unresolved');
  assert.deepEqual(r.linked_sources.map((s) => s.public_id), ['src-1']);
  assert.equal(p.state.writes.length, 0);
});

test('a failed / unsupported source blocks too; extracted + dismissed finalize', async () => {
  const failed = pool({ sourcesSeq: [[{ public_id: 's', lifecycle_status: 'unsupported' }]] });
  assert.equal((await finalizeReport(failed, 9, { user: { role: 'analyst' } })).code, 'linked_ioc_sources_unresolved');
  const ok = pool({ sourcesSeq: [[{ public_id: 'a', lifecycle_status: 'extracted' }, { public_id: 'b', lifecycle_status: 'dismissed' }]] });
  const { events, audit } = auditSink();
  const r = await finalizeReport(ok, 9, { user: { role: 'analyst' }, audit });
  assert.equal(r.ok, true);
  assert.equal(ok.state.writes.length, 1);
  assert.match(ok.state.writes[0].sql, /UPDATE threat_reports r/);
  assert.equal(events.length, 1);
  assert.equal(events[0].severity, 'info');
  assert.equal(events[0].metadata.linked_source_override, undefined);
});

test('a source appearing between the read and the write cannot bypass the guard', async () => {
  const appeared = [{ public_id: 'late', lifecycle_status: 'discovered' }];
  const p = pool({ sourcesSeq: [[], appeared] });
  const r = await finalizeReport(p, 9, { user: { role: 'analyst' } });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'linked_ioc_sources_unresolved');
  assert.deepEqual(r.linked_sources.map((s) => s.public_id), ['late']);
  assert.equal(p.state.report.finalized_at, undefined);
});

test('override: administrator only, with a written reason; audited as a warning', async () => {
  const sources = [[{ public_id: 'src-1', lifecycle_status: 'failed', original_url: 'https://user:secret@vendor.example/iocs.csv' }]];
  const analyst = await finalizeReport(pool({ sourcesSeq: sources }), 9, { user: { role: 'analyst' }, sourceOverride: { reason: 'pack is a duplicate of the article tables' } });
  assert.equal(analyst.status, 403);
  assert.equal(analyst.code, 'finalize_override_forbidden');
  const unaudited = pool({ sourcesSeq: sources });
  const noAudit = await finalizeReport(unaudited, 9, { user: { role: 'admin' }, sourceOverride: { reason: 'pack is a duplicate of the article tables' } });
  assert.equal(noAudit.status, 503);
  assert.equal(noAudit.code, 'finalize_override_audit_unavailable');
  assert.equal(unaudited.state.writes.length, 0);
  const short = await finalizeReport(pool({ sourcesSeq: sources }), 9, { user: { role: 'admin' }, sourceOverride: { reason: 'dup' } });
  assert.equal(short.status, 400);
  assert.equal(short.code, 'finalize_override_reason_required');

  const p = pool({ sourcesSeq: sources });
  const { events, audit } = auditSink();
  const r = await finalizeReport(p, 9, { user: { role: 'admin' }, audit, sourceOverride: { reason: 'pack is a duplicate of the article tables' } });
  assert.equal(r.ok, true);
  assert.equal(p.state.writes[0].params[1], true);
  assert.equal(events.length, 1);
  assert.equal(events[0].severity, 'warning');
  const meta = events[0].metadata.linked_source_override;
  assert.equal(meta.reason, 'pack is a duplicate of the article tables');
  assert.deepEqual(meta.sources.map((s) => s.public_id), ['src-1']);
  assert.doesNotMatch(meta.sources[0].url, /secret/);
  // The override never lifts pending review.
  const pending = pool({ candidates: [{ ...approved, review_status: 'pending' }], sourcesSeq: sources });
  const blocked = await finalizeReport(pending, 9, { user: { role: 'admin' }, sourceOverride: { reason: 'pack is a duplicate of the article tables' } });
  assert.equal(blocked.code, 'pending_review_remaining');
});

test('validateSourceOverride is null when no override is requested', () => {
  assert.equal(validateSourceOverride(null, { role: 'admin' }), null);
  assert.equal(validateSourceOverride(undefined, null), null);
});

test('a finalized report is never reopened: a blocked re-finalize writes nothing', async () => {
  const finalized = { ...report, analysis_status: 'ready', import_status: 'ready', finalized_at: '2026-10-21T19:29:00Z' };
  const p = pool({ reportRow: finalized, sourcesSeq: [[{ public_id: 'src-8', lifecycle_status: 'discovered' }]] });
  const r = await finalizeReport(p, 9, { user: { role: 'analyst' } });
  assert.equal(r.ok, false);
  assert.equal(p.state.writes.length, 0);
  assert.equal(p.state.report.finalized_at, '2026-10-21T19:29:00Z');
  assert.equal(p.state.report.analysis_status, 'ready');
});

test('no bypass: the status store refuses to finalize and only the guarded statement sets finalized_at', async () => {
  const { updateReportStatus } = await import('./store.js');
  const pool = { query: async () => { throw new Error('must not query'); } };
  await assert.rejects(() => updateReportStatus(pool, 9, { import_status: 'ready', finalize: true }), /cannot finalize/);

  const fs = await import('node:fs');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const backend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const writers = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(?:m?js)$/.test(e.name) && !/\.test\.m?js$/.test(e.name)) {
        if (/finalized_at\s*=\s*(?:NOW\(\)|CASE WHEN \$\d+ THEN NOW\(\))/i.test(fs.readFileSync(p, 'utf8'))) {
          writers.push(path.relative(backend, p).split(path.sep).join('/'));
        }
      }
    }
  };
  for (const d of ['lib', 'routes', 'scripts', 'services', 'workers']) {
    if (fs.existsSync(path.join(backend, d))) walk(path.join(backend, d));
  }
  // store.js keeps the inert CASE for its fixed parameter list ($17 is always false).
  assert.deepEqual(writers.sort(), ['lib/threatLibrary/finalizeGuard.js', 'lib/threatLibrary/store.js']);
});
