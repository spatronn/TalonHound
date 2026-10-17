import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { candidateColumns, createJob, createThreatReport } from './store.js';
import { REFRESH_BLOCKED_CODE, REFRESH_CONCURRENT_CHANGE_CODE, previewExtractionRefresh, runExtractionRefresh } from './extractionRefresh.js';
import { extractReportCandidates } from './extractionStages.js';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { isReportIndicatorMember } from './indicatorMembership.js';

/**
 * Real-Postgres proof of the P1 hotfix (membership reconciliation + IOC link
 * guard). The stored rows reproduce the production shape: an incomplete URL
 * prefix that an older contract read as a publisher C2 Indicator, approved and
 * created as a global IOC; the current extraction reads it as non-IOC.
 *
 * Verified on the FINAL STORED STATE (rows, IOC records, IOC Source links,
 * report progress), not only on preview responses.
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
  max: 4
};
const pool = new pg.Pool(config);
const other = new pg.Pool({ ...config, max: 2 });

let hasDb = false;
if (process.env.ALLOW_THREAT_LIBRARY_DB_TESTS === '1') {
  try {
    await pool.query('SELECT has_original_document_occurrence FROM threat_report_candidates LIMIT 0');
    hasDb = true;
  } catch {
    hasDb = false;
  }
}
const opts = { skip: hasDb ? false : 'set ALLOW_THREAT_LIBRARY_DB_TESTS=1 with a migrated throwaway database to run' };

test.after(async () => {
  await pool.end();
  await other.end();
});

const SOURCE = 'https://vendor-research.example/blog/itest-ioc-links/';
const PREFIX = 'http://203.0.113.50:443/t/';
const RESTORE = { analysis_status: 'review_required', import_status: 'ready' };
const LOCK_SQL_RE = /FROM threat_report_candidates WHERE report_id = \$1 ORDER BY id FOR UPDATE/;

function documentFor() {
  const html = `<!doctype html><html lang="en"><head><title>Links</title></head><body><article>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
<h2>Indicators of compromise</h2>
<h3>C2 URLs</h3>
<pre>${PREFIX}
${PREFIX}a779ab
${PREFIX}ae7427</pre>
<h3>Domains</h3><ul><li>evil-c2[.]example</li><li>bad-relay[.]example</li><li>third-hop[.]example</li></ul>
<h2>Conclusion</h2><p>The actor continues to evolve its toolset.</p>
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
}

async function insertIoc(observable, type) {
  const { rows } = await pool.query(
    `INSERT INTO ioc_items (public_id, observable, observable_type, source_name, confidence, note, created_at)
     VALUES (gen_random_uuid(), $1, $2, 'itest-ioc-link', 'high', 'itest', NOW()) RETURNING id`,
    [observable, type]
  );
  return Number(rows[0].id);
}

async function insertRow(reportId, col) {
  const { rows } = await pool.query(
    `INSERT INTO threat_report_candidates (
       report_id, candidate_type, original_value, normalized_value, assessment, role, review_status,
       match_state, matched_ioc_id, matched_ioc_observable_type, is_ioc, source_assertion, evidence,
       has_original_document_occurrence, promotion_outcome
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15) RETURNING id`,
    [
      reportId, col.candidate_type, col.original_value, col.normalized_value, col.assessment, col.role, col.review_status,
      col.match_state, col.matched_ioc_id ?? null, col.matched_ioc_observable_type ?? null, col.is_ioc, col.source_assertion,
      JSON.stringify(col.evidence), col.has_original_document_occurrence !== false, col.promotion_outcome || null
    ]
  );
  return rows[0].id;
}

async function insertUser(role) {
  const { rows } = await pool.query(
    `INSERT INTO users (username, password_hash, role, status) VALUES ($1, 'x', $2, 'active') RETURNING public_id`,
    [`itest-link-${role}-${crypto.randomUUID()}`, role]
  );
  return rows[0].public_id;
}

/**
 * Report whose stored rows equal the current extraction except the incomplete
 * prefix, stored as the older contract + bulk Create IOCs left it, and one
 * still-valid publisher domain that is approved and linked to its IOC.
 */
async function setupReport() {
  const extracted = documentFor();
  const report = await createThreatReport(pool, { title: `itest-ioc-link-${crypto.randomUUID()}`, source_type: 'url', source_url: SOURCE });
  await pool.query(
    `UPDATE threat_reports SET canonical_document = $2::jsonb, analysis_status = 'review_required', import_status = 'ready' WHERE id = $1`,
    [report.id, JSON.stringify(extracted.document)]
  );
  const iocPrefix = await insertIoc(PREFIX, 'url');
  const iocDomain = await insertIoc('evil-c2.example', 'domain');
  const ids = {};
  for (const c of extracted.candidates) {
    let col = candidateColumns(c);
    if (c.normalized_value === PREFIX) {
      col = candidateColumns({
        ...c,
        is_ioc: true,
        assessment: 'malicious',
        role: 'command_and_control',
        source_assertion: 'explicit_c2',
        policy_decision: 'explicit_report_assertion',
        review_status: 'approved',
        match_state: 'existing',
        matched_ioc_id: iocPrefix,
        matched_ioc_observable_type: 'url'
      });
      col.promotion_outcome = 'created';
    } else if (c.normalized_value === 'evil-c2.example') {
      col = candidateColumns({ ...c, review_status: 'approved', match_state: 'existing', matched_ioc_id: iocDomain, matched_ioc_observable_type: 'domain' });
      col.promotion_outcome = 'created';
    }
    ids[c.normalized_value] = await insertRow(report.id, col);
  }
  const job = await createJob(pool, { reportId: report.id, jobType: 'refresh_extraction' });
  return { report, extracted, job, ids, iocPrefix, iocDomain };
}

async function cleanup(reportId, iocIds = []) {
  await pool.query(
    `DELETE FROM threat_report_candidate_source_links WHERE candidate_id IN (SELECT id FROM threat_report_candidates WHERE report_id = $1)`,
    [reportId]
  );
  await pool.query(`DELETE FROM threat_report_ioc_sources WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_report_candidates WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_library_jobs WHERE report_id = $1`, [reportId]);
  await pool.query(`DELETE FROM threat_reports WHERE id = $1`, [reportId]);
  if (iocIds.length) await pool.query(`DELETE FROM ioc_items WHERE id = ANY($1::bigint[])`, [iocIds]);
}

const allRows = async (reportId) =>
  (await pool.query(`SELECT * FROM threat_report_candidates WHERE report_id = $1 ORDER BY id`, [reportId])).rows;
const indicators = (rows) => rows.filter((r) => isReportIndicatorMember(r)).map((r) => r.normalized_value).sort();
const storedReport = async (id) => (await pool.query(`SELECT * FROM threat_reports WHERE id = $1`, [id])).rows[0];
const freshJob = async (reportId) => createJob(pool, { reportId, jobType: 'refresh_extraction' });

async function acceptPolicy(reportId, role) {
  const preview = await previewExtractionRefresh(pool, await storedReport(reportId));
  return {
    preview,
    policy: {
      mode: 'accept',
      reason: 'Reviewed preview: incomplete prefix leaves Indicators',
      preview_fingerprint: preview.membership_diff.material_fingerprint,
      requested_by: await insertUser(role),
      requested_at: new Date().toISOString()
    }
  };
}

test('preview: the created incomplete prefix is a protected, reviewed, IOC-linked loss; its link is kept; nothing is written', opts, async () => {
  const s = await setupReport();
  try {
    const before = await allRows(s.report.id);
    assert.equal(indicators(before).includes(PREFIX), true, 'stored as an Indicator');
    const preview = await previewExtractionRefresh(pool, await storedReport(s.report.id));
    assert.deepEqual(preview.membership_diff.indicators, { before: 6, after: 5 });
    const removed = preview.membership_diff.removed_indicators;
    assert.deepEqual(removed.map((r) => [r.identity, r.reason_code, r.row_outcome, r.reviewed, String(r.matched_ioc_id)]), [
      [`url:${PREFIX}`, 'publisher_assertion_lost', 'kept', true, String(s.iocPrefix)]
    ]);
    assert.equal(preview.membership_diff.counts.ioc_link_changes, 0, 'the global IOC link is not cleared');
    assert.equal(preview.guard.decision, 'block');
    assert.equal(preview.guard.authorization.required_role, 'admin');
    assert.deepEqual(await allRows(s.report.id), before, 'preview never writes');
  } finally {
    await cleanup(s.report.id, [s.iocPrefix, s.iocDomain]);
  }
});

test('analyst acceptance of the admin-protected loss is refused; the transaction writes nothing', opts, async () => {
  const s = await setupReport();
  try {
    const before = await allRows(s.report.id);
    const { policy } = await acceptPolicy(s.report.id, 'analyst');
    const res = await runExtractionRefresh(pool, { reportId: s.report.id, jobId: s.job.id, restoreStatus: RESTORE, membershipPolicy: policy });
    assert.equal(res.ok, false);
    assert.equal(res.code, REFRESH_BLOCKED_CODE);
    assert.ok(res.summary.membership_guard.reasons.some((r) => r.code === 'acceptance_requires_admin'));
    assert.deepEqual(await allRows(s.report.id), before, 'refused: no candidate written');
    const rep = await storedReport(s.report.id);
    assert.equal(rep.analysis_status, 'review_required');
  } finally {
    await pool.query(`DELETE FROM users WHERE username LIKE 'itest-link-%'`);
    await cleanup(s.report.id, [s.iocPrefix, s.iocDomain]);
  }
});

test('admin acceptance applies exactly the previewed change: membership leaves, decision + IOC link + IOC record kept; re-refresh is a no-op', opts, async () => {
  const s = await setupReport();
  try {
    const before = await allRows(s.report.id);
    const { preview, policy } = await acceptPolicy(s.report.id, 'admin');
    const res = await runExtractionRefresh(pool, { reportId: s.report.id, jobId: s.job.id, restoreStatus: RESTORE, membershipPolicy: policy });
    assert.equal(res.ok, true, JSON.stringify(res.summary?.membership_guard));
    assert.equal(res.summary.membership_guard.decision, 'apply_accepted');
    assert.equal(res.summary.membership_guard.material_fingerprint, preview.membership_diff.material_fingerprint);

    const after = await allRows(s.report.id);
    assert.equal(after.length, before.length, 'no row deleted or added');
    assert.deepEqual(indicators(after), indicators(before).filter((v) => v !== PREFIX));
    const prefix = after.find((r) => r.normalized_value === PREFIX);
    assert.equal(String(prefix.id), String(s.ids[PREFIX]), 'same row (in-place update)');
    assert.equal(prefix.review_status, 'approved', 'review decision kept');
    assert.equal(prefix.promotion_outcome, 'created', 'Create IOCs outcome kept');
    assert.equal(Number(prefix.matched_ioc_id), s.iocPrefix, 'global IOC link kept');
    assert.equal(prefix.is_ioc, false);
    assert.equal(prefix.source_assertion, 'non_ioc');
    const { rows: iocs } = await pool.query(`SELECT id FROM ioc_items WHERE id = ANY($1::bigint[])`, [[s.iocPrefix, s.iocDomain]]);
    assert.equal(iocs.length, 2, 'no global IOC record deleted');
    // Everything else is untouched analyst state.
    for (const b of before.filter((r) => r.normalized_value !== PREFIX)) {
      const a = after.find((r) => String(r.id) === String(b.id));
      assert.equal(a.review_status, b.review_status);
      assert.equal(String(a.matched_ioc_id ?? ''), String(b.matched_ioc_id ?? ''));
    }
    // Audit trail names the affected identity.
    const rep = await storedReport(s.report.id);
    const mg = rep.analysis_progress.last_refresh.membership_guard;
    assert.deepEqual(mg.affected.removed_indicators, [`url:${PREFIX}`]);
    assert.equal(mg.accepted_by_role, 'admin');

    // A second refresh under the default protect policy changes nothing (the link stays).
    const again = await runExtractionRefresh(pool, { reportId: s.report.id, jobId: (await freshJob(s.report.id)).id, restoreStatus: RESTORE });
    assert.equal(again.ok, true, JSON.stringify(again.summary?.membership_guard));
    assert.equal(again.summary.updated, 0);
    assert.equal(again.summary.membership_guard.decision, 'apply');
    assert.equal(Number((await allRows(s.report.id)).find((r) => r.normalized_value === PREFIX).matched_ioc_id), s.iocPrefix);
  } finally {
    await pool.query(`DELETE FROM users WHERE username LIKE 'itest-link-%'`);
    await cleanup(s.report.id, [s.iocPrefix, s.iocDomain]);
  }
});

test('a stale preview (link state changed after it was taken) is refused with nothing written', opts, async () => {
  const s = await setupReport();
  const decoy = await insertIoc('decoy-ioc.example', 'domain');
  try {
    const { policy } = await acceptPolicy(s.report.id, 'admin');
    // After the preview, a stored link is changed (e.g. a manual relink): the
    // refresh would now also MOVE that link back to the catalog match.
    await pool.query(`UPDATE threat_report_candidates SET matched_ioc_id = $2, updated_at = NOW() WHERE id = $1`, [s.ids['evil-c2.example'], decoy]);
    const before = await allRows(s.report.id);
    const res = await runExtractionRefresh(pool, { reportId: s.report.id, jobId: s.job.id, restoreStatus: RESTORE, membershipPolicy: policy });
    assert.equal(res.ok, false);
    assert.equal(res.code, REFRESH_BLOCKED_CODE);
    const codes = res.summary.membership_guard.reasons.map((r) => r.code);
    assert.ok(codes.includes('preview_stale'), JSON.stringify(codes));
    assert.ok(codes.includes('ioc_link_changed'), JSON.stringify(codes));
    assert.deepEqual(await allRows(s.report.id), before);
  } finally {
    await pool.query(`DELETE FROM users WHERE username LIKE 'itest-link-%'`);
    await cleanup(s.report.id, [s.iocPrefix, s.iocDomain, decoy]);
  }
});

test('intentional unlink: a deleted IOC record clears the link only with an admin acceptance of exactly that change', opts, async () => {
  const s = await setupReport();
  try {
    // Accept the prefix loss first so only the link change remains.
    const first = await acceptPolicy(s.report.id, 'admin');
    assert.equal((await runExtractionRefresh(pool, { reportId: s.report.id, jobId: s.job.id, restoreStatus: RESTORE, membershipPolicy: first.policy })).ok, true);
    // The domain's IOC record is removed from the catalog by an admin.
    await pool.query(`DELETE FROM ioc_items WHERE id = $1`, [s.iocDomain]);
    const before = await allRows(s.report.id);
    const blocked = await runExtractionRefresh(pool, { reportId: s.report.id, jobId: (await freshJob(s.report.id)).id, restoreStatus: RESTORE });
    assert.equal(blocked.ok, false);
    assert.deepEqual(blocked.summary.membership_guard.reasons.filter((r) => r.material).map((r) => r.code), ['ioc_link_changed']);
    assert.deepEqual(await allRows(s.report.id), before, 'protect: link not silently cleared');

    const { preview, policy } = await acceptPolicy(s.report.id, 'admin');
    assert.deepEqual(preview.membership_diff.ioc_link_changes.map((l) => [l.identity, l.change]), [['domain:evil-c2.example', 'cleared']]);
    assert.deepEqual(preview.membership_diff.indicators, { before: 5, after: 5 }, 'counts alone would not show it');
    const applied = await runExtractionRefresh(pool, { reportId: s.report.id, jobId: (await freshJob(s.report.id)).id, restoreStatus: RESTORE, membershipPolicy: policy });
    assert.equal(applied.ok, true, JSON.stringify(applied.summary?.membership_guard));
    const row = (await allRows(s.report.id)).find((r) => r.normalized_value === 'evil-c2.example');
    assert.equal(row.matched_ioc_id, null);
    assert.equal(row.review_status, 'approved', 'decision kept');
    const rep = await storedReport(s.report.id);
    assert.deepEqual(rep.analysis_progress.last_refresh.membership_guard.affected.ioc_link_changes, [
      { identity: 'domain:evil-c2.example', from_ioc_id: s.iocDomain, to_ioc_id: null }
    ]);
  } finally {
    await pool.query(`DELETE FROM users WHERE username LIKE 'itest-link-%'`);
    await cleanup(s.report.id, [s.iocPrefix, s.iocDomain]);
  }
});

test('IOC Source link survives: a reviewed linked row leaving the document keeps its row, decision, IOC link and source link', opts, async () => {
  const s = await setupReport();
  const iocLinked = await insertIoc('linked-kept.example', 'domain');
  try {
    const template = candidateColumns(s.extracted.candidates.find((c) => c.candidate_type === 'domain'));
    const linkedId = await insertRow(s.report.id, {
      ...template,
      normalized_value: 'linked-kept.example',
      original_value: 'linked-kept.example',
      review_status: 'approved',
      match_state: 'existing',
      matched_ioc_id: iocLinked,
      matched_ioc_observable_type: 'domain',
      promotion_outcome: 'created'
    });
    const { rows: src } = await pool.query(
      `INSERT INTO threat_report_ioc_sources (report_id, original_url, canonical_url, lifecycle_status, approved_at)
       VALUES ($1, $2, $2, 'extracted', NOW()) RETURNING id`,
      [s.report.id, `https://example.test/iocs/${crypto.randomUUID()}`]
    );
    await pool.query(`INSERT INTO threat_report_candidate_source_links (candidate_id, source_id, source_assertion) VALUES ($1, $2, 'linked_source_ioc')`, [linkedId, src[0].id]);
    const { preview, policy } = await acceptPolicy(s.report.id, 'admin');
    const linkedLoss = preview.membership_diff.removed_indicators.find((r) => r.identity === 'domain:linked-kept.example');
    assert.equal(linkedLoss.row_outcome, 'original_occurrence_cleared');
    assert.equal(preview.membership_diff.counts.reviewed_candidates_deleted, 0, 'nothing reviewed is deleted');
    const res = await runExtractionRefresh(pool, { reportId: s.report.id, jobId: s.job.id, restoreStatus: RESTORE, membershipPolicy: policy });
    assert.equal(res.ok, true, JSON.stringify(res.summary?.membership_guard));
    const row = (await allRows(s.report.id)).find((r) => String(r.id) === String(linkedId));
    assert.ok(row, 'row kept (not deleted)');
    assert.equal(row.has_original_document_occurrence, false);
    assert.equal(row.review_status, 'approved');
    assert.equal(Number(row.matched_ioc_id), iocLinked);
    const { rows: links } = await pool.query(`SELECT 1 FROM threat_report_candidate_source_links WHERE candidate_id = $1`, [linkedId]);
    assert.equal(links.length, 1, 'IOC Source link kept');
  } finally {
    await pool.query(`DELETE FROM users WHERE username LIKE 'itest-link-%'`);
    await cleanup(s.report.id, [s.iocPrefix, s.iocDomain, iocLinked]);
  }
});

test('concurrent Create IOCs relink between the guard snapshot and the row lock aborts the accepted refresh; nothing written', opts, async () => {
  const s = await setupReport();
  const decoy = await insertIoc('decoy-concurrent.example', 'domain');
  try {
    const { policy } = await acceptPolicy(s.report.id, 'admin');
    const before = await allRows(s.report.id);
    let raced = false;
    const racing = {
      query: (...a) => pool.query(...a),
      connect: async () => {
        const client = await pool.connect();
        return {
          query: async (sql, params) => {
            if (typeof sql === 'string' && LOCK_SQL_RE.test(sql) && !raced) {
              raced = true;
              await other.query(`UPDATE threat_report_candidates SET matched_ioc_id = $2, updated_at = NOW() WHERE id = $1`, [s.ids['bad-relay.example'], decoy]);
            }
            return client.query(sql, params);
          },
          release: (...a) => client.release(...a)
        };
      }
    };
    const res = await runExtractionRefresh(racing, { reportId: s.report.id, jobId: s.job.id, restoreStatus: RESTORE, membershipPolicy: policy });
    assert.equal(raced, true);
    assert.equal(res.ok, false);
    assert.equal(res.code, REFRESH_CONCURRENT_CHANGE_CODE);
    const after = await allRows(s.report.id);
    for (const b of before) {
      const a = after.find((r) => String(r.id) === String(b.id));
      if (String(b.id) === String(s.ids['bad-relay.example'])) assert.equal(Number(a.matched_ioc_id), decoy, 'concurrent link kept');
      else assert.deepEqual(a, b);
    }
  } finally {
    await pool.query(`DELETE FROM users WHERE username LIKE 'itest-link-%'`);
    await cleanup(s.report.id, [s.iocPrefix, s.iocDomain, decoy]);
  }
});

test('explicit promote_to_ioc survives an applied refresh: classification, decision, link and Quality v5 note persisted', opts, async () => {
  const s = await setupReport();
  try {
    // The prefix was promoted Context Only → IOC by an analyst (single-row
    // override) and then created: an explicit decision, not bulk history.
    const promotedFrom = { assessment: 'context_only', role: 'reference', match_state: 'context_only', review_status: 'pending', is_ioc: false, policy_decision: 'ioc_excluded_incomplete_url_prefix', decision_source: 'deterministic', promoted_at: new Date().toISOString(), promoted_by: 'itest-analyst' };
    await pool.query(
      `UPDATE threat_report_candidates
       SET evidence = COALESCE(evidence, '{}'::jsonb) || $2::jsonb, assessment = 'suspicious', role = 'unknown', updated_at = NOW()
       WHERE id = $1`,
      [s.ids[PREFIX], JSON.stringify({ promoted_from: promotedFrom, decision_source: 'analyst', policy_decision: 'analyst_promoted_from_context_only' })]
    );
    const before = await allRows(s.report.id);
    assert.equal(indicators(before).includes(PREFIX), true, 'the promoted prefix is an Indicator');
    const preview = await previewExtractionRefresh(pool, await storedReport(s.report.id));
    assert.equal(preview.membership_diff.removed_indicators.some((r) => r.identity === `url:${PREFIX}`), false, 'a promoted row is not a refresh loss');
    assert.equal(preview.membership_diff.counts.ioc_link_changes, 0);

    const res = await runExtractionRefresh(pool, { reportId: s.report.id, jobId: s.job.id, restoreStatus: RESTORE });
    assert.equal(res.ok, true, JSON.stringify(res.summary?.membership_guard));
    const row = (await allRows(s.report.id)).find((r) => r.normalized_value === PREFIX);
    assert.equal(String(row.id), String(s.ids[PREFIX]));
    assert.equal(row.is_ioc, true, 'promotion re-applied');
    assert.equal(row.assessment, 'suspicious');
    assert.equal(row.review_status, 'approved');
    assert.equal(row.promotion_outcome, 'created');
    assert.equal(Number(row.matched_ioc_id), s.iocPrefix);
    assert.equal(row.evidence.promoted_from.promoted_by, 'itest-analyst', 'promotion provenance kept');
    assert.equal(row.evidence.policy_decision, 'analyst_promoted_from_context_only');
    assert.equal(indicators([row]).includes(PREFIX), true, 'still an Indicator after refresh');

    const quality = (await storedReport(s.report.id)).analysis_progress.extraction_diagnostics.quality;
    assert.equal(quality.version, 'tl-quality-v7');
    const w = quality.warnings.find((x) => x.code === 'analyst_state_membership_divergence');
    assert.ok(w, 'the override is recorded as a divergence');
    assert.equal(w.severity, 'info', 'an explicit analyst promotion is a note, not a warning');
    assert.equal(w.divergence.causes.analyst_promotion, 1);
    assert.equal(w.divergence.causes.unexplained, 0);
  } finally {
    await cleanup(s.report.id, [s.iocPrefix, s.iocDomain]);
  }
});

test('a stored link whose IOC record no longer names the identity is not carried: protected change, nothing written', opts, async () => {
  const s = await setupReport();
  const wrong = await insertIoc('http://203.0.113.99/unrelated', 'url');
  try {
    // Stale id: the prefix row points at an IOC record of another value.
    await pool.query(`UPDATE threat_report_candidates SET matched_ioc_id = $2, updated_at = NOW() WHERE id = $1`, [s.ids[PREFIX], wrong]);
    const before = await allRows(s.report.id);
    const preview = await previewExtractionRefresh(pool, await storedReport(s.report.id));
    assert.deepEqual(preview.membership_diff.ioc_link_changes.map((l) => [l.identity, l.change, l.from_ioc_id, l.to_ioc_id]), [
      [`url:${PREFIX}`, 'cleared', wrong, null]
    ]);
    assert.equal(preview.guard.authorization.required_role, 'admin');
    const res = await runExtractionRefresh(pool, { reportId: s.report.id, jobId: s.job.id, restoreStatus: RESTORE });
    assert.equal(res.ok, false);
    assert.equal(res.code, REFRESH_BLOCKED_CODE);
    assert.ok(res.summary.membership_guard.reasons.some((r) => r.code === 'ioc_link_changed'));
    assert.deepEqual(await allRows(s.report.id), before, 'protect: nothing written');
  } finally {
    await cleanup(s.report.id, [s.iocPrefix, s.iocDomain, wrong]);
  }
});
