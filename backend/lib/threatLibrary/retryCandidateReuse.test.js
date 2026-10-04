/**
 * Retry candidate reuse: a completed report re-analysed on Retry reloads its
 * stored candidates instead of extracting again, and every candidate passes
 * the evidence policy once more (mergeAiCandidateUpdates). The policy
 * re-annotates occurrences from their structural inputs, so the persisted
 * evidence record must carry them: otherwise a curated IOC row reloads as
 * prose and loses its explicit publisher assertion (Indicators 21 → 0 on a
 * real report). Evidence records persisted before the inputs were stored keep
 * the row reading the extractor recorded.
 *
 * Path under test: fresh extraction → replaceCandidates → loadReportCandidatesForAnalysis
 * → mergeAiCandidateUpdates (no AI update) → replaceCandidates → reload → merge.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { mergeAiCandidateUpdates } from './pipeline.js';
import { replaceCandidates, loadReportCandidatesForAnalysis } from './store.js';
import { isActionableReviewIndicator } from './promotion.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { hasStructuralInputs } from './indicatorScope.js';

const SOURCE = 'https://research.example/blog/retry-reuse/';
const SHA_A = crypto.createHash('sha256').update('retry-reuse-sample-a').digest('hex');
const SHA_B = crypto.createHash('sha256').update('retry-reuse-sample-b').digest('hex');
const BODY_DOMAIN = 'docs-mirror-cache.example';

const HTML = `<!doctype html><html lang="en"><head><title>Retry reuse fixture</title></head><body><article>
<h1>Synthetic intrusion campaign</h1>
${Array.from({ length: 4 }, (_, i) => `<p>Background paragraph ${i + 1} describes initial access, tooling and operator tradecraft across several victims.</p>`).join('\n')}
<p>Researchers compared the lure with documentation hosted at ${BODY_DOMAIN.replace('.', '[.]')} during the analysis.</p>
<h2>Indicators of Compromise</h2>
<h3>File indicators</h3>
<p>${SHA_A}</p>
<p>${SHA_B}</p>
<h3>Network IOCs</h3>
<p>relay-voxmail[.]com</p>
<p>inbox-notice-hub[.]net</p>
</article></body></html>`;

const REVIEWED = 'approved';

/** In-memory threat_report_candidates for the real store functions (JSON round-trip like jsonb). */
function fakeCandidateTable() {
  let rows = [];
  let nextId = 1;
  const exec = async (sql, params) => {
    const s = String(sql);
    if (/^(BEGIN|COMMIT|ROLLBACK)/.test(s.trim())) return { rows: [] };
    if (/DELETE FROM threat_report_candidates/.test(s)) {
      rows = rows.filter((r) => r.report_id !== params[0]);
      return { rows: [], rowCount: 0 };
    }
    if (/INSERT INTO threat_report_candidates/.test(s)) {
      const [report_id, portable_id, candidate_type, original_value, normalized_value, assessment, role, confidence,
        evidence_text, section, block_id, page_number, review_status, match_state, matched_ioc_id,
        matched_ioc_observable_type, is_ioc, source_assertion, evidence] = params;
      const row = {
        id: nextId++, report_id, portable_id, candidate_type, original_value, normalized_value, assessment, role,
        confidence: confidence == null ? null : String(confidence), evidence_text, section, block_id, page_number,
        review_status, match_state, matched_ioc_id, matched_ioc_observable_type, is_ioc, source_assertion,
        evidence: JSON.parse(evidence)
      };
      rows.push(row);
      return { rows: [row] };
    }
    if (/FROM threat_report_candidates WHERE report_id = \$1 ORDER BY id/.test(s)) {
      return { rows: rows.filter((r) => r.report_id === params[0]).map((r) => JSON.parse(JSON.stringify(r))) };
    }
    throw new Error(`unexpected SQL: ${s.slice(0, 80)}`);
  };
  return {
    rows: () => rows,
    stripStructuralInputs() {
      // Shape of every evidence record persisted before the structural inputs were stored.
      for (const r of rows) for (const o of r.evidence.occurrences || []) {
        delete o.row_shape; delete o.structural_row; delete o.block_type; delete o.layout;
      }
    },
    pool: { query: exec, connect: async () => ({ query: exec, release: () => {} }) }
  };
}

function freshExtraction() {
  const r = extractCanonicalDocumentFromHtml(HTML, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  const { candidates } = extractCandidatesWithDiagnostics(r.document, { sourceUrl: SOURCE });
  // Analyst reviewed + created IOCs for the explicit indicators.
  let ioc = 900;
  for (const c of candidates) {
    if (c.source_assertion === 'explicit_ioc') {
      c.review_status = REVIEWED;
      c.matched_ioc_id = ioc++;
      c.matched_ioc_observable_type = c.candidate_type === 'sha256' ? 'hash' : c.candidate_type;
      c.match_state = 'existing';
    }
  }
  return { document: r.document, candidates };
}

const key = (c) => `${c.candidate_type}:${c.normalized_value}`;
const member = (c) => isActionableReviewIndicator({ ...c, evidence: buildCandidateEvidenceRecord(c) });
function snapshot(cands) {
  return Object.fromEntries(cands.map((c) => [key(c), {
    source_assertion: c.source_assertion,
    member: member(c),
    review_status: c.review_status || 'pending',
    matched_ioc_id: c.matched_ioc_id ?? null
  }]));
}

async function retryReuse(table, document) {
  const reloaded = await loadReportCandidatesForAnalysis(table.pool, 7);
  const merged = mergeAiCandidateUpdates(reloaded, { candidate_updates: [] }, { document });
  await replaceCandidates(table.pool, 7, merged);
  return merged;
}

test('fixture: explicit IOC rows and a body-only mention', () => {
  const { candidates } = freshExtraction();
  const s = snapshot(candidates);
  assert.equal(s[`sha256:${SHA_A}`].source_assertion, 'explicit_ioc');
  assert.equal(s['domain:relay-voxmail.com'].source_assertion, 'explicit_ioc');
  assert.equal(s[`sha256:${SHA_A}`].member, true);
  assert.equal(s[`domain:${BODY_DOMAIN}`].source_assertion, 'body_mention');
});

test('Retry reuse keeps explicit provenance, Indicator eligibility and review state; body mentions stay body mentions', async () => {
  const { document, candidates } = freshExtraction();
  const before = snapshot(candidates);
  const table = fakeCandidateTable();
  await replaceCandidates(table.pool, 7, candidates);
  for (const o of table.rows().flatMap((r) => r.evidence.occurrences || [])) {
    assert.equal(hasStructuralInputs(o), true, 'persisted occurrences carry their structural inputs');
  }
  const first = await retryReuse(table, document);
  assert.deepEqual(snapshot(first), before);
  // A second Retry reads the record the first one wrote: still identical.
  const second = await retryReuse(table, document);
  assert.deepEqual(snapshot(second), before);
  assert.equal(Object.values(before).filter((v) => v.member && v.source_assertion === 'explicit_ioc').length, 4);
});

test('legacy evidence records (no structural inputs) keep the recorded row reading on Retry', async () => {
  const { document, candidates } = freshExtraction();
  const before = snapshot(candidates);
  const table = fakeCandidateTable();
  await replaceCandidates(table.pool, 7, candidates);
  table.stripStructuralInputs();
  const after = await retryReuse(table, document);
  assert.deepEqual(snapshot(after), before);
  assert.equal(snapshot(after)[`domain:${BODY_DOMAIN}`].member, false);
});

test('legacy fallback never promotes a narrative occurrence', async () => {
  const { document, candidates } = freshExtraction();
  const table = fakeCandidateTable();
  await replaceCandidates(table.pool, 7, candidates);
  table.stripStructuralInputs();
  // A legacy row whose recorded reading is prose (asserted absent, narrative kind),
  // even inside the curated section, must not become an assertion on reload.
  const row = table.rows().find((r) => r.normalized_value === 'inbox-notice-hub.net');
  for (const o of row.evidence.occurrences) {
    delete o.asserted;
    o.occurrence_kind = 'narrative_mention';
  }
  row.source_assertion = 'body_mention';
  row.evidence.source_assertion = 'body_mention';
  const after = await retryReuse(table, document);
  const c = after.find((x) => x.normalized_value === 'inbox-notice-hub.net');
  assert.notEqual(c.source_assertion, 'explicit_ioc');
  assert.equal(after.find((x) => x.normalized_value === 'relay-voxmail.com').source_assertion, 'explicit_ioc');
});
