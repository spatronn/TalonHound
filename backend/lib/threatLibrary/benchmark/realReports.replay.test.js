/**
 * Real-report analyst-state replay regression (P1 hotfix).
 *
 * Production finding (2026-10-15): the deterministic P1 extraction read NCSC
 * as 0 Indicators and Raven as 217, but Refresh extraction kept 4 and 218
 * because a stored Create-IOC outcome forced the identity back to an IOC
 * Indicator during analyst-state replay.
 *
 * Worst case for every available real report: every identity the current
 * extraction produces is assumed to have been approved AND created as a
 * global IOC under an older contract. Replaying that history must leave the
 * report Indicator membership exactly where the deterministic publisher
 * reading puts it, which realReports.test.js ratchets against the labels.
 * Generic: no report identity or value is named here.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { caseSourceAvailable, loadBenchmarkCases, materializeCase } from './benchmarkRunner.js';
import { extractReportCandidates } from '../extractionStages.js';
import { preserveAnalystCandidates } from '../candidateAnalystState.js';
import { buildCandidateEvidenceRecord } from '../evidencePolicy.js';
import { isReportIndicatorMember } from '../indicatorMembership.js';

const SOURCE_DIR = process.env.TL_BENCHMARK_SOURCE_DIR || null;
const identity = (c) => `${c.candidate_type}:${c.normalized_value}`;
const members = (cands) =>
  cands.filter((c) => isReportIndicatorMember({ ...c, evidence: buildCandidateEvidenceRecord(c) })).map(identity).sort();

/** Stored rows as an older contract + bulk Create IOCs would have left them. */
function createdHistory(candidates) {
  return candidates.map((c, i) => ({
    id: String(10_000 + i),
    candidate_type: c.candidate_type,
    normalized_value: c.normalized_value,
    review_status: 'approved',
    promotion_outcome: i % 2 ? 'created' : 'already_existing',
    matched_ioc_id: 900_000 + i,
    assessment: 'malicious',
    is_ioc: true,
    source_assertion: 'explicit_ioc',
    match_state: 'existing',
    evidence: { source_assertion: 'explicit_ioc', policy_decision: 'explicit_report_assertion' }
  }));
}

test('replayed Create-IOC history never changes publisher Indicator membership (all available real reports)', {
  skip: SOURCE_DIR ? false : 'set TL_BENCHMARK_SOURCE_DIR to a private source store to replay real reports'
}, () => {
  const cases = loadBenchmarkCases({ sourceDir: SOURCE_DIR, privateDir: null }).filter((c) => c.id.startsWith('real-'));
  let replayed = 0;
  for (const c of cases) {
    if (!caseSourceAvailable(c)) continue;
    const { report, document } = materializeCase(c);
    const fresh = extractReportCandidates(report, document).candidates;
    const final = preserveAnalystCandidates(fresh.map((x) => ({ ...x })), createdHistory(fresh));
    assert.deepEqual(members(final), members(fresh), `${c.id}: replay changed Indicator membership`);
    // Review history is kept on every surviving identity.
    assert.equal(final.every((x) => x.review_status === 'approved'), true, `${c.id}: review decisions kept`);
    replayed += 1;
  }
  assert.ok(replayed > 0, 'at least one real-report source available');
});
