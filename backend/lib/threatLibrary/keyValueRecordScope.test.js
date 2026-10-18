/**
 * Unit 42 PPI-shaped IOC appendix (tl-zones-v13): key-value record paragraphs
 * ("SHA256 hash: … / File name: … / Description: …") under H3 operation
 * headings stay inside the publisher IOC section. A record field line used to
 * act as a synthetic heading that reset the appendix, dropping every later
 * hash / URL / domain to report_body.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { looksLikeLabelHeading, THREAT_LIBRARY_DOCUMENT_ZONES_VERSION } from './documentZones.js';
import { isIndicatorRowShape, RECORD_FIELD_LINE_RE } from './indicatorScope.js';

const SOURCE = 'https://research.example/blog/ppi-key-value-records/';
const H1 = '7f792c45de1e28fd42ac44c9444f157a2161742d130bac336c0e991aabbb112c';
const H2 = 'fc485882626512e7ff82a1d7cd8e8fb3e9751b026d97e682d6908aefff1f2d73';
const H3 = '3052bd320a34e12ee694811ed0578797477dfd480c664491e509ed15ce1a6961';
const H4 = 'e05bc22afbc5ddd50b49c85ee169dd13318000d38286de2b8bcff98217256a8d';
const H5 = 'fdcc95b7791c0d6590dcf1a412dc9fcc92ad2095818d1b78368b31efad012007';

const html = `<!doctype html><html><head><title>PPI records</title></head><body><main><article>
<h1>PPI records</h1>
<h2>Technical Analysis</h2>
<p>The loader is delivered as a trojanized installer and later contacts its operator panel for tasking.</p>
<p>File name: setup.exe</p>
<p>The operator rotates infrastructure every few days and reuses the same installer naming scheme.</p>
<h2>Indicators of Compromise</h2>
<h3>Initial Access and OfferLoader</h3>
<p>SHA256 hash: ${H1}</p>
<p>File name: windirstat.exe</p>
<p>File description: Trojanized installer</p>
<p>SHA256 hash: ${H2}</p>
<p>File name: windirstat.tmp</p>
<h3>Operation A: Insomnia RAT</h3>
<p>SHA256 hash: ${H3}</p>
<p>File name: eld0.exe</p>
<p>URL: hxxps[:]//stryper[.]info/t.ps1</p>
<p>Description: Stage-2 PowerShell installer</p>
<p>Domain: stryper[.]info</p>
<p>Description: Second-stage agent host</p>
<h3>Operation B: ARKTunnel</h3>
<p>SHA256 hash: ${H4} File size: 92,657 bytes</p>
<p>File name: procorTrex.zip</p>
<p>Domain: reg.pcsdkflyer[.]ca</p>
<p>Description: WebSocket RAT C2</p>
<h3>Operation C: Docro Hijacker</h3>
<p>SHA256 hash: ${H5}</p>
<p>Docro extension path:</p>
<p>File location: C:\\ProgramData\\DocsHelper\\docro</p>
<p>Domain: vendralo[.]info</p>
<p>Description: Per-victim rule delivery</p>
<h3>Rotational Infrastructure</h3>
<h4>Payload-Handoff and Second-Stage Hosts</h4>
<h4>Install-Tracker Beacons (Operator Panel)</h4>
<table><thead><tr><th>Domain</th><th>Role</th></tr></thead><tbody>
<tr><td>voyagemist[.]space</td><td>PPI affiliate install tracker</td></tr>
<tr><td>chawton[.]info</td><td>PPI affiliate install tracker</td></tr>
</tbody></table>
<h2>Additional Resources</h2>
<p>Earlier research on the same family – Example Labs</p>
</article></main></body></html>`;

function run() {
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true);
  const ex = extractReportCandidates({ source_type: 'url', source_url: SOURCE }, r.document);
  return {
    blocks: ex.annotated.blocks,
    members: new Set(ex.candidates.filter(isReportIndicatorMember).map((c) => `${c.candidate_type}:${c.normalized_value}`))
  };
}

test('key-value record contracts', () => {
  assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v15');
});

test('record field lines are never label headings; section labels still are', () => {
  for (const line of ['File name: windirstat.exe', 'Description: Python agent host', 'File size: 3,041,280 bytes', 'SHA256 hash: abc']) {
    assert.equal(RECORD_FIELD_LINE_RE.test(line), true, line);
    assert.equal(looksLikeLabelHeading(line), false, line);
  }
  for (const line of ['Domain:', 'Indicators of Compromise', 'Network indicators']) {
    assert.equal(RECORD_FIELD_LINE_RE.test(line), false, line);
  }
  assert.equal(looksLikeLabelHeading('Docro extension path:'), true);
});

test('a labelled hash followed by the next record field on one line is one row', () => {
  assert.equal(isIndicatorRowShape(`SHA256 hash: ${H4} File size: 92,657 bytes`, H4), true);
  // A value embedded in prose on both sides is still not a row.
  assert.equal(isIndicatorRowShape(`We saw ${H4} dropped by the loader`, H4), false);
});

test('every record under the H3 operation headings is a publisher Indicator', () => {
  const { blocks, members } = run();
  for (const id of [
    `sha256:${H1}`, `sha256:${H2}`, `sha256:${H3}`, `sha256:${H4}`, `sha256:${H5}`,
    'url:https://stryper.info/t.ps1', 'domain:stryper.info', 'domain:reg.pcsdkflyer.ca',
    'domain:vendralo.info', 'domain:voyagemist.space', 'domain:chawton.info'
  ]) {
    assert.ok(members.has(id), `${id} is an Indicator`);
  }
  // Record file names stay out of the Indicator set.
  for (const id of members) assert.ok(!/(?:windirstat|eld0|procortrex|setup\.exe)/i.test(id), `${id} not an Indicator`);
  const start = blocks.findIndex((b) => b.type === 'heading' && b.text === 'Indicators of Compromise');
  const end = blocks.findIndex((b) => b.type === 'heading' && b.text === 'Additional Resources');
  const leaked = blocks.slice(start, end).filter((b) => b.zone !== 'explicit_ioc_section').map((b) => `${b.id} ${b.text}`);
  assert.deepEqual(leaked, [], 'no IOC-section block falls to report_body');
  // A record-field line in narrative never opens a section.
  const bodyField = blocks.find((b) => b.text === 'File name: setup.exe');
  assert.equal(bodyField.zone, 'report_body');
});
