/**
 * Unit42-shaped IOC appendix: sample cards with "File size:" / "File type:" /
 * "File location:" list rows between hashes must not close publisher IOC scope
 * (tl-zones-v12). Mid-appendix inventory metadata is not article-tag chrome.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import {
  extractCandidatesWithDiagnostics,
  THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
} from './candidateExtraction.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import {
  annotateDocumentZones,
  isArticleMetadataListItem,
  THREAT_LIBRARY_DOCUMENT_ZONES_VERSION
} from './documentZones.js';

const SOURCE = 'https://research.example/blog/amos-sample-inventory/';

const H1 = '71781ad8adefb499aee9bcbe1a166e69ccc37a47066682f617d65c76d8cde88c';
const H2 = '7ea6ff8b12c59aaae1ab6f4f5a57045dad5a8127954f3ffd3d1c154d40d7ca3a';
const H3 = 'a598fcdcd49247312861ff90c16cb4a5d49fede6072e30e7416dd276668fa2a9';
const H4 = '6bfcdb4920383375b7e519918df7eb4db751b974b5571a15ce66b82478012620';
const H5 = '4504006d1911057be42435d4625f03d83c4d0b7b6898d14beb9cdeba6cf667b9';

test('sample inventory metadata contracts', () => {
  assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v15');
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v36');
});

test('isArticleMetadataListItem rejects File size / type inventory rows', () => {
  assert.equal(isArticleMetadataListItem({ type: 'list', text: 'File size: 1,991 bytes' }), false);
  assert.equal(isArticleMetadataListItem({ type: 'list', text: 'File type: Zsh script text' }), false);
  assert.equal(isArticleMetadataListItem({ type: 'list', text: 'SHA-256 hash: deadbeef' }), false);
  assert.equal(isArticleMetadataListItem({ type: 'list', text: 'MacOS' }), true);
  assert.equal(isArticleMetadataListItem({ type: 'list', text: 'Threat intelligence' }), true);
});

function htmlDoc(inner) {
  return `<!doctype html><html lang="en"><head><title>AMOS sample inventory</title></head><body><article>
<p>Background paragraph describing the AMOS stealer infection observed in a lab environment.</p>
${inner}
</article></body></html>`;
}

function extract(inner) {
  const r = extractCanonicalDocumentFromHtml(htmlDoc(inner), { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  const zoned = annotateDocumentZones(r.document, { sourceUrl: SOURCE });
  return { ...extractCandidatesWithDiagnostics(r.document, { sourceUrl: SOURCE }), document: r.document, zoned };
}

const find = (cands, type, value) =>
  cands.find((c) => c.candidate_type === type && String(c.normalized_value).toLowerCase() === String(value).toLowerCase());
const persisted = (c) => ({ ...c, evidence: buildCandidateEvidenceRecord(c) });
const isMember = (c) => Boolean(c) && isReportIndicatorMember(persisted(c));
const zoneOf = (zoned, re) => zoned.blocks.find((b) => re.test(String(b.text || '')))?.zone ?? null;

test('A — File size metadata between sample hashes keeps appendix Indicators', () => {
  const { candidates, zoned } = extract(`
<h2>Indicators of Compromise</h2>
<p>We discovered the following five files during this AMOS stealer infection:</p>
<p>Initial Zsh script downloaded from a command run from the macOS Terminal window</p>
<ul>
<li>SHA-256 hash: ${H1}</li>
<li>File size: 1,991 bytes</li>
<li>File type: Zsh script text executable, ASCII text</li>
<li>File location: hxxps[:]//ferncore13[.]com/curl/${H1}</li>
</ul>
<p>Payload (Zsh script) extracted from the initially downloaded Zsh script</p>
<ul>
<li>SHA-256 hash: ${H2}</li>
<li>File size: 1,213 bytes</li>
<li>File type: Zsh script text executable, ASCII text</li>
</ul>
<p>Installer for AMOS stealer</p>
<ul>
<li>SHA-256 hash: ${H3}</li>
<li>File size: 330,768 bytes</li>
<li>File location: /tmp/helper</li>
</ul>
<p>Binary from AMOS stealer infection persistent on the infected macOS host</p>
<ul>
<li>SHA-256 hash: ${H4}</li>
<li>File size: 438,576 bytes</li>
</ul>
<p>Another binary from AMOS stealer infection persistent on the infected macOS host</p>
<ul>
<li>SHA-256 hash: ${H5}</li>
<li>File size: 568,368 bytes</li>
</ul>
<p>Malicious website with instructions that will infect a vulnerable macOS host:</p>
<ul>
<li>hxxps[:]//getmacouscloud[.]com</li>
</ul>
<p>URL for the initial download decoded from Base64 text provided by the malicious website:</p>
<ul>
<li>hxxps[:]//ferncore13[.]com/curl/${H1}</li>
</ul>
<p>URLs from extracted from the payload returned from the initial download:</p>
<ul>
<li>hxxps[:]//grove-89[.]com/api/metrics/run?event=pasted</li>
<li>hxxps[:]//ferncore13[.]com/2kqYRM0DCrnyJgoS4gVLl_FHJRRdTUhGCbjyuYwpZ6c/m1/update</li>
</ul>
<h2>Additional Resources</h2>
<ul>
<li>2026-06-09: Atomic macOS (AMOS) Stealer infection – Malware-Traffic-Analysis.net</li>
</ul>
<h2>Tags</h2>
<ul>
<li>MacOS</li>
<li>Threat intelligence</li>
</ul>`);

  assert.equal(zoneOf(zoned, new RegExp(`^SHA-256 hash: ${H1}$`)), 'explicit_ioc_section');
  assert.notEqual(zoneOf(zoned, /^File size: 1,991 bytes$/), 'source_metadata');
  assert.equal(zoneOf(zoned, new RegExp(`^SHA-256 hash: ${H2}$`)), 'explicit_ioc_section');
  assert.equal(zoneOf(zoned, new RegExp(`^SHA-256 hash: ${H5}$`)), 'explicit_ioc_section');
  assert.equal(zoneOf(zoned, /getmacouscloud/), 'explicit_ioc_section');
  assert.equal(zoneOf(zoned, /grove-89/), 'explicit_ioc_section');

  for (const h of [H1, H2, H3, H4, H5]) {
    assert.equal(isMember(find(candidates, 'sha256', h)), true, `sha256 ${h} must be Indicator`);
  }
  assert.equal(isMember(find(candidates, 'url', 'https://getmacouscloud.com/')) || isMember(find(candidates, 'url', 'https://getmacouscloud.com')), true);
  assert.equal(isMember(find(candidates, 'url', `https://ferncore13.com/curl/${H1}`)), true);
  assert.equal(isMember(find(candidates, 'url', 'https://grove-89.com/api/metrics/run?event=pasted')), true);
  assert.equal(
    isMember(find(candidates, 'url', 'https://ferncore13.com/2kqYRM0DCrnyJgoS4gVLl_FHJRRdTUhGCbjyuYwpZ6c/m1/update')),
    true
  );

  // Peer "Additional Resources" is reference chrome, not a subgroup of the appendix.
  assert.ok(
    ['reference_section', 'report_body'].includes(zoneOf(zoned, /^Additional Resources$/)),
    `Additional Resources zone=${zoneOf(zoned, /^Additional Resources$/)}`
  );
  assert.notEqual(zoneOf(zoned, /Malware-Traffic-Analysis/), 'explicit_ioc_section');
  const members = candidates.filter((c) => isMember(c)).map((c) => `${c.candidate_type}:${c.normalized_value}`);
  assert.equal(members.some((m) => m.includes('malware-traffic-analysis.net')), false, members.join(','));
});

test('B — bare article tag chips after Indicators still close appendix', () => {
  const { zoned, candidates } = extract(`
<h2>Indicators of Compromise</h2>
<ul>
<li>${H1}</li>
<li>MacOS</li>
<li>Threat intelligence</li>
</ul>
<p>Follow-on narrative mentioning ${H2} outside the closed appendix.</p>`);

  assert.equal(isMember(find(candidates, 'sha256', H1)), true);
  // Tag chips close scope; a later narrative hash stays non-member under MODE A.
  assert.equal(isMember(find(candidates, 'sha256', H2)), false);
  assert.ok(
    ['source_metadata', 'report_body'].includes(zoneOf(zoned, /^MacOS$/)),
    `MacOS zone=${zoneOf(zoned, /^MacOS$/)}`
  );
});
