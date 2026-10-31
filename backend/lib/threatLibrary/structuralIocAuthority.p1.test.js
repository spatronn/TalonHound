/**
 * P1 structural IOC authority: nested list headings, filename-first rows,
 * body-table self-proof limits, and legitimate-service list demotion.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument } from './canonicalDocument.js';
import {
  extractCandidatesFromDocument,
  extractCandidatesWithDiagnostics,
  THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
} from './candidateExtraction.js';
import {
  annotateDocumentZones,
  demoteLegitimateServiceListDiscovery,
  THREAT_LIBRARY_DOCUMENT_ZONES_VERSION
} from './documentZones.js';
import { extractCanonicalDocumentFromHtml, THREAT_LIBRARY_HTML_EXTRACTOR_VERSION } from './extract/extractHtml.js';
import { HTML_BLOCKS_VERSION } from './extract/htmlBlocks.js';
import { isAnnotatedIndicatorRowLine } from './indicatorScope.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import {
  interpretIocTable,
  isInfrastructureLookupTable,
  TABLE_SEMANTICS_VERSION
} from './tableSemantics.js';
import {
  inferPdfHeadingLevel,
  isFilenameHashRowLine,
  PDF_LAYOUT_VERSION
} from './pdfLayout.js';

assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v16');
assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v48');
assert.equal(THREAT_LIBRARY_HTML_EXTRACTOR_VERSION, 'threat_library_html_v9');
assert.equal(HTML_BLOCKS_VERSION, 'threat_library_html_v9');
assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v14');
assert.equal(PDF_LAYOUT_VERSION, 'threat_library_pdf_v6');

const member = (c) => isReportIndicatorMember({ ...c, evidence: buildCandidateEvidenceRecord(c) });
const find = (cands, type, value) => cands.find((c) => c.candidate_type === type && c.normalized_value === value);

test('HTML: heading nested inside list item keeps heading level', () => {
  const html = `<article>
<h2>8. Indicator of Compromise</h2>
<ul><li><h3>C2</h3></li></ul>
<p>www.online.check-computer.kro[.]kr</p>
<p>online.lecture-site.kro[.]kr</p>
<ul><li>APT</li><li>Malware</li></ul>
</article>`;
  const r = extractCanonicalDocumentFromHtml(html, {
    url: 'https://example.test/kimsuky',
    finalUrl: 'https://example.test/kimsuky',
    httpStatus: 200
  });
  assert.equal(r.ok, true);
  const headings = r.document.blocks.filter((b) => b.type === 'heading');
  assert.ok(headings.some((b) => b.text === 'C2' && b.level === 3), 'nested h3 must emit as heading');
  const annotated = annotateDocumentZones(r.document);
  const c2 = annotated.blocks.find((b) => b.type === 'heading' && b.text === 'C2');
  assert.ok(c2);
  assert.ok(
    c2.zone === 'explicit_ioc_section' || c2.zone === 'c2_section',
    `C2 subgroup must stay authoritative, got ${c2.zone}`
  );
  const cands = extractCandidatesFromDocument(annotated);
  assert.equal(member(find(cands, 'domain', 'www.online.check-computer.kro.kr')), true);
  assert.equal(member(find(cands, 'domain', 'online.lecture-site.kro.kr')), true);
});

test('filename-first annotated rows are indicator row content', () => {
  const md5 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  assert.equal(isAnnotatedIndicatorRowLine(`loader.exe ${md5}`), true);
  assert.equal(isAnnotatedIndicatorRowLine(`${md5} oleasapi.dll`), true);
  assert.equal(isFilenameHashRowLine(`loader.exe ${md5}`), true);
});

test('body Domain|IP|First seen|ASN table does not self-prove outside appendix', () => {
  const block = {
    id: 't1',
    zone: 'report_body',
    section_heading: 'Infrastructure',
    table: {
      headers: ['Domain', 'IP', 'First seen', 'ASN'],
      rows: [
        ['evil.example', '203.0.113.10', '2024-01-01', 'AS64500'],
        ['other.example', '198.51.100.20', '2024-02-01', 'AS64501']
      ]
    }
  };
  assert.equal(isInfrastructureLookupTable(
    [
      { header: 'Domain', intent: 'indicator' },
      { header: 'IP', intent: 'indicator' },
      { header: 'First seen', intent: 'other' },
      { header: 'ASN', intent: 'other' }
    ],
    null
  ), true);
  const r = interpretIocTable(block);
  assert.equal(r.infrastructure_lookup, true);
  assert.equal(r.explicit, false);
  assert.equal(r.reason, 'infrastructure_lookup_outside_ioc_scope');
});

test('body MD5|URL table without type column does not self-prove outside appendix', () => {
  const block = {
    id: 't2',
    zone: 'report_body',
    section_heading: 'Related Variant Information',
    table: {
      headers: ['MD5', 'URL', 'Size'],
      rows: [
        ['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'androcl.example.org/a.php', '100'],
        ['cccccccccccccccccccccccccccccccc', 'androcl.example.org/b.php', '200']
      ]
    }
  };
  const r = interpretIocTable(block);
  assert.equal(r.explicit, false);
  assert.match(r.reason, /outside_ioc_scope/);
});

test('Type|Indicator|Description tables still self-prove outside appendix', () => {
  const block = {
    id: 't3',
    zone: 'report_body',
    section_heading: 'Frequently Asked Questions',
    table: {
      headers: ['Type', 'Indicator', 'Description'],
      rows: [
        ['Domain', 'evil.example.com', 'c2'],
        ['MD5', 'dddddddddddddddddddddddddddddddd', 'payload']
      ]
    }
  };
  const r = interpretIocTable(block);
  assert.equal(r.explicit, true);
  assert.equal(r.reason, 'structural_ioc_table');
});

test('legitimate-service lead-in demotes unlabelled observable-list discovery', () => {
  const blocks = [
    { id: 'b1', type: 'paragraph', text: 'Review traffic to these legitimate shared services:', zone: 'report_body' },
    { id: 'b2', type: 'list_item', text: 'api.telegram.org', zone: 'explicit_ioc_section', zone_reason: 'observable_list' },
    { id: 'b3', type: 'list_item', text: 'backblazeb2.com', zone: 'explicit_ioc_section', zone_reason: 'observable_list' },
    { id: 'b4', type: 'list_item', text: 'storjshare.io', zone: 'explicit_ioc_section', zone_reason: 'observable_list' }
  ];
  demoteLegitimateServiceListDiscovery(blocks);
  assert.equal(blocks[1].zone, 'report_body');
  assert.equal(blocks[1].zone_reason, 'legitimate_service_list');
  assert.equal(blocks[3].zone_reason, 'legitimate_service_list');
});

test('PDF headings infer levels; filename/hash lines stay observational rows', () => {
  const bodyH = 10;
  assert.equal(inferPdfHeadingLevel({ text: '8. Indicators of Compromise', height: 14 }, { bodyHeight: bodyH }), 2);
  assert.equal(inferPdfHeadingLevel({ text: '3.2 Loaders', height: 12 }, { bodyHeight: bodyH }), 3);
  const md5 = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
  const pages = [
    {
      page: 1,
      items: [
        { str: 'Indicators of Compromise', transform: [1, 0, 0, 1, 50, 700], width: 200, height: 16, fontName: 'Bold' },
        { str: 'Loaders', transform: [1, 0, 0, 1, 50, 680], width: 60, height: 12, fontName: 'Bold' },
        { str: `loader.exe ${md5}`, transform: [1, 0, 0, 1, 50, 660], width: 220, height: 10, fontName: 'Mono' },
        { str: `helper.dll ${md5.replace(/e/g, 'f')}`, transform: [1, 0, 0, 1, 50, 645], width: 220, height: 10, fontName: 'Mono' }
      ]
    }
  ];
  // Minimal geometry: build via pagesToBlocks expects prepared pages from itemsToLines path.
  // Use plain observable-row assembly through annotate on synthetic blocks instead.
  const doc = createCanonicalDocument({
    title: 'pdf p1',
    blocks: [
      { id: 'h1', type: 'heading', text: 'Indicators of Compromise', level: 2, page: 1 },
      { id: 'h2', type: 'heading', text: 'Loaders', level: 3, page: 1 },
      { id: 'r1', type: 'list_item', text: `loader.exe ${md5}`, layout: 'observable_row', page: 1 },
      { id: 'r2', type: 'list_item', text: `helper.dll ${md5.replace(/e/g, 'f')}`, layout: 'observable_row', page: 1 }
    ]
  });
  const annotated = annotateDocumentZones(doc);
  assert.equal(annotated.blocks.find((b) => b.id === 'h2').zone, 'explicit_ioc_section');
  assert.equal(annotated.blocks.find((b) => b.id === 'r1').zone, 'explicit_ioc_section');
  const cands = extractCandidatesFromDocument(annotated);
  assert.equal(member(find(cands, 'md5', md5)), true);
});

test('truncated defanged hostname is not reconstructed into a shorter domain', () => {
  const html = `<article>
<h2>Indicators of Compromise</h2>
<ul><li><h3>C2</h3></li></ul>
<p>www.online.check-computer.kro[.]kr</p>
<p>cyber.lecture.site.online-driver.kro[.]k</p>
<p>konamo[.]xyz</p>
</article>`;
  const r = extractCanonicalDocumentFromHtml(html, {
    url: 'https://example.test/trunc',
    finalUrl: 'https://example.test/trunc',
    httpStatus: 200
  });
  assert.equal(r.ok, true);
  const cands = extractCandidatesFromDocument(annotateDocumentZones(r.document));
  assert.equal(find(cands, 'domain', 'cyber.lecture.site.online-driver.kro'), undefined);
  assert.equal(member(find(cands, 'domain', 'www.online.check-computer.kro.kr')), true);
  assert.equal(member(find(cands, 'domain', 'konamo.xyz')), true);
});

test('MODE B advisory Contact / reporting prose does not promote agency chrome as Indicators', () => {
  const html = `<article>
<h1>Iranian cyber targeting advisory</h1>
<p>Review traffic to these legitimate shared services:</p>
<ul><li>api[.]telegram[.]org</li><li>backblazeb2[.]com</li><li>storjshare[.]io</li></ul>
<h2>Contact</h2>
<h3>United Kingdom</h3>
<p>Please report significant cyber security incidents to report.ncsc.gov.uk (monitored 24/7)</p>
<h3>United States</h3>
<p>If you or someone you know has fallen victim to this campaign, file a complaint with the FBI Internet Crime Complaint Center at www.ic3.gov</p>
<h3>Netherlands</h3>
<p>Any individual suspecting or confirming a compromise should contact the General Intelligence Security Service (https://www.aivd.nl) or local law enforcement.</p>
</article>`;
  const url = 'https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists';
  const r = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(r.ok, true);
  const { candidates, diagnostics } = extractCandidatesWithDiagnostics(r.document, {
    sourceUrl: url,
    sourceHost: 'www.ncsc.gov.uk'
  });
  assert.equal(diagnostics.document_scope.has_authoritative_indicator_scope, false, 'MODE B: no publisher IOC appendix');
  assert.equal(member(find(candidates, 'domain', 'api.telegram.org')), false);
  assert.equal(member(find(candidates, 'domain', 'report.ncsc.gov.uk')), false, 'publisher reporting portal');
  assert.equal(member(find(candidates, 'domain', 'www.ic3.gov')), false, 'partner complaint portal');
  assert.equal(member(find(candidates, 'url', 'https://www.aivd.nl/')), false, 'partner contact URL');
});

test('incomplete URL path prefix of a sibling IOC URL is not an Indicator', () => {
  const html = `<article>
<h2>IOCs</h2>
<pre>http://203.0.113.55:443/t/
http://203.0.113.55:443/t/a779ab
http://203.0.113.55:443/t/ae7427</pre>
</article>`;
  const r = extractCanonicalDocumentFromHtml(html, {
    url: 'https://research.example/raven',
    finalUrl: 'https://research.example/raven',
    httpStatus: 200
  });
  assert.equal(r.ok, true);
  const cands = extractCandidatesFromDocument(annotateDocumentZones(r.document));
  assert.equal(member(find(cands, 'url', 'http://203.0.113.55:443/t/')), false, 'bare prefix');
  assert.equal(member(find(cands, 'url', 'http://203.0.113.55:443/t/a779ab')), true);
  assert.equal(member(find(cands, 'url', 'http://203.0.113.55:443/t/ae7427')), true);
});

test('independently asserted directory URL without a longer sibling stays an Indicator', () => {
  const html = `<article>
<h2>Indicators of compromise</h2>
<ul>
<li>http://203.0.113.88/payload/</li>
<li>http://203.0.113.88/gate.php</li>
<li>evil-c2[.]example</li>
</ul>
</article>`;
  const r = extractCanonicalDocumentFromHtml(html, {
    url: 'https://research.example/dir-url',
    finalUrl: 'https://research.example/dir-url',
    httpStatus: 200
  });
  assert.equal(r.ok, true);
  const cands = extractCandidatesFromDocument(annotateDocumentZones(r.document));
  assert.equal(member(find(cands, 'url', 'http://203.0.113.88/payload/')), true, 'standalone directory URL');
  assert.equal(member(find(cands, 'url', 'http://203.0.113.88/gate.php')), true);
  assert.equal(member(find(cands, 'domain', 'evil-c2.example')), true);
});

test('IOC-list root URL with a path sibling stays an Indicator', () => {
  const html = `<article>
<h2>Indicators of compromise</h2>
<ul>
<li>http://malware-drop.example/</li>
<li>http://malware-drop.example/stage2.bin</li>
</ul>
</article>`;
  const r = extractCanonicalDocumentFromHtml(html, {
    url: 'https://research.example/root-url',
    finalUrl: 'https://research.example/root-url',
    httpStatus: 200
  });
  assert.equal(r.ok, true);
  const cands = extractCandidatesFromDocument(annotateDocumentZones(r.document));
  assert.equal(member(find(cands, 'url', 'http://malware-drop.example/')), true, 'inventory root kept');
  assert.equal(member(find(cands, 'url', 'http://malware-drop.example/stage2.bin')), true);
});

test('C2-chrome origin is not an Indicator when only path URLs are in the IOC inventory', () => {
  const html = `<article>
<h2>Indicators of compromise</h2>
<p>URL</p>
<p>hxxps://drop.vendor-pack[.]example/stage2.enc</p>
<p>hxxps://drop.vendor-pack[.]example/Helper.pkg.enc</p>
<h3>C2</h3>
<p>hxxps://drop.vendor-pack[.]example</p>
</article>`;
  const r = extractCanonicalDocumentFromHtml(html, {
    url: 'https://research.example/root-chrome',
    finalUrl: 'https://research.example/root-chrome',
    httpStatus: 200
  });
  assert.equal(r.ok, true);
  const cands = extractCandidatesFromDocument(annotateDocumentZones(r.document));
  assert.equal(member(find(cands, 'url', 'https://drop.vendor-pack.example/')), false, 'C2-chrome origin demoted');
  assert.equal(member(find(cands, 'url', 'https://drop.vendor-pack.example/stage2.enc')), true);
  assert.equal(member(find(cands, 'url', 'https://drop.vendor-pack.example/Helper.pkg.enc')), true);
});

test('body Threat Infrastructure table values are not Indicators when appendix exists', () => {
  const html = `<article>
<h2>3. Analysis</h2>
<table><tr><th>IP</th><th>Domain</th><th>Registrar</th></tr>
<tr><td>203.0.113.10</td><td>nid.naver.rkfd[.]com</td><td>Godaddy</td></tr>
<tr><td>198.51.100.20</td><td>securedrivelog.register[.]im</td><td>Namecheap</td></tr>
</table>
<h2>8. Indicator of Compromise</h2>
<ul><li><h3>C2</h3></li></ul>
<p>www.online.check-computer.kro[.]kr</p>
<p>online.lecture-site.kro[.]kr</p>
<p>konamo[.]xyz</p>
</article>`;
  const r = extractCanonicalDocumentFromHtml(html, {
    url: 'https://example.test/genians',
    finalUrl: 'https://example.test/genians',
    httpStatus: 200
  });
  assert.equal(r.ok, true);
  const cands = extractCandidatesFromDocument(annotateDocumentZones(r.document, {
    sourceUrl: 'https://example.test/genians',
    sourceHost: 'example.test'
  }));
  assert.equal(member(find(cands, 'domain', 'nid.naver.rkfd.com')), false, 'body infrastructure domain');
  assert.equal(member(find(cands, 'domain', 'securedrivelog.register.im')), false, 'body infrastructure domain');
  assert.equal(member(find(cands, 'domain', 'www.online.check-computer.kro.kr')), true);
  assert.equal(member(find(cands, 'domain', 'online.lecture-site.kro.kr')), true);
  assert.equal(member(find(cands, 'domain', 'konamo.xyz')), true);
});
