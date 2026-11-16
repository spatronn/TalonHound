/**
 * 27-report review queue 35904–35934 (tl-candidates-v70, tl-section-tree-v22,
 * tl-zones-v20, tl-table-v20, tl-digest-v6).
 *
 * A. 35915: an IOC table cell "sha256:<hex>" is that digest (8 rows were
 *    rejected as invalid_domain). The algorithm must name the run's length.
 * B. 35907 / 35908 / 35915: Git commit / blob ids and a container image index
 *    digest name repository / registry objects, never file samples; a digest
 *    joined by "and" shares the previous digest's label.
 * C. 35921: a 32-hex run that is a whole inner hostname label
 *    ("soraki-proxy.<hex>.workers[.]dev") is part of the host, not an MD5;
 *    "stage.<hex>.exe" and "<hex>.bin" stay hashes.
 * D. 35905: "46.166.79[.]31:5432/TCP" is an endpoint with its transport, not a
 *    URL; the address is read with its port.
 * E. 35913: "Appendix D — References" nested under an open IOC heading ends
 *    its authority for its own subtree (including inner labels).
 * F. 35916: the post's featured image on the publisher host after the last
 *    IOC table is page metadata, not an inventory row.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { extractReportCandidates } from './extractionStages.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { SECTION_TREE_VERSION } from './sectionTree/version.js';
import { THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, classifyHeadingText } from './documentZones.js';
import { TABLE_SEMANTICS_VERSION, algorithmPrefixedDigest, parseIndicatorCell } from './tableSemantics.js';
import { DIGEST_KINDS, classifyHexDigest } from './digestSemantics.js';
import { hexRunIsHostnameLabelFragment } from './sourceOccurrence.js';

const H64_WHL = '7598727f209d717041db37f7dca271d3a7d328a279890e0e1d55375729aeb86d';
const H64_INDEX = '1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e';
const H32_LABEL = '20245aad98d27b1b1a2f0f103e1d7ee0';

test('review queue 35904 contracts', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v72');
  assert.equal(SECTION_TREE_VERSION, 'tl-section-tree-v22');
  assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v20');
  assert.equal(TABLE_SEMANTICS_VERSION, 'tl-table-v21');
});

function extract(blocks, sourceUrl = 'https://publisher.example/report') {
  return extractReportCandidates(
    { source_type: 'url', source_url: sourceUrl },
    createCanonicalDocument({ title: 'Review queue 35904 fixture', blocks })
  );
}

function find(result, type, value) {
  return result.candidates.find((c) => c.candidate_type === type && c.normalized_value === value) || null;
}

function assertMember(result, type, value) {
  const c = find(result, type, value);
  assert.ok(c, `missing candidate ${type}:${value}`);
  assert.equal(isReportIndicatorMember(c), true, `${type}:${value} ${c.policy_decision} ${c.membership_decision?.rule_id}`);
  return c;
}

function assertNotMember(result, type, value) {
  const c = find(result, type, value);
  if (!c) return null;
  assert.equal(isReportIndicatorMember(c), false, `${type}:${value} became ${c.policy_decision} ${c.membership_decision?.rule_id}`);
  return c;
}

test('A: an algorithm-prefixed digest cell is that digest; a mismatched prefix is not', () => {
  assert.equal(algorithmPrefixedDigest(`sha256:${H64_WHL}`), H64_WHL);
  assert.equal(algorithmPrefixedDigest(`SHA-256=${H64_WHL}`), H64_WHL);
  assert.equal(algorithmPrefixedDigest(`md5:${H64_WHL}`), null);
  assert.equal(algorithmPrefixedDigest(`imphash:${H32_LABEL}`), null);
  const parsed = parseIndicatorCell(`sha256:${H64_WHL}`, null);
  assert.equal(parsed.values.length, 1);
  assert.equal(parsed.values[0].candidate_type, 'sha256');
  assert.equal(parsed.values[0].normalized_value, H64_WHL);
  assert.equal(parsed.values[0].raw, `sha256:${H64_WHL}`);

  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
    createTableBlock({
      id: 't1',
      headers: ['Indicator', 'Notes'],
      rows: [
        ['litellm[.]dev', 'Exfiltration domain'],
        [`sha256:${H64_INDEX}`, 'Infected litellm image index'],
        [`sha256:${H64_WHL}`, 'Malicious litellm macOS x86-64 .whl hash']
      ]
    })
  ]);
  assertMember(result, 'domain', 'litellm.dev');
  assertMember(result, 'sha256', H64_WHL);
  assertNotMember(result, 'sha256', H64_INDEX);
  const index = find(result, 'technical_artifact', H64_INDEX);
  assert.ok(index, 'image index digest stays visible as context');
  assert.equal(index.digest_kind, DIGEST_KINDS.OBJECT_ID);
});

test('B: Git commit / blob ids are object identifiers, not file samples', () => {
  const commit = 'de2f74e784b2eafa0d66fbb6d88b42ea11ee34cf';
  const c1 = '2de727046706062d38edfbbf8340f32d1eb2bdfb';
  const c2 = 'dc7d7455c95b3092eb14bff2bd93315b84b066fa';
  const blob = 'ee6e5addfe591923fc385553cb66cf0d25634a6b';
  assert.equal(classifyHexDigest(`bee-js commit ${commit}`, commit).kind, DIGEST_KINDS.OBJECT_ID);
  assert.equal(classifyHexDigest(`Swarm Desktop commits ${c1} and ${c2}`, c2).kind, DIGEST_KINDS.OBJECT_ID);
  assert.equal(classifyHexDigest(`file docs/wfx-audit.md (git blob ${blob})`, blob).kind, DIGEST_KINDS.OBJECT_ID);
  // A file noun after the word keeps the sample reading; "and" between two
  // file hashes keeps the file reading of the first.
  assert.equal(classifyHexDigest(`SHA256 of committed dropper: ${H64_WHL}`, H64_WHL).kind, DIGEST_KINDS.FILE);
  assert.equal(classifyHexDigest(`loader.exe ${H64_INDEX} and ${H64_WHL}`, H64_WHL).kind, DIGEST_KINDS.FILE);

  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of Compromise (IOCs)' },
    { id: 'h2', type: 'heading', level: 3, text: 'Malicious Package and Release' },
    { id: 'l1', type: 'list', text: `bee-js commit ${commit}` },
    { id: 'l2', type: 'list', text: `Swarm Desktop commits ${c1} and ${c2}` },
    { id: 'l3', type: 'list', text: `Pull request: branch wfx-docs; file docs/wfx-audit.md (git blob ${blob})` },
    { id: 'h3', type: 'heading', level: 3, text: 'File Hashes (SHA-256)' },
    { id: 'l4', type: 'list', text: `bee-js-13.3.0.tgz: ${H64_WHL}` }
  ]);
  assertMember(result, 'sha256', H64_WHL);
  for (const v of [commit, c1, c2, blob]) {
    assert.equal(find(result, 'sha1', v), null, `sha1:${v} must not be a file-hash candidate`);
    assert.ok(find(result, 'technical_artifact', v), `object id ${v} stays visible as context`);
  }
});

test('C: a hex run that is a whole inner hostname label belongs to the host', () => {
  const host = `soraki-proxy.${H32_LABEL}.workers.dev`;
  const at = host.indexOf(H32_LABEL);
  assert.equal(hexRunIsHostnameLabelFragment(host, at, at + 32), true);
  for (const text of [`stage.${H32_LABEL}.exe`, `${H32_LABEL}.bin`, `x ${H32_LABEL}. Next`]) {
    const i = text.indexOf(H32_LABEL);
    assert.equal(hexRunIsHostnameLabelFragment(text, i, i + 32), false, text);
  }
  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
    { id: 'h2', type: 'heading', level: 3, text: 'Exfiltration locations' },
    { id: 'c1', type: 'code', text: `soraki-proxy.${H32_LABEL}.workers[.]dev` }
  ]);
  assertMember(result, 'domain', host);
  assert.equal(find(result, 'md5', H32_LABEL), null);
});

test('D: ip:port/TCP is an endpoint, not a URL', () => {
  const result = extract([
    { id: 'p1', type: 'paragraph', text: 'The 1C server process initiated an outbound connection to an external PostgreSQL server controlled by the attackers: rphost.exe → 46.166.79[.]31:5432/TCP.' },
    { id: 'h1', type: 'heading', level: 2, text: 'Network indicators' },
    { id: 'l1', type: 'list', text: '46.166.79[.]31' }
  ]);
  assert.equal(find(result, 'url', '46.166.79.31:5432/TCP'), null);
  assertMember(result, 'ip', '46.166.79.31');
});

test('E: a nested "Appendix D — References" ends the IOC heading above it', () => {
  assert.equal(classifyHeadingText('Appendix D — References'), 'reference_section');
  assert.equal(classifyHeadingText('Annex 2: Further reading'), 'reference_section');
  assert.equal(classifyHeadingText('Appendix C — Static Analysis Notes'), null);
  const result = extract([
    { id: 'h1', type: 'heading', level: 2, text: 'Technical Indicators and Reference Data' },
    { id: 'p0', type: 'paragraph', text: 'The following information is provided for security teams investigating or detecting activity associated with this campaign.' },
    { id: 'h2', type: 'heading', level: 5, text: 'Appendix B — Network Indicators' },
    { id: 'p1', type: 'paragraph', text: 'Redirect/shortener domains:' },
    { id: 'p2', type: 'paragraph', text: 'authgpt.info' },
    { id: 'p3', type: 'paragraph', text: 'ai-billing.info' },
    { id: 'h3', type: 'heading', level: 5, text: 'Appendix D — References' },
    { id: 'p4', type: 'paragraph', text: 'Public corroboration:' },
    { id: 'p5', type: 'paragraph', text: 'pcrisk.es — documents 188f0289b4[.]nxcli.io by name as a fraudulent OpenAI subscription payment page.' },
    { id: 'p6', type: 'paragraph', text: 'Hosting provider documentation:' },
    { id: 'p7', type: 'paragraph', text: 'https://www.nexcess.com/platform/sites-stores/' }
  ]);
  assertMember(result, 'domain', 'authgpt.info');
  assertMember(result, 'domain', 'ai-billing.info');
  assertNotMember(result, 'domain', 'pcrisk.es');
  assertNotMember(result, 'url', 'https://www.nexcess.com/platform/sites-stores/');
});

test('F: the publisher\'s featured image after the last IOC table is page metadata', () => {
  const cover = 'https://i0.wp.com/www.d3lab.net/wp-content/uploads/2026/09/cover.png?fit=1672%2C941&ssl=1';
  const result = extract(
    [
      { id: 'h1', type: 'heading', level: 2, text: 'SHA-256 hashes of key artefacts' },
      createTableBlock({ id: 't1', headers: ['Artefact', 'SHA-256'], rows: [['BQW1eqi3.js', H64_WHL]] }),
      { id: 'p1', type: 'paragraph', text: '22 Settembre 2026' },
      { id: 'p2', type: 'paragraph', text: cover }
    ],
    'https://www.d3lab.net/an-italian-phishing-campaign-delivering-an-ios-exploit-chain/'
  );
  assertMember(result, 'sha256', H64_WHL);
  assertNotMember(result, 'url', cover);
});
