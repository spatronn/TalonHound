/**
 * Section authority boundaries, through the real HTML and PDF adapters: positive,
 * negative, ambiguous and reordered layouts. A heading decides authority for its own
 * content only when it names an inventory group or holds rows.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractReportCandidates } from './extractionStages.js';
import { linesToBlocks, isFormalSectionTitleLine } from './pdfLayout.js';
import { trimUrlBoundary } from './observableTypeResolver.js';
import { createCanonicalDocument } from './canonicalDocument.js';
import { decideMembership, MEMBERSHIP_OUTCOME as O } from './membershipDecision.js';

const url = 'https://publisher.example/blog/report';
const PROSE = '<p>The operators rotate their infrastructure between waves and reuse the same loader across victims in several regions.</p>';
const list = (values) => `<ul>${values.map((v) => `<li>${v}</li>`).join('')}</ul>`;

function read(body) {
  const ex = extractCanonicalDocumentFromHtml(`<html><body><article><h1>Report title</h1>${PROSE}${body}</article></body></html>`, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(ex.ok, true);
  return readDocument(ex.document);
}

function readDocument(document) {
  const r = extractReportCandidates({ id: 1, source_url: url, source_type: 'url' }, document);
  const decision = (value) => r.candidates.find((c) => c.normalized_value === value)?.membership_decision;
  return { r, outcome: (value) => decision(value)?.outcome, rule: (value) => decision(value)?.rule_id, decision };
}

const IOC = `<h2>Indicators of Compromise</h2>${list(['evil-c2-one.net', 'evil-c2-two.net'])}`;

test('positive: rows under the IOC heading and its typed groups are publisher assertions', () => {
  const x = read(`<h2>Indicators of Compromise</h2><h3>Domains</h3>${list(['evil-c2-one.net'])}<h3>Network</h3>${list(['evil-c2-two.net'])}`);
  assert.equal(x.outcome('evil-c2-one.net'), O.MEMBER);
  assert.equal(x.outcome('evil-c2-two.net'), O.MEMBER);
  assert.equal(x.rule('evil-c2-two.net'), 'R10_publisher_assertion');
});

test('nested "About the Author" does not inherit the appendix, as prose or as a list', () => {
  for (const content of ['<p>Follow the author at author-homepage.net for more research.</p>', list(['author-homepage.net'])]) {
    const x = read(`${IOC}<h3>About the Author</h3>${content}`);
    assert.equal(x.outcome('evil-c2-one.net'), O.MEMBER);
    assert.notEqual(x.outcome('author-homepage.net'), O.MEMBER, content);
    assert.notEqual(x.rule('author-homepage.net'), 'R10_publisher_assertion', content);
  }
});

test('a later inventory group after a non-group section is asserted again', () => {
  const x = read(`${IOC}<h3>Analyst notes</h3><p>We rate these with moderate confidence after reviewing telemetry.</p><h3>Hashes</h3>${list(['9a1dd1d96481d61934dcc2d568971d06'])}`);
  assert.equal(x.outcome('9a1dd1d96481d61934dcc2d568971d06'), O.MEMBER);
});

test('a bold sibling line ends a C2 scope for the prose under it', () => {
  const x = read(`<h2>C2 servers</h2>${list(['evil-c2-one.net', 'evil-c2-two.net'])}<p><strong>Legitimate cloud services</strong></p><p>The implant also reads from storage.cloudvendor.net to fetch public configuration.</p>`);
  assert.equal(x.outcome('evil-c2-one.net'), O.MEMBER);
  assert.notEqual(x.outcome('storage.cloudvendor.net'), O.MEMBER);
  assert.notEqual(x.rule('storage.cloudvendor.net'), 'R44_unresolved_section_narrative', 'not read as narrative inside the C2 scope');
});

test('a value table under a heading calling its files legitimate is not asserted', () => {
  const x = read(`${IOC}<h3>Legitimate files leveraged for DLL sideloading</h3><table><tr><th>MD5</th><th>Name</th></tr><tr><td>9a1dd1d96481d61934dcc2d568971d06</td><td>vendor.exe</td></tr></table>`);
  assert.notEqual(x.outcome('9a1dd1d96481d61934dcc2d568971d06'), O.MEMBER);
  assert.ok(x.outcome('9a1dd1d96481d61934dcc2d568971d06'), 'still visible');
});

test('a field line of a key-value record stays inside its record', () => {
  const x = read(`<h2>Indicators of Compromise</h2><p>SHA256 hash: e4521c560f99ae638d5f68a472f0f7497596cca8ed22cfa21276a94f6463f3fc</p><p>Description: Per-victim rule delivery</p><p>SHA256 hash: 0a4521c560f99ae638d5f68a472f0f7497596cca8ed22cfa21276a94f6463f3f</p>`);
  assert.equal(x.outcome('0a4521c560f99ae638d5f68a472f0f7497596cca8ed22cfa21276a94f6463f3f'), O.MEMBER);
});

test('an IPv6 row with a date note is a row, not a section label', () => {
  const x = read(`<h2>Indicators of Compromise</h2><p>2607:5500:3000:1cab::2 (since 2024-08-28)</p><p>2607:5500:3000:7bc::2 (since 2024-09-10)</p>`);
  assert.equal(x.outcome('2607:5500:3000:1cab::2'), O.MEMBER);
  assert.equal(x.outcome('2607:5500:3000:7bc::2'), O.MEMBER);
});

test('a typed table under a sibling heading reaches review, in either section order', () => {
  const table = '<h2>Campaign clusters</h2><table><tr><th>Type</th><th>Value</th></tr><tr><td>domain</td><td>cluster-a.net</td></tr><tr><td>ip</td><td>45.77.1.9</td></tr></table>';
  for (const body of [`${IOC}${table}`, `${table}${IOC}`]) {
    const x = read(body);
    assert.equal(x.outcome('evil-c2-one.net'), O.MEMBER);
    for (const v of ['cluster-a.net', '45.77.1.9']) {
      assert.equal(x.outcome(v), O.NEEDS_REVIEW, v);
      assert.equal(x.rule(v), 'R40_structured_rows_uncertain_section', v);
    }
  }
});

test('section order does not change any outcome', () => {
  const blocks = {
    ioc: IOC,
    prose: '<h2>Analysis</h2><p>The loader beacons to narrative-c2.net during installation.</p>',
    refs: `<h2>References</h2>${list(['https://research-blog.net/post'])}`
  };
  const orders = [['ioc', 'prose', 'refs'], ['prose', 'ioc', 'refs'], ['prose', 'refs', 'ioc']];
  const seen = orders.map((o) => {
    const x = read(o.map((k) => blocks[k]).join(''));
    return ['evil-c2-one.net', 'narrative-c2.net', 'https://research-blog.net/post'].map((v) => x.outcome(v));
  });
  assert.deepEqual(seen[1], seen[0]);
  assert.deepEqual(seen[2], seen[0]);
  assert.deepEqual(seen[0], [O.MEMBER, O.NEEDS_REVIEW, O.CONTEXT_ONLY]);
});

test('a narrative operational statement is never asserted, with or without an inventory', () => {
  const alone = read('<p>The loader beacons to narrative-c2.net during installation.</p>');
  assert.equal(alone.outcome('narrative-c2.net'), O.NEEDS_REVIEW);
  assert.equal(alone.rule('narrative-c2.net'), 'R31_operational_statement');
  const beside = read(`<p>The loader beacons to narrative-c2.net during installation.</p>${IOC}`);
  assert.equal(beside.outcome('narrative-c2.net'), O.NEEDS_REVIEW);
  assert.equal(beside.rule('narrative-c2.net'), 'R41_operational_statement');
});

test('victims, benign services, references and placeholders are never asserted', () => {
  const x = read(`<p>The victim, victim-corp.net, was notified. The malware also checks connectivity against the legitimate service www.cloudvendor.net.</p>${IOC}<h2>References</h2>${list(['https://research-blog.net/post'])}`);
  for (const v of ['victim-corp.net', 'www.cloudvendor.net', 'https://research-blog.net/post']) {
    assert.notEqual(x.outcome(v), O.MEMBER, v);
  }
  const placeholders = read(`<h2>Indicators of Compromise</h2>${list(['example.com', '127.0.0.1', 'evil-c2-one.net'])}`);
  assert.equal(placeholders.outcome('evil-c2-one.net'), O.MEMBER);
  for (const v of ['example.com', '127.0.0.1']) assert.notEqual(placeholders.outcome(v), O.MEMBER, v);
});

test('every decision names its rule, reason, evidence and contract', () => {
  const x = read(`<p>The loader beacons to narrative-c2.net during installation.</p>${IOC}`);
  for (const v of ['narrative-c2.net', 'evil-c2-one.net']) {
    const d = x.decision(v);
    assert.ok(d.rule_id && d.reason_code && d.contract_version, v);
    assert.ok(d.evidence_refs.length > 0, `${v} has an evidence reference`);
  }
});

test('R31 and R32: a prose statement goes to review; a grounded model verdict does not change that', () => {
  const operational = { operational_clause: true };
  assert.equal(decideMembership(operational, {}, {}, {}, { sections: ['uncertain'] }, {}).outcome, O.NEEDS_REVIEW);
  const unsupported = decideMembership(operational, {}, {}, {}, { sections: ['uncertain'] }, { assessment: 'malicious', supported: false, applied: false });
  assert.equal(unsupported.rule_id, 'R31_operational_statement');
  const grounded = decideMembership(operational, {}, {}, {}, { sections: ['uncertain'] }, { assessment: 'malicious', supported: true, applied: true });
  assert.equal(grounded.outcome, O.NEEDS_REVIEW);
  assert.equal(grounded.rule_id, 'R32_grounded_model_assessment');
  const curated = decideMembership(operational, {}, {}, {}, { sections: ['uncertain'], document_has_asserting_section: true }, { assessment: 'malicious', supported: true, applied: true });
  assert.equal(curated.outcome, O.NEEDS_REVIEW);
});

// --- plain PDF: every line in the body font, no heading metadata -------------------

function plainPdfDocument(lines) {
  const items = lines.map((text, i) => ({ text, y: 780 - i * 14, x: 50, height: 11, fontName: 'F1', itemCount: 1, cells: [{ text, x: 50 }] }));
  const { blocks } = linesToBlocks(items, { pageNum: 1, startIdx: 1, bodyFonts: new Set(['F1']), bodyHeight: 11, tables: false });
  return createCanonicalDocument({ title: 'Plain PDF', language: 'en', blocks, meta: { adapter: 'pdf', extractor: 'threat_library_pdf_v8' } });
}

const PDF_LINES = ['The operators of the campaign relied on a small set of servers.', 'The loader beacons to narrative-c2.net during installation.', 'Indicators of Compromise', 'evil-c2-one.net', 'evil-c2-two.net', 'Recommendations', 'Review outbound connections to storage.cloudvendor.net regularly.'];

test('plain PDF: a body-font IOC title opens the section; narrative prose stays out of it', () => {
  const doc = plainPdfDocument(PDF_LINES);
  assert.ok(doc.blocks.some((b) => b.type === 'heading' && b.text === 'Indicators of Compromise'), JSON.stringify(doc.blocks.map((b) => [b.type, b.text])));
  const x = readDocument(doc);
  assert.equal(x.outcome('evil-c2-one.net'), O.MEMBER);
  assert.equal(x.rule('evil-c2-one.net'), 'R10_publisher_assertion');
  assert.equal(x.outcome('narrative-c2.net'), O.NEEDS_REVIEW);
  assert.notEqual(x.outcome('storage.cloudvendor.net'), O.MEMBER);
});

test('plain PDF: an IOC title after a line with no closing punctuation still opens the section', () => {
  const doc = plainPdfDocument(['The full list is available at https://github.com/publisher/iocs/blob/main/full.csv', 'Indicators of Compromise', 'evil-c2-one.net', 'evil-c2-two.net']);
  const x = readDocument(doc);
  assert.equal(x.rule('evil-c2-one.net'), 'R10_publisher_assertion');
});

test('plain PDF: a title-like phrase inside a sentence does not become a heading', () => {
  const doc = plainPdfDocument(['Our analysis of the campaign covers its', 'references', 'and how the loader was delivered.']);
  assert.ok(!doc.blocks.some((b) => b.type === 'heading'), JSON.stringify(doc.blocks.map((b) => [b.type, b.text])));
});

test('formal section titles are whole lines only', () => {
  for (const t of ['Indicators of Compromise', 'IOCs', '8. Indicators of Compromise (IoCs)', 'Appendix A: Indicators of Compromise', 'References', 'About the Author']) {
    assert.equal(isFormalSectionTitleLine(t), true, t);
  }
  for (const t of ['Indicators of compromise were shared with partners', 'See the references below for more', 'The IOCs']) {
    assert.equal(isFormalSectionTitleLine(t), false, t);
  }
});

// --- defects the historical replay ledger exposed ---------------------------------

test('a hash found by a similarity pivot is still a file hash', () => {
  const hash = 'b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678';
  const x = read(`<h2>Indicators of Compromise</h2><h3>File Hashes (SHA-256)</h3>${list([`p.mjs.malicious (Variant of setup.mjs based on TLSH pivot): ${hash}`])}`);
  assert.equal(x.r.candidates.find((c) => c.normalized_value === hash)?.candidate_type, 'sha256');
  assert.equal(x.outcome(hash), O.MEMBER);
});

test('a real TLSH or ssdeep attribute label still keeps a digest out of the file hashes', () => {
  const hash = 'b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678';
  const x = read(`<h2>Indicators of Compromise</h2>${list([`TLSH: ${hash}`])}`);
  assert.notEqual(x.r.candidates.find((c) => c.normalized_value === hash)?.candidate_type, 'sha256');
});

test('domains written with a title-cased TLD are domains; code members are not', () => {
  const x = read('<p>The identified domains included cycl.Top, chumchurum.Org and chumchuru.Com.</p>');
  for (const v of ['cycl.top', 'chumchurum.org', 'chumchuru.com']) {
    assert.ok(x.r.candidates.some((c) => c.candidate_type === 'domain' && c.normalized_value === v), v);
    assert.equal(x.outcome(v), O.NEEDS_REVIEW, v);
  }
  const code = read('<p>The loader calls System.Net and then invokes client.Run before exiting.</p>');
  assert.ok(!code.r.candidates.some((c) => c.candidate_type === 'domain' && /system\.net|client\.run/.test(c.normalized_value)));
});

test('a host named inside a behaviour sentence in an indicator table is not asserted', () => {
  const x = read(`<h2>Host Indicators</h2><table><tr><th>Indicator</th><th>Meaning</th></tr>
    <tr><td>evil-c2-one.net</td><td>Active C2 session</td></tr>
    <tr><td>8,192 simultaneous outbound connections to speedtest-host.net followed by process termination</td><td>Bandwidth profiling</td></tr></table>`);
  assert.equal(x.outcome('evil-c2-one.net'), O.MEMBER);
  assert.notEqual(x.outcome('speedtest-host.net'), O.MEMBER);
  assert.ok(x.outcome('speedtest-host.net'), 'still visible');
});

// --- What was measured on stored model verdicts: abused legitimate services reach R32. ---

test('a model verdict on an abused legitimate service does not make it an Indicator', () => {
  const statement = { operational_clause: true };
  const verdict = { assessment: 'malicious', supported: true, applied: true };
  const d = decideMembership(statement, {}, {}, {}, { sections: ['uncertain'] }, verdict);
  assert.equal(d.outcome, O.NEEDS_REVIEW);
  assert.equal(d.inputs.model_assessment, 'malicious', 'the analyst can see what the model said');
  assert.equal(decideMembership({}, {}, {}, {}, { sections: ['uncertain'] }, { assessment: 'malicious', supported: null, applied: true }).outcome, O.NEEDS_REVIEW, 'nor can an unchecked one');
  assert.equal(decideMembership({ structured_row: true }, {}, {}, {}, { sections: ['uncertain'] }, {}).outcome, O.MEMBER, 'the structured inventory of a document without a curated section still counts');
  assert.equal(decideMembership({}, { explicit: true }, {}, {}, { sections: ['asserting'] }, {}).outcome, O.MEMBER, 'publisher assertions still count');
});

test('the contract fingerprint changes when the membership rules do', async () => {
  const { extractionContractBundle, contractFingerprint } = await import('./contractBundle.js');
  const bundle = extractionContractBundle();
  assert.match(bundle.membership, /^tl-membership-decision-v\d+$/);
  assert.notEqual(contractFingerprint(bundle), contractFingerprint({ ...bundle, membership: 'tl-membership-decision-v0' }));
});

test('a publisher truncation mark ends a URL, like a redaction mark, and leaves no bracket in its identity', () => {
  assert.equal(trimUrlBoundary('https://files.evil-host.net/v1/content.zip[...]'), 'https://files.evil-host.net/v1/content.zip');
  assert.equal(trimUrlBoundary('https://files.evil-host.net/v1/content.zip[\u2026]'), 'https://files.evil-host.net/v1/content.zip');
  assert.equal(trimUrlBoundary('https://h.example/a?b=[REDACTED]'), 'https://h.example/a?b=');
  assert.equal(trimUrlBoundary('https://h.example/a[1]/b'), 'https://h.example/a[1]/b', 'an ordinary bracketed segment stays');
});
