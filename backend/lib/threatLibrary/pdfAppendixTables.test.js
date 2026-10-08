/**
 * PDF IOC appendix tables (threat_library_pdf_v4 / tl-table-v4 /
 * tl-type-resolver-v7 / tl-candidates-v17).
 *
 * A government-advisory style PDF sets text size in the text matrix with
 * `1 Tf`, so pdf.js 1.x reports `item.height` ≈ size² (11 pt → ~120 pt). The
 * v3 layout trusted that height: y-grouping merged ~10 table rows into one
 * "line", adjacent cells were glued into synthetic domains / fake SHA-256s,
 * no appendix table was reconstructed, MODE A was never detected and every
 * glued artifact became a report Indicator. Each test pins one generic step.
 *
 * The fixture is synthetic pdf.js text items with that geometry (double-scaled
 * height, centred table headers, double-spaced rows, labelled multi-line hash
 * cells, a narrow gutter, a pdf.js phantom space, a wrapped digest).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  glyphHeight,
  isPhantomSpaceOverlap,
  itemsToLines,
  joinWrappedCellFragments,
  pagesToBlocks,
  rowBreakGap,
  PDF_LAYOUT_VERSION
} from './pdfLayout.js';
import { createCanonicalDocument } from './canonicalDocument.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { deriveMatchState } from './constants.js';
import { interpretIocTable, isInlineTypeLabelToken, parseIndicatorCell } from './tableSemantics.js';
import { hasCodeIdentifierShape } from './observableTypeResolver.js';

const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// --- synthetic pdf.js items --------------------------------------------------

const PAGE_HEIGHT = 792;
/** pdf.js 1.x item for text sized in Tm with `1 Tf`: height = size × size. */
function item(str, x, y, size, font = 'g_d0_f1', width = null) {
  return {
    str,
    transform: [size, 0, 0, size, x, y],
    width: width ?? str.length * size * 0.5,
    height: size * size,
    fontName: font
  };
}
const chrome = () => [
  item('TLP:CLEAR ', 527, 738.5, 11, 'g_d0_f3'),
  item('ACME | ADVISORY | PARTNERS', 478, 722, 10),
  item('Page of 4 | Product ID: XX00-000A', 1.4, 36.7, 9)
];
const heading = (text, y) => item(text, 36, y, 16, 'g_d0_f5');
const caption = (text, y) => item(text, 246, y, 11, 'g_d0_f9');
const prose = (lines, y0, pitch = 15) => lines.map((t, i) => item(t, 36, y0 - i * pitch, 11));

const NARRATIVE_ONLY = 'staging.narrative-only[.]net';
const SHARED = 'c2.alpha-relay[.]com';
const DOMAIN_ROWS = [
  '_msdcs.corp-relay[.]com',
  SHARED,
  'update.beta-cdn[.]net',
  '154-119-131-252.m.gamma-scan[.]net',
  null, // phantom-space row (below)
  'mail.delta-host[.]org',
  'vpn21.epsilon-net[.]com'
];
const IPS = ['45.32.140[.]182', '36.249.156[.]51', '112.5.168[.]102', '59.120.167[.]25', '218.66.163.188'];
const WEBSHELLS = ['b374.php', 'back.pl', 'error.jsp', 'gf.phtml'];
const TOOLS = [
  { name: ['toolkitScanne', 'r.py'], category: ['Enumerati', 'on'], key: 'tool-a', gutter: true },
  { name: ['probe.exe'], category: ['Scanning'], key: 'tool-b', wrapTail: 1 }
];

function page1() {
  return [
    ...chrome(),
    heading('Technical Details', 695),
    ...prose([
      `The actors operated a relay at ${SHARED} for command and control of implants.`,
      `Operators also staged payloads on ${NARRATIVE_ONLY} which served as the C2 server for a week.`,
      'Affected versions include 2.3.19 to 2.3.20.2 of the framework before the vendor patch.',
      'Network defenders should review the appendix for the complete list of indicators.',
      'Additional context on the campaign appears in the remaining sections of this advisory.'
    ], 670)
  ];
}

function page2() {
  const items = [
    ...chrome(),
    heading('Appendix A: Indicators of Compromise', 695),
    ...prose(['See Table 10 to Table 13 for a list of observed IOCs. The IOCs listed in the appendices may', 'or may not be addressed in the body of this document.'], 672),
    caption('Table 10. Domain Names', 543),
    item('Domain', 172.9, 518.9, 10.5),
    item('First Seen', 379.7, 518.9, 10.5),
    item('Last Seen', 495.8, 518.9, 10.5)
  ];
  DOMAIN_ROWS.forEach((d, i) => {
    const y = 492.8 - i * 26.8;
    if (d) items.push(item(d, 41.6, y, 10.5, 'g_d0_f1', d.length * 5));
    else {
      // pdf.js turned a TJ kern into spaces inside one item and counted them in its width.
      items.push(item('2-  12', 41.6, y, 10.5, 'g_d0_f1', 27.4));
      items.push(item('-44-140.h.gamma-scan[.]net ', 62.7, y, 10.5, 'g_d0_f1', 125));
    }
    items.push(item('1/18/2019', 349.5, y, 10.5, 'g_d0_f1', 52.7));
    items.push(item('1/18/2027*', 465.3, y, 10.5, 'g_d0_f1', 58.8));
  });
  return items;
}

function page3() {
  const items = [...chrome(), caption('Table 11. IP Addresses', 700), item('IP Address', 120, 676, 10.5), item('First Seen', 300, 676, 10.5), item('Last Seen', 420, 676, 10.5)];
  IPS.forEach((ip, i) => {
    const y = 650 - i * 26.8;
    items.push(item(ip, 115, y, 10.5, 'g_d0_f1', ip.length * 5), item('3/15/2023', 300, y, 10.5), item('3/20/2023', 420, y, 10.5));
  });
  return items;
}

function page4() {
  const items = [...chrome(), caption('Table 13. Leveraged Webshells', 700), item('Name', 70, 676, 10.5), item('Hashes', 364, 676, 10.5)];
  // Rows: "MD5: …" on top, name vertically centred beside "SHA-256:", digest below.
  let y = 650;
  for (const name of WEBSHELLS) {
    items.push(item(`MD5: ${md5(name)}`, 193, y, 10.5, 'g_d0_f1', 210));
    items.push(item(name, 45, y - 17.3, 10.5, 'g_d0_f1', name.length * 5.5), item('SHA-256:', 193, y - 17.3, 10.5, 'g_d0_f1', 45));
    items.push(item(sha256(name), 193, y - 34.6, 10.5, 'g_d0_f1', 360));
    y -= 61.3;
  }
  items.push(caption('Table 14. Leveraged Binaries and Scripts', y - 10));
  y -= 36;
  items.push(item('Name', 70, y, 10.5), item('Category', 138, y, 10.5), item('Hashes', 364, y, 10.5));
  y -= 26.2;
  for (const t of TOOLS) {
    const digest = sha256(t.key);
    items.push(item(`MD5: ${md5(t.key)}`, 193, y, 10.5, 'g_d0_f1', 210));
    if (t.gutter) {
      // Long name set right up against the category column: closer than a cell gap.
      items.push(item(t.name[0], 45, y - 10.2, 10.5, 'g_d0_f1', 82), item(t.category[0], 131, y - 10.2, 10.5, 'g_d0_f1', 46));
      items.push(item(t.name[1], 45, y - 20.3, 10.5, 'g_d0_f1', 21), item(t.category[1], 131, y - 20.3, 10.5, 'g_d0_f1', 14), item('SHA-256:', 193, y - 20.3, 10.5, 'g_d0_f1', 45));
      items.push(item(digest, 193, y - 34.6, 10.5, 'g_d0_f1', 360));
      y -= 61.3;
    } else {
      items.push(item(t.name[0], 45, y - 17.3, 10.5, 'g_d0_f1', 50), item(t.category[0], 131, y - 17.3, 10.5, 'g_d0_f1', 42), item('SHA-256:', 193, y - 17.3, 10.5, 'g_d0_f1', 45));
      items.push(item(digest.slice(0, 63), 193, y - 31.6, 10.5, 'g_d0_f1', 355));
      items.push(item(digest.slice(63), 193, y - 45.9, 10.5, 'g_d0_f1', 6));
      y -= 72.6;
    }
  }
  return items;
}

const PAGES = [page1(), page2(), page3(), page4()].map((items, i) => ({ page: i + 1, items, pageHeight: PAGE_HEIGHT }));

/** Publisher-asserted identities of the fixture appendix (Tables 10, 11, 13, 14). */
const PUBLISHER = new Set([
  ...DOMAIN_ROWS.filter(Boolean).map((d) => `domain:${d.replace(/\[\.\]/g, '.').toLowerCase()}`),
  'domain:2-12-44-140.h.gamma-scan.net',
  ...IPS.map((ip) => `ip:${ip.replace(/\[\.\]/g, '.')}`),
  ...WEBSHELLS.flatMap((n) => [`md5:${md5(n)}`, `sha256:${sha256(n)}`]),
  ...TOOLS.flatMap((t) => [`md5:${md5(t.key)}`, `sha256:${sha256(t.key)}`])
]);

const keyOf = (c) => `${c.candidate_type}:${c.normalized_value}`;
function persisted(c) {
  return {
    ...c,
    evidence: buildCandidateEvidenceRecord(c),
    match_state: deriveMatchState({ assessment: c.assessment, confidence: c.confidence, matchedIocId: null, valid: c.assessment !== 'invalid' })
  };
}
function extract(pages = PAGES) {
  const { blocks } = pagesToBlocks(pages);
  const doc = createCanonicalDocument({ title: 'fixture', blocks, meta: { extractor: PDF_LAYOUT_VERSION, adapter: 'pdf' } });
  const { candidates, diagnostics } = extractCandidatesWithDiagnostics(doc);
  const rows = candidates.map(persisted);
  return { blocks, rows, diagnostics, members: rows.filter(isReportIndicatorMember) };
}

// --- layout ------------------------------------------------------------------

test('glyph height: a pdf.js height above the transform scale is capped; a smaller one is kept', () => {
  assert.equal(glyphHeight(item('x', 0, 0, 11)), 11, '11 pt text reported as 121 pt');
  assert.equal(glyphHeight({ str: 'x', transform: [12, 0, 0, 12, 0, 0], height: 9 }), 9, 'under-reported height unchanged');
  assert.equal(glyphHeight({ str: 'x', transform: [], height: 7 }), 7);
});

test('items → lines: double-scaled table rows stay one visual line each (no cell gluing)', () => {
  const lines = itemsToLines(PAGES[1].items, { pageHeight: PAGE_HEIGHT });
  const rowLines = lines.filter((l) => /gamma-scan|alpha-relay|beta-cdn|delta-host|epsilon-net|corp-relay/.test(l.text));
  assert.equal(rowLines.length, DOMAIN_ROWS.length);
  for (const l of rowLines) assert.equal(l.cells.length, 3, `row split into domain | first | last: ${l.text}`);
  const phantom = rowLines.find((l) => l.text.includes('h.gamma-scan'));
  assert.equal(phantom.cells[0].text, '2-12-44-140.h.gamma-scan[.]net');
});

test('phantom space: overlap explained by pdf.js-inserted spaces only', () => {
  assert.equal(isPhantomSpaceOverlap('2-  12', 6.3, 10.5), true);
  assert.equal(isPhantomSpaceOverlap('2- 12', 6.3, 10.5), false, 'a single space is typeset text');
  assert.equal(isPhantomSpaceOverlap('CONFIDENTIAL  DRAFT', 80, 10.5), false, 'a banner overlay overlaps far more');
  assert.equal(isPhantomSpaceOverlap('2-  12', 1.5, 10.5), false, 'ordinary kerning is not an overlap');
});

test('row gaps: bimodal gaps give a row break; uniform rows give none', () => {
  const at = (ys) => ys.map((y) => ({ line: { y } }));
  const split = rowBreakGap(at([650, 640, 630, 615.7, 589, 579, 569, 554.7, 528]));
  assert.ok(split > 15 && split < 26, `split between intra-row and row gaps (${split})`);
  assert.equal(rowBreakGap(at([500, 473.2, 446.4, 419.6, 392.8, 366])), 0);
});

test('wrapped digest inside a labelled cell re-joins; complete digests stay separate', () => {
  const d = sha256('wrap');
  assert.equal(joinWrappedCellFragments([`MD5: ${md5('wrap')}`, 'SHA-256:', d.slice(0, 63), d.slice(63)]), `MD5: ${md5('wrap')} SHA-256: ${d}`);
  const a = sha256('a');
  const b = sha256('b');
  assert.equal(joinWrappedCellFragments([`SHA-256: ${a}`, b]), `SHA-256: ${a} ${b}`);
});

test('reconstruction: every appendix page becomes a table block with one row per publisher row', () => {
  const { blocks } = extract();
  const tables = blocks.filter((b) => b.type === 'table');
  const domainRows = tables.flatMap((t) => t.table.rows).filter((r) => /\[\.\][a-z]/i.test(r[0] || ''));
  assert.equal(domainRows.length, DOMAIN_ROWS.length);
  const hashRows = tables.flatMap((t) => t.table.rows).filter((r) => r.some((c) => /MD5: [a-f0-9]{32} SHA-256: [a-f0-9]{64}$/.test(c)));
  assert.equal(hashRows.length, WEBSHELLS.length + TOOLS.length, 'each hash cell holds its MD5 and its full SHA-256');
  const gutter = tables.flatMap((t) => t.table.rows).find((r) => r.some((c) => c.includes(md5('tool-a'))));
  assert.ok(gutter.some((c) => /^toolkitScanne/.test(c)) && gutter.some((c) => /^Enumerati/.test(c)), 'name and category split at the gutter');
});

// --- semantics -----------------------------------------------------------------

test('labelled hash cells: inline type labels are labels, the Hashes column is the indicator column', () => {
  assert.equal(isInlineTypeLabelToken('MD5:'), true);
  assert.equal(isInlineTypeLabelToken('SHA-256:'), true);
  assert.equal(isInlineTypeLabelToken('Note:'), false);
  const cell = `MD5: ${md5('x')} SHA-256: ${sha256('x')}`;
  const parsed = parseIndicatorCell(cell, { type: 'hash', endpoint: false });
  assert.deepEqual(parsed.values.map((v) => v.candidate_type).sort(), ['md5', 'sha256']);
  assert.equal(parsed.rejected.length, 0);
  const interp = interpretIocTable({ id: 't', table: { headers: ['Name', 'Hashes'], rows: [['b374.php', cell], ['error.jsp', `MD5: ${md5('y')} SHA-256: ${sha256('y')}`]] } });
  assert.equal(interp.explicit, true);
  assert.ok(interp.columns.find((c) => c.header === 'Hashes').intent === 'indicator');
});

test('file-name column: a ccTLD-suffixed file name beside file names is a file, never a domain', () => {
  const rows = [['b374.php', `MD5: ${md5('1')}`], ['back.pl', `MD5: ${md5('2')}`], ['error.jsp', `MD5: ${md5('3')}`]];
  const interp = interpretIocTable({ id: 't', table: { headers: ['Name', 'Hashes'], rows } });
  const back = interp.rows.flatMap((r) => r.values).find((v) => v.refanged === 'back.pl');
  assert.equal(back.candidate_type, 'technical_artifact');
  assert.equal(back.is_ioc, false);
  // A declared Domain column, or a column that is mostly domains, is never re-read.
  const domains = interpretIocTable({ id: 'd', table: { headers: ['Domain', 'Note'], rows: [['evil.pl', 'C2'], ['run.php', 'x'], ['err.jsp', 'y']] } });
  assert.equal(domains.rows.flatMap((r) => r.values).find((v) => v.refanged === 'evil.pl').candidate_type, 'domain');
  const mostly = interpretIocTable({ id: 'm', table: { headers: null, rows: [['evil.pl', md5('a')], ['bad.ru', md5('b')], ['run.php', md5('c')]] } });
  assert.equal(mostly.rows.flatMap((r) => r.values).find((v) => v.refanged === 'evil.pl').candidate_type, 'domain');
});

test('RFC 8552 underscored DNS labels are not code identifiers under a delegated suffix', () => {
  assert.equal(hasCodeIdentifierShape('_msdcs.corp-relay.com', { suffixStrength: 'strong' }), false);
  assert.equal(hasCodeIdentifierShape('pdc._msdcs.corp-relay.com', { suffixStrength: 'strong' }), false);
  assert.equal(hasCodeIdentifierShape('my_var.config.load', { suffixStrength: 'weak' }), true);
  assert.equal(hasCodeIdentifierShape('_private.Module', { suffixStrength: 'weak' }), true);
  assert.equal(hasCodeIdentifierShape('snake_case.example.com', { suffixStrength: 'strong' }), true);
});

// --- end to end ------------------------------------------------------------------

test('MODE A: report Indicators equal the publisher appendix identities exactly', () => {
  const { rows, members } = extract();
  assert.ok(rows.some((c) => c.evidence.document_has_authoritative_scope === true), 'curated appendix detected (MODE A)');
  const got = new Set(members.map(keyOf));
  assert.deepEqual([...PUBLISHER].filter((k) => !got.has(k)), [], 'missing publisher identities');
  assert.deepEqual([...got].filter((k) => !PUBLISHER.has(k)), [], 'non-publisher Indicators');
  for (const c of members) assert.equal(c.source_assertion, 'explicit_ioc', `${keyOf(c)} asserted by the appendix`);
});

test('false-positive patterns from glued cells no longer exist anywhere in the candidate set', () => {
  const { rows } = extract();
  const md5s = new Set([...PUBLISHER].filter((k) => k.startsWith('md5:')).map((k) => k.slice(4)));
  for (const c of rows) {
    if (c.candidate_type === 'domain') {
      const hits = [...PUBLISHER].filter((k) => k.startsWith('domain:') && c.normalized_value.includes(k.slice(7)) && c.normalized_value !== k.slice(7));
      assert.deepEqual(hits, [], `${c.normalized_value} glues publisher cells`);
      assert.doesNotMatch(c.normalized_value, /^\d{1,3}-\d{1,3}\.h\./, 'no truncated hostname fragment');
    }
    if (c.candidate_type === 'sha256') {
      assert.equal(md5s.has(c.normalized_value.slice(0, 32)) && md5s.has(c.normalized_value.slice(32)), false, 'no fake SHA-256 from two MD5 cells');
    }
  }
  const back = rows.find((c) => c.normalized_value === 'back.pl');
  assert.equal(back.candidate_type, 'technical_artifact');
  assert.equal(isReportIndicatorMember(back), false);
  const version = rows.find((c) => c.candidate_type === 'ip' && c.normalized_value === '2.3.20.2');
  assert.ok(!version || !isReportIndicatorMember(version), 'version string is never an Indicator');
});

test('MODE A: a narrative-only malicious value stays out; narrative + appendix is one asserted Indicator', () => {
  const { rows, members } = extract();
  const narrative = rows.find((c) => c.normalized_value === NARRATIVE_ONLY.replace('[.]', '.'));
  assert.ok(narrative, 'narrative value still extracted for context / AI');
  assert.equal(isReportIndicatorMember(narrative), false);
  const shared = rows.filter((c) => c.normalized_value === SHARED.replace('[.]', '.'));
  assert.equal(shared.length, 1, 'one canonical candidate');
  assert.ok(members.includes(shared[0]));
  assert.equal(shared[0].source_assertion, 'explicit_ioc');
  const pages = new Set(shared[0].evidence.occurrences.map((o) => o.page));
  assert.ok(pages.has(1) && pages.has(2), 'narrative and appendix occurrences kept');
});

test('MODE B unchanged: without the appendix the narrative value is a reviewable Indicator', () => {
  const { rows, members } = extract([PAGES[0]]);
  assert.equal(rows.some((c) => c.evidence.document_has_authoritative_scope === true), false);
  assert.ok(members.some((c) => c.normalized_value === NARRATIVE_ONLY.replace('[.]', '.')));
});

test('re-extraction is deterministic (same identities, assertions and memberships)', () => {
  const sig = () => extract().rows.map((c) => `${keyOf(c)}|${c.source_assertion}|${c.assessment}|${isReportIndicatorMember(c)}`).sort();
  assert.deepEqual(sig(), sig());
});
