/**
 * pdf_v8: observables wrapped inside narrow PDF table cells (ESET white papers
 * 34383 Gamaredon, 34385 GopherWhisper).
 *
 * Root causes in pdf_v7:
 * 1. A single token cut mid-label by the cell edge ("wwpeeya.ignores.wor" +
 *    "kers[.]dev") re-joined with a space, because only separator-ended heads
 *    joined; extraction then read fragments ("kers.dev", "ole.site").
 * 2. The first line of a value wrapped over two or three lines (a SHA-1 as
 *    "C72E…" / "737B…" / "D7", a domain as "cheese-metals-" / … ) is a short
 *    single-cell line in the observable font, so it passed the structural
 *    heading test and ended the table region. The rows fell out of the table and
 *    out of the IOC section (headings "C72E7540D6F12D74D8E", "6F", "18" …).
 * 3. Odd-page running titles whose kern space pdf.js squeezes out
 *    ("21GopherWhisper: …") were not recognised as the same chrome as
 *    "22 GopherWhisper: …"; once the IOC section was restored, such a line
 *    became a section heading that re-opened it inside the ATT&CK tables.
 *
 * Fixtures are byte-accurate PDFs read by the production pdf.js path.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { pdfToCanonicalDocument } from './pdfIngest.js';
import { PDF_LAYOUT_VERSION, joinWrappedCellFragments } from './pdfLayout.js';
import { extractCandidatesFromDocument } from './candidateExtraction.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import {
  THREAT_LIBRARY_DOCUMENT_ZONES_VERSION,
  detectRepeatedHeaderFooterBlockIds,
  normalizeForRepetition
} from './documentZones.js';
import { parseIocSourceContent } from './iocSources/parseContent.js';

const FONTS = { F1: 'Helvetica', F2: 'Courier', F3: 'Helvetica-Bold' };

/**
 * Byte-accurate PDF 1.4: one entry per page, each a list of
 * [text, x, y, size, font] with font F1 Helvetica / F2 Courier / F3 Helvetica-Bold.
 */
function pdfPages(pages) {
  const fontIds = Object.keys(FONTS);
  const pageObj = (i) => 3 + i * 2;
  const fontObj = (k) => 3 + pages.length * 2 + k;
  const objs = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
    `2 0 obj\n<< /Type /Pages /Kids [${pages.map((_, i) => `${pageObj(i)} 0 R`).join(' ')}] /Count ${pages.length} >>\nendobj\n`
  ];
  const fontRes = fontIds.map((id, k) => `/${id} ${fontObj(k)} 0 R`).join(' ');
  pages.forEach((lines, i) => {
    const content = lines
      .map(([text, x, y, size, font = 'F1']) => `BT /${font} ${size} Tf ${x} ${y} Td (${String(text).replace(/[()\\]/g, ' ')}) Tj ET`)
      .join('\n') + '\n';
    objs.push(`${pageObj(i)} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents ${pageObj(i) + 1} 0 R /Resources << /Font << ${fontRes} >> >> >>\nendobj\n`);
    objs.push(`${pageObj(i) + 1} 0 obj\n<< /Length ${Buffer.byteLength(content, 'latin1')} >>\nstream\n${content}endstream\nendobj\n`);
  });
  fontIds.forEach((id, k) => objs.push(`${fontObj(k)} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /${FONTS[id]} >>\nendobj\n`));
  let body = '%PDF-1.4\n%\xE2\xE3\xCF\xD3\n';
  const offsets = [0];
  for (const obj of objs) {
    offsets.push(Buffer.byteLength(body, 'latin1'));
    body += obj;
  }
  const xrefStart = Buffer.byteLength(body, 'latin1');
  let xref = `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objs.length; i += 1) xref += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  body += `${xref}trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
  return Buffer.from(body, 'latin1');
}

const sha1 = (s) => crypto.createHash('sha1').update(`pdf-wrapped-cells:${s}`).digest('hex').toUpperCase();
export const HASHES = ['temp001.exe', 'delltool.exe', 'whisper.dll'].map((file) => ({ file, hash: sha1(file) }));
export const HEX_LABEL = crypto.createHash('md5').update('pdf-wrapped-cells:tunnel').digest('hex');

const PROSE = [
  'Our investigation revealed an actor targeting a governmental entity with a varied toolset of loaders,',
  'injectors, and backdoors. The first part of the toolset consisted of several new tools that were used',
  'together with a custom backdoor. Later we also uncovered a new injector capable of persisting through',
  'a Windows service and a backdoor executed by that injector. By analyzing the command and control',
  'communications obtained from attacker operated channels, we were able to gain more information about',
  'the alignment, inner workings, and post-compromise activities of the group described in this paper.',
  'The tables below list the files and the network infrastructure that we attribute to this activity.',
  'Hashes are given as SHA-1 values; domains are defanged to avoid accidental resolution by readers.'
];

const L = 11.5; // wrapped-line pitch inside a cell
const R = 26; // row break

/** Hash table rows: each SHA-1 wraps over three lines (19 + 19 + 2 characters). */
function hashRows(y0) {
  const out = [];
  let y = y0;
  for (const [i, { file, hash }] of HASHES.entries()) {
    out.push([hash.slice(0, 19), 64, y, 9, 'F2']);
    out.push([hash.slice(19, 38), 64, y - L, 9, 'F2']);
    out.push([file, 185, y - L, 9, 'F2']);
    out.push([`Win64/Agent.A${i}`, 290, y - L, 9]);
    out.push(['Backdoor component.', 400, y - L, 9]);
    out.push([hash.slice(38), 64, y - 2 * L, 9, 'F2']);
    y -= 2 * L + R;
  }
  return { lines: out, y };
}

/** Network rows: [head line?, main domain fragment, tail fragment?]. */
const NETWORK = [
  // cut mid-label at the cell edge (head fills the 19-glyph column)
  { main: 'qzx7.tunnel-pad.wor', tail: 'kers[.]dev' },
  // head ends in a delegated TLD (".work"), only the geometry tells it was cut
  { main: 'vk3.p4ad3742dd.work', tail: 'ers[.]dev' },
  // three lines, broken at hyphen / dot separators
  { head: 'cheese-metals-', main: 'gourmet-talks.', tail: 'trycloudflare[.]com' },
  // soft break inside a label that is no DNS suffix ("try")
  { main: 'asin-winston.try', tail: 'cloudflare[.]com' },
  // a hex label over two lines, then the rest of the name
  { head: HEX_LABEL.slice(0, 19), main: `${HEX_LABEL.slice(19)}.looph`, tail: 'ole[.]site' },
  // two complete domains in one cell, neither filling it: stay two values
  { main: 'alpha-node[.]ru', tail: 'beta-node[.]net' }
];

function networkRows(y0) {
  const out = [];
  let y = y0;
  for (const row of NETWORK) {
    if (row.head) {
      out.push([row.head, 163, y, 9, 'F2']);
      y -= L;
    }
    out.push(['N/A', 64, y, 9]);
    out.push([row.main, 163, y, 9, 'F2']);
    out.push(['N/A', 290, y, 9]);
    out.push(['2025-12-30', 370, y, 9]);
    out.push(['Example C&C server.', 440, y, 9]);
    if (row.tail) out.push([row.tail, 163, y - L, 9, 'F2']);
    y -= (row.tail ? L : 0) + R;
  }
  out.push(['46.151.29[.]58', 64, y, 9]);
  out.push(['N/A', 163, y, 9]);
  out.push(['Example Hosting', 290, y, 9]);
  out.push(['2025-03-24', 370, y, 9]);
  out.push(['Example C&C server.', 440, y, 9]);
  return { lines: out, y: y - R };
}

export function whitePaper() {
  const p1 = PROSE.map((t, i) => [t, 58, 740 - i * 12.4, 9]);
  p1.push(['IOCs', 58, 620, 14, 'F3'], ['Files', 58, 596, 12, 'F3']);
  p1.push(['SHA-1', 64, 572, 9], ['Filename', 185, 572, 9], ['Detection', 290, 572, 9], ['Description', 400, 572, 9]);
  const hashes = hashRows(572 - R);
  p1.push(...hashes.lines);
  const p2 = [['Network', 58, 740, 12, 'F3']];
  p2.push(['IP', 64, 716, 9], ['Domain', 163, 716, 9], ['Hosting', 290, 716, 9], ['First seen', 370, 716, 9], ['Details', 440, 716, 9]);
  p2.push(['provider', 290, 716 - L, 9]);
  const net = networkRows(716 - L - R);
  p2.push(...net.lines);
  p2.push(['MITRE ATT&CK techniques', 58, net.y - 10, 14, 'F3']);
  p2.push(['The operators exfiltrate archives through file.io and host relays on workers.dev subdomains.', 58, net.y - 34, 9]);
  return pdfPages([p1, p2]);
}

const EXPECTED_MEMBERS = [
  ...HASHES.map((h) => `sha1:${h.hash.toLowerCase()}`),
  'domain:qzx7.tunnel-pad.workers.dev',
  'domain:vk3.p4ad3742dd.workers.dev',
  'domain:cheese-metals-gourmet-talks.trycloudflare.com',
  'domain:asin-winston.trycloudflare.com',
  `domain:${HEX_LABEL}.loophole.site`,
  'domain:alpha-node.ru',
  'domain:beta-node.net',
  'ip:46.151.29.58'
].sort();

const key = (c) => `${c.candidate_type}:${c.normalized_value}`;
const member = (c) => isReportIndicatorMember({ ...c, evidence: buildCandidateEvidenceRecord(c) });

let cached = null;
async function paper() {
  if (!cached) cached = (await pdfToCanonicalDocument(whitePaper(), { fileName: 'wrapped-cells.pdf' })).document;
  return cached;
}

test('contract versions: pdf_v8 layout, tl-zones-v19', () => {
  assert.equal(PDF_LAYOUT_VERSION, 'threat_library_pdf_v8');
  assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v19');
});

test('wrapped SHA-1 cells: three-line hashes stay one table row each, no hex headings', async () => {
  const doc = await paper();
  const hexHeadings = doc.blocks.filter((b) => b.type === 'heading' && /^[0-9a-f]+$/i.test(b.text));
  assert.deepEqual(hexHeadings.map((b) => b.text), []);
  const table = doc.blocks.find((b) => b.type === 'table' && b.table.rows.some((r) => r.includes('temp001.exe')));
  assert.ok(table, JSON.stringify(doc.blocks.map((b) => [b.type, b.text])));
  const rows = table.table.rows.filter((r) => /exe|dll/.test(r.join(' ')));
  assert.deepEqual(rows.map((r) => [r[0], r[1]]), HASHES.map((h) => [h.hash, h.file]));
});

test('wrapped domain cells: cut labels re-join without a space, separate values keep it', async () => {
  const doc = await paper();
  const table = doc.blocks.find((b) => b.type === 'table' && b.table.rows.some((r) => r.join(' ').includes('Example C&C')));
  assert.ok(table);
  const cells = table.table.rows.map((r) => r[1]);
  assert.ok(cells.includes('qzx7.tunnel-pad.workers[.]dev'), JSON.stringify(cells));
  assert.ok(cells.includes('vk3.p4ad3742dd.workers[.]dev'), JSON.stringify(cells));
  assert.ok(cells.includes('cheese-metals-gourmet-talks.trycloudflare[.]com'), JSON.stringify(cells));
  assert.ok(cells.includes('asin-winston.trycloudflare[.]com'), JSON.stringify(cells));
  assert.ok(cells.includes(`${HEX_LABEL}.loophole[.]site`), JSON.stringify(cells));
  // Negative: two complete values in one cell, neither cut by the edge.
  assert.ok(cells.includes('alpha-node[.]ru beta-node[.]net'), JSON.stringify(cells));
  // Negative: a header word wrapped in its cell keeps its space.
  const header = table.table.headers || table.table.rows[0];
  assert.ok(header.includes('Hosting provider'), JSON.stringify(header));
});

test('Indicator membership: exactly the wrapped table values; no fragments, prose mentions stay out', async () => {
  const doc = await paper();
  const cands = extractCandidatesFromDocument(doc);
  const members = cands.filter(member).map(key).sort();
  assert.deepEqual(members, EXPECTED_MEMBERS);
  const all = new Set(cands.map(key));
  for (const frag of ['domain:kers.dev', 'domain:ers.dev', 'domain:ole.site', 'domain:cloudflare.com', 'domain:tunnel-pad.wor']) {
    assert.equal(all.has(frag), false, frag);
  }
  // file.io / workers.dev after the IOC section are mentions, not Indicators.
  for (const v of ['domain:file.io', 'domain:workers.dev']) assert.equal(members.includes(v), false, v);
});

test('linked PDF source: the white paper yields the reconstructed values only', async () => {
  const buffer = whitePaper();
  const parsed = await parseIocSourceContent({
    body: buffer.toString('utf8'),
    buffer,
    contentType: 'application/pdf',
    url: 'https://vendor-research.example/papers/wrapped-cells.pdf',
    path: null,
    sourcePublicId: 'src_pdf_wrap',
    pdfToDocument: pdfToCanonicalDocument,
    reportScope: {}
  });
  assert.equal(parsed.ok, true, JSON.stringify(parsed));
  assert.deepEqual(parsed.candidates.map(key).sort(), EXPECTED_MEMBERS);
});

test('joinWrappedCellFragments: cut-host rule needs a visible cut and a delegated suffix', () => {
  // Geometry: the head filled the cell.
  assert.equal(joinWrappedCellFragments([{ text: 'srkwk.3742eddi.work', fillsCell: true }, { text: 'ers[.]dev' }]), 'srkwk.3742eddi.workers[.]dev');
  // Lexical: the head's last label is no DNS suffix.
  assert.equal(joinWrappedCellFragments(['wwpeeya.ignores.wor', 'kers[.]dev']), 'wwpeeya.ignores.workers[.]dev');
  assert.equal(joinWrappedCellFragments(['parameter-iron-turn', 's-combinations.', 'trycloudflare[.]com'].map((text, i) => ({ text, fillsCell: i === 0 }))), 'parameter-iron-turns-combinations.trycloudflare[.]com');
  // No cut evidence: the head is a complete name and did not fill the cell.
  assert.equal(joinWrappedCellFragments(['srkwk.3742eddi.work', 'ers[.]dev']), 'srkwk.3742eddi.work ers[.]dev');
  assert.equal(joinWrappedCellFragments(['evil[.]com', 'bad[.]net']), 'evil[.]com bad[.]net');
  // Words and filenames never become hostnames.
  assert.equal(joinWrappedCellFragments([{ text: 'Hosting', fillsCell: true }, { text: 'provider' }]), 'Hosting provider');
  assert.equal(joinWrappedCellFragments([{ text: 'Enumerati', fillsCell: true }, { text: 'on' }]), 'Enumerati on');
  assert.equal(joinWrappedCellFragments([{ text: 'intelservice.ex', fillsCell: true }, { text: 'e' }]), 'intelservice.ex e');
  assert.equal(joinWrappedCellFragments([{ text: 'Win32/PSWTool.WebB', fillsCell: true }, { text: 'rowserPassView.I' }]), 'Win32/PSWTool.WebB rowserPassView.I');
  // Multi-word cells keep prose spacing.
  assert.equal(joinWrappedCellFragments([{ text: 'Gamaredon C&C', fillsCell: true }, { text: 'server.' }]), 'Gamaredon C&C server.');
  // Existing rules unchanged.
  assert.equal(joinWrappedCellFragments(['C72E7540D6F12D74D8E', '737B02F31568385F575', 'D7']), 'C72E7540D6F12D74D8E737B02F31568385F575D7');
  assert.equal(joinWrappedCellFragments(['jvyuwatt.ssuworker.', 'workers[.]dev']), 'jvyuwatt.ssuworker.workers[.]dev');
});

test('running title with a glued page number is the same chrome as the spaced one', () => {
  assert.equal(normalizeForRepetition('21GopherWhisper: A burrow full of malware'), normalizeForRepetition('22 GopherWhisper: A burrow full of malware'));
  // Short alphanumeric starts are not page numbers.
  assert.notEqual(normalizeForRepetition('3rd party loader component'), normalizeForRepetition('party loader component'));
  const blocks = [];
  for (let p = 1; p <= 8; p += 1) {
    blocks.push({ id: `p${p}-t`, page: p, type: 'paragraph', text: p % 2 ? `${p}Example Research: A paper title` : `${p} Example Research: A paper title` });
    blocks.push({ id: `p${p}-b`, page: p, type: 'paragraph', text: `Body text of page ${p} with distinct content number ${p * 7}.` });
  }
  const flagged = detectRepeatedHeaderFooterBlockIds(blocks);
  for (let p = 1; p <= 8; p += 1) {
    assert.equal(flagged.has(`p${p}-t`), true, `page ${p} title`);
    assert.equal(flagged.has(`p${p}-b`), false, `page ${p} body`);
  }
});
