/**
 * PDF structural reliability (P1.1 — tl-zones-v12 / tl-candidates-v28 /
 * threat_library_pdf_v6): metamorphic regressions.
 *
 * One synthetic publisher IOC set is rendered in structurally equivalent PDF
 * shapes — heading-level estimates, split headings, rows vs tables vs merged
 * inventories, multi-pair lines, repeated page chrome, column order — and the
 * report Indicator identity set must be identical in every shape. Contrasting
 * cases pin where the structure is genuinely ambiguous and the conservative
 * reading is kept. Exact identity sets, never counts. Synthetic values only.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { extractReportCandidates } from './extractionStages.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { isReportIndicatorMember } from './indicatorMembership.js';
import { inventoryPairLines, pagesToBlocks, isFilenameHashRowLine, PDF_LAYOUT_VERSION } from './pdfLayout.js';
import { recoverInventoryRowBlock, THREAT_LIBRARY_DOCUMENT_ZONES_VERSION } from './documentZones.js';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';

const md5 = (s) => crypto.createHash('md5').update(`p11:${s}`).digest('hex');
const sha1 = (s) => crypto.createHash('sha1').update(`p11:${s}`).digest('hex');
const sha256 = (s) => crypto.createHash('sha256').update(`p11:${s}`).digest('hex');

const NETWORK = [
  { source: 'update-relay[.]net', id: 'domain:update-relay.net' },
  { source: '203.0.113.77', id: 'ip:203.0.113.77' }
];
const SAMPLES = ['vulkan-1.dll', 'oleasapi.dll', 'msbasesysdc.dll', 'loader.exe'].map((file) => ({ file, hash: md5(file) }));
const EXPECTED = [...NETWORK.map((n) => n.id), ...SAMPLES.map((s) => `md5:${s.hash}`)].sort();
const NETWORK_ONLY = NETWORK.map((n) => n.id).sort();

const identity = (c) => `${c.candidate_type}:${c.normalized_value}`;

function members(document) {
  const { candidates } = extractReportCandidates({ source_type: 'pdf', source_url: null }, document);
  return candidates
    .filter((c) => isReportIndicatorMember({ ...c, evidence: buildCandidateEvidenceRecord(c) }))
    .map(identity)
    .sort();
}

function htmlMembers(html) {
  const url = 'https://research.example/blog/p11/';
  const r = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.ok(r.ok);
  const { candidates } = extractReportCandidates({ source_type: 'url', source_url: url }, r.document);
  return candidates
    .filter((c) => isReportIndicatorMember({ ...c, evidence: buildCandidateEvidenceRecord(c) }))
    .map(identity)
    .sort();
}

/** Canonical PDF block builder (pdf_v6 block shapes). */
function builder() {
  let n = 0;
  const id = () => `p1-b${String(++n).padStart(2, '0')}`;
  return {
    heading: (text, level, page = 1) => ({ id: id(), type: 'heading', text, page, section: text, ...(level === undefined ? {} : { level }) }),
    paragraph: (text, page = 1) => ({ id: id(), type: 'paragraph', text, page, section: null }),
    row: (text, page = 1) => ({ id: id(), type: 'list_item', text, page, section: null, layout: 'observable_row' }),
    edge: (text, page) => ({ id: id(), type: 'paragraph', text, page, section: null, layout: 'page_edge' }),
    table: (headers, rows, page = 1) => createTableBlock({ id: id(), page, headers, rows, source: 'pdf_geometry' })
  };
}

const INTRO = 'The intrusion set deploys a modular loader chain against several regional targets across multiple waves.';
const OUTRO = 'The actor continues to evolve its toolset and infrastructure.';

function pdfDoc(blocks) {
  return createCanonicalDocument({ title: 'P1.1 variant', language: 'en', blocks, meta: { extractor: PDF_LAYOUT_VERSION, adapter: 'pdf' } });
}

/**
 * IOC appendix with an optional network sub-heading and sample sub-heading.
 * @param {{ appendix?: number, sub?: number, net?: string|null, samples?: string|null, repr: string }} o
 */
function appendixVariant(o) {
  const B = builder();
  const blocks = [B.paragraph(INTRO), B.heading('Indicators of compromise', o.appendix)];
  if (o.net) blocks.push(B.heading(o.net, o.sub));
  for (const v of NETWORK) blocks.push(B.row(v.source));
  if (o.samples) blocks.push(B.heading(o.samples, o.sub));
  const pairs = SAMPLES.map((s) => `${s.file} ${s.hash}`);
  if (o.repr === 'table') blocks.push(B.table(['Filename', 'MD5'], SAMPLES.map((s) => [s.file, s.hash])));
  else if (o.repr === 'table_hash_first') blocks.push(B.table(['MD5', 'Filename'], SAMPLES.map((s) => [s.hash, s.file])));
  else if (o.repr === 'hash_lines') for (const s of SAMPLES) blocks.push(B.row(s.hash));
  else if (o.repr === 'filename_hash_lines') for (const p of pairs) blocks.push(B.row(p));
  else if (o.repr === 'merged_paragraph') blocks.push(B.paragraph(pairs.join(' ')));
  else if (o.repr === 'two_pairs_per_row') for (let i = 0; i < pairs.length; i += 2) blocks.push(B.row(pairs.slice(i, i + 2).join(' ')));
  else throw new Error(o.repr);
  blocks.push(B.heading('Conclusion', o.appendix), B.paragraph(OUTRO));
  return pdfDoc(blocks);
}

test('contract versions', () => {
  assert.equal(PDF_LAYOUT_VERSION, 'threat_library_pdf_v6');
  assert.equal(THREAT_LIBRARY_DOCUMENT_ZONES_VERSION, 'tl-zones-v12');
});

// --- inventory reconstruction primitives ------------------------------------

test('inventoryPairLines: pure filename/hash inventories in either consistent order', () => {
  const [a, b, c] = SAMPLES;
  assert.deepEqual(inventoryPairLines(`${a.file} ${a.hash} ${b.file} ${b.hash}`), [`${a.file} ${a.hash}`, `${b.file} ${b.hash}`]);
  assert.deepEqual(inventoryPairLines(`${a.hash} ${a.file} ${b.hash} ${b.file} ${c.hash} ${c.file}`), [
    `${a.hash} ${a.file}`,
    `${b.hash} ${b.file}`,
    `${c.hash} ${c.file}`
  ]);
  // MD5, SHA-1 and SHA-256 mixed in one inventory.
  assert.deepEqual(inventoryPairLines(`a.exe ${md5('x')} b.dll ${sha1('x')} c.ps1 ${sha256('x')}`)?.length, 3);
});

test('inventoryPairLines: anything ambiguous stays narrative (null)', () => {
  const [a, b] = SAMPLES;
  const cases = {
    single_pair: `${a.file} ${a.hash}`,
    prose_word: `${a.file} ${a.hash} and ${b.file} ${b.hash}`,
    mixed_order: `${a.file} ${a.hash} ${b.hash} ${b.file}`,
    odd_tokens: `${a.file} ${a.hash} ${b.file}`,
    hashes_only: `${a.hash} ${b.hash}`,
    dns_suffix_not_a_file: `update.com ${a.hash} relay.net ${b.hash}`,
    url_token: `hxxp://x[.]example/a.exe ${a.hash} ${b.file} ${b.hash}`,
    short_hex: `${a.file} ${a.hash.slice(0, 30)} ${b.file} ${b.hash}`
  };
  for (const [name, text] of Object.entries(cases)) assert.equal(inventoryPairLines(text), null, name);
});

test('recoverInventoryRowBlock: re-types a pure inventory in place (id, page, length preserved)', () => {
  const text = SAMPLES.map((s) => `${s.file} ${s.hash}`).join(' ');
  const out = recoverInventoryRowBlock({ id: 'p3-b07', type: 'paragraph', text, page: 3, section: null });
  assert.equal(out.id, 'p3-b07');
  assert.equal(out.page, 3);
  assert.equal(out.type, 'list_item');
  assert.equal(out.layout, 'observable_row');
  assert.equal(out.layout_recovered, 'inventory_paragraph');
  assert.equal(out.text.length, text.length, 'separators swapped 1:1, offsets unchanged');
  assert.deepEqual(out.text.split('\n'), SAMPLES.map((s) => `${s.file} ${s.hash}`));
  // Untouched: narrative, headings, tables, page chrome, already line-structured text.
  for (const b of [
    { id: 'x1', type: 'paragraph', text: `The dropper ${SAMPLES[0].file} (${SAMPLES[0].hash}) loads ${SAMPLES[1].file}.` },
    { id: 'x2', type: 'heading', text, level: 2 },
    { id: 'x3', type: 'paragraph', text, layout: 'page_edge' },
    { id: 'x4', type: 'list_item', text: `${SAMPLES[0].file} ${SAMPLES[0].hash}\n${SAMPLES[1].file} ${SAMPLES[1].hash}`, layout: 'observable_row' }
  ]) assert.deepEqual(recoverInventoryRowBlock({ ...b }), b, b.id);
});

test('isFilenameHashRowLine accepts dense multi-pair lines (pdf_v6) but not prose', () => {
  const line = SAMPLES.map((s) => `${s.file} ${s.hash}`).join(' ');
  assert.equal(isFilenameHashRowLine(line), true);
  assert.equal(isFilenameHashRowLine(`We observed ${SAMPLES[0].file} with hash ${SAMPLES[0].hash} being written to the temp folder by the installer.`), false);
});

// --- metamorphic heading-level × representation grid ------------------------

const STRUCTURES = {
  flat: { net: null, samples: null },
  typed: { net: 'Network', samples: 'Samples' },
  c2_loaders: { net: 'C2 servers', samples: 'Loaders' },
  typed_file_hashes: { net: 'Network', samples: 'File hashes' }
};
// [appendix level, sub-heading level]: nested estimate, equal estimate (bold-only
// headings), level-less (pre-v5 residual), mixed.
const LEVELS = { nested: [2, 3], equal: [3, 3], unknown: [undefined, undefined], mixed: [2, undefined] };
const REPRS = ['table', 'table_hash_first', 'hash_lines', 'filename_hash_lines', 'merged_paragraph', 'two_pairs_per_row'];

for (const [sid, s] of Object.entries(STRUCTURES)) {
  for (const [lid, [appendix, sub]] of Object.entries(LEVELS)) {
    test(`PDF ${sid} × levels ${lid}: every representation yields the exact publisher Indicator set`, () => {
      for (const repr of REPRS) {
        assert.deepEqual(members(appendixVariant({ ...s, appendix, sub, repr })), EXPECTED, `${sid}/${lid}/${repr}`);
      }
    });
  }
}

test('ambiguity pin: unknown or equal hierarchy + a sub-label naming no indicator group after a C2 child closes scope', () => {
  // "Plugins" after "C2 servers": with estimated-equal or missing levels the
  // blocks cannot say whether Plugins is a sibling topic or an appendix child.
  // Conservative reading kept: the network values stay, the table is not
  // promoted. With a real nesting estimate the appendix scope holds.
  for (const [appendix, sub] of [[3, 3], [undefined, undefined]]) {
    assert.deepEqual(
      members(appendixVariant({ net: 'C2 servers', samples: 'Plugins', appendix, sub, repr: 'table' })),
      NETWORK_ONLY,
      `levels ${appendix}/${sub}`
    );
  }
  assert.deepEqual(members(appendixVariant({ net: 'C2 servers', samples: 'Plugins', appendix: 2, sub: 3, repr: 'table' })), EXPECTED);
});

test('real HTML same-level sibling ("Related infrastructure") over a Filename|MD5 table does not inherit appendix scope', () => {
  const rows = SAMPLES.map((s) => `<tr><td>${s.file}</td><td>${s.hash}</td></tr>`).join('');
  const table = `<table><thead><tr><th>Filename</th><th>MD5</th></tr></thead><tbody>${rows}</tbody></table>`;
  const page = (inner) => `<!doctype html><html><head><title>t</title></head><body><article><h1>Report</h1><p>${INTRO}</p>${inner}<h2>Conclusion</h2><p>${OUTRO}</p></article></body></html>`;
  const net = `<ul>${NETWORK.map((n) => `<li>${n.source}</li>`).join('')}</ul>`;
  assert.deepEqual(htmlMembers(page(`<h2>Indicators of compromise</h2>${net}<h2>Related infrastructure</h2>${table}`)), NETWORK_ONLY);
  assert.deepEqual(htmlMembers(page(`<h2>Indicators of compromise</h2>${net}<h3>Related samples</h3>${table}`)), EXPECTED);
});

// --- other structural shapes ------------------------------------------------

test('heading text split across two heading blocks still opens the appendix', () => {
  for (const level of [2, undefined]) {
    const B = builder();
    const doc = pdfDoc([
      B.paragraph(INTRO),
      B.heading('Indicators of', level),
      B.heading('compromise', level),
      ...NETWORK.map((n) => B.row(n.source)),
      B.table(['Filename', 'MD5'], SAMPLES.map((s) => [s.file, s.hash])),
      B.heading('Conclusion', level),
      B.paragraph(OUTRO)
    ]);
    assert.deepEqual(members(doc), EXPECTED, `level ${level}`);
  }
});

test('IOC table continued across pages with repeated header row and running header/footer chrome', () => {
  const B = builder();
  const doc = pdfDoc([
    B.paragraph(INTRO),
    B.heading('Indicators of compromise', 2),
    ...NETWORK.map((n) => B.row(n.source)),
    B.heading('Samples', 3),
    B.table(['Filename', 'MD5'], SAMPLES.slice(0, 2).map((s) => [s.file, s.hash]), 1),
    B.edge('ACME Threat Research | TLP:CLEAR | Page 1', 1),
    B.edge('ACME Threat Research | TLP:CLEAR | Page 2', 2),
    B.table(['Filename', 'MD5'], SAMPLES.slice(2).map((s) => [s.file, s.hash]), 2),
    B.heading('Conclusion', 2, 2),
    B.paragraph(OUTRO, 2)
  ]);
  assert.deepEqual(members(doc), EXPECTED);
});

test('hashes in adjacent cells: Filename | MD5 | SHA1 | SHA256 inventory keeps every digest, never the filename', () => {
  const B = builder();
  const rows = SAMPLES.map((s) => [s.file, s.hash, sha1(s.file), sha256(s.file)]);
  const doc = pdfDoc([
    B.paragraph(INTRO),
    B.heading('Indicators of compromise', 2),
    B.table(['Filename', 'MD5', 'SHA1', 'SHA256'], rows),
    B.heading('Conclusion', 2),
    B.paragraph(OUTRO)
  ]);
  const expected = SAMPLES.flatMap((s) => [`md5:${s.hash}`, `sha1:${sha1(s.file)}`, `sha256:${sha256(s.file)}`]).sort();
  assert.deepEqual(members(doc), expected);
});

test('mixed MD5 / SHA-1 / SHA-256 inventory merged into one paragraph is recovered per pair', () => {
  const B = builder();
  const inv = [
    ['a-loader.exe', md5('a')],
    ['b-stage.dll', sha1('b')],
    ['c-plugin.ps1', sha256('c')]
  ];
  const doc = pdfDoc([
    B.paragraph(INTRO),
    B.heading('Indicators of compromise', 2),
    B.paragraph(inv.map(([f, h]) => `${f} ${h}`).join(' ')),
    B.heading('Conclusion', 2),
    B.paragraph(OUTRO)
  ]);
  assert.deepEqual(members(doc), [`md5:${md5('a')}`, `sha1:${sha1('b')}`, `sha256:${sha256('c')}`].sort());
});

test('appendix boundary: a pure inventory after the appendix closes is not promoted (MODE A authority)', () => {
  const B = builder();
  const outside = [md5('outside-1'), md5('outside-2'), md5('outside-3')];
  const doc = pdfDoc([
    B.paragraph(INTRO),
    B.heading('Indicators of compromise', 2),
    ...NETWORK.map((n) => B.row(n.source)),
    ...SAMPLES.map((s) => B.row(`${s.file} ${s.hash}`)),
    B.heading('Legitimate components abused', 2),
    B.paragraph(`MsMpEng.exe ${outside[0]} vmtoolsd.exe ${outside[1]} rundll32.exe ${outside[2]}`),
    B.heading('Conclusion', 2),
    B.paragraph(OUTRO)
  ]);
  assert.deepEqual(members(doc), EXPECTED);
});

test('incomplete URL prefix and contextual provider domains are not Indicators', () => {
  const B = builder();
  const doc = pdfDoc([
    B.paragraph('The implant exfiltrates archives through api.telegram.org and stages files on backblazeb2.com before beaconing.'),
    B.heading('Indicators of compromise', 2),
    B.row('hxxps://update-relay[.]net/gate/panel.php'),
    B.row('hxxps://update-relay[.]net/gate/'),
    B.row('203.0.113.77'),
    ...SAMPLES.map((s) => B.row(`${s.file} ${s.hash}`)),
    B.heading('Conclusion', 2),
    B.paragraph(OUTRO)
  ]);
  const got = members(doc);
  assert.ok(got.includes('url:https://update-relay.net/gate/panel.php'), JSON.stringify(got));
  assert.ok(!got.includes('url:https://update-relay.net/gate/'), 'strict prefix of a sibling URL Indicator');
  assert.ok(!got.includes('domain:api.telegram.org'));
  assert.ok(!got.includes('domain:backblazeb2.com'));
  for (const s of SAMPLES) assert.ok(got.includes(`md5:${s.hash}`), s.file);
});

// --- geometry path (pdf.js items → blocks) ----------------------------------

const PAGE_HEIGHT = 792;
function item(str, x, y, size = 10, font = 'body') {
  return { str, transform: [size, 0, 0, size, x, y], width: str.length * size * 0.5, height: size, fontName: font };
}
/**
 * Lay lines out top-down at prose pitch; `{ gap, items }` sets the step above
 * one line (table rows sit further apart than wrapped prose lines).
 */
function geometryDoc(lines) {
  let y = 700;
  const items = [];
  lines.forEach((l, i) => {
    const entry = Array.isArray(l) ? { items: l } : l.items ? l : { items: [l] };
    if (i > 0) y -= entry.gap || 14;
    for (const it of entry.items) items.push({ ...it, transform: [...it.transform.slice(0, 5), y] });
  });
  const { blocks } = pagesToBlocks([{ page: 1, items, pageHeight: PAGE_HEIGHT }]);
  return { blocks, doc: pdfDoc(blocks) };
}
const bodyLines = (texts) => texts.map((t) => item(t, 50, 0));

test('geometry: dense multi-pair inventory lines under a lead-in sentence stay rows (pdf_v6)', () => {
  const pairs = SAMPLES.map((s) => `${s.file} ${s.hash}`);
  for (const perLine of [2, 3, 4]) {
    const inv = [];
    for (let i = 0; i < pairs.length; i += perLine) inv.push(pairs.slice(i, i + perLine).join(' '));
    const { blocks, doc } = geometryDoc([
      ...bodyLines([INTRO, 'Analysts should review these artifacts and the infrastructure listed below.']),
      item('Indicators of compromise', 50, 0, 14, 'bold'),
      ...bodyLines(NETWORK.map((n) => n.source)),
      ...bodyLines(['The following loader samples were observed during the campaign:']),
      ...bodyLines(inv),
      item('Conclusion', 50, 0, 14, 'bold'),
      ...bodyLines([OUTRO, 'Defenders should monitor for the behaviours described in this report.'])
    ]);
    const invBlocks = blocks.filter((b) => SAMPLES.some((s) => String(b.text).includes(s.hash)));
    assert.ok(invBlocks.every((b) => b.layout === 'observable_row'), `${perLine}/line: ${JSON.stringify(invBlocks.map((b) => b.type))}`);
    assert.ok(!blocks.some((b) => b.type === 'paragraph' && SAMPLES.some((s) => String(b.text).includes(s.hash))), 'no inventory merged into the lead-in');
    assert.deepEqual(members(doc), EXPECTED, `${perLine} pairs per line`);
  }
});

test('geometry: column order (Filename | MD5 vs MD5 | Filename) does not change Indicators', () => {
  const variants = {
    filename_first: (s) => [item(s.file, 50, 0), item(s.hash, 260, 0)],
    hash_first: (s) => [item(s.hash, 50, 0), item(s.file, 330, 0)]
  };
  const results = {};
  for (const [name, row] of Object.entries(variants)) {
    const header = name === 'filename_first'
      ? [item('Filename', 50, 0, 10, 'bold'), item('MD5', 260, 0, 10, 'bold')]
      : [item('MD5', 50, 0, 10, 'bold'), item('Filename', 330, 0, 10, 'bold')];
    const { blocks, doc } = geometryDoc([
      ...bodyLines([INTRO, 'Analysts should review these artifacts and the infrastructure listed below.']),
      item('Indicators of compromise', 50, 0, 14, 'bold'),
      ...bodyLines(NETWORK.map((n) => n.source)),
      { gap: 22, items: [item('Samples', 50, 0, 12, 'bold')] },
      { gap: 24, items: header },
      ...SAMPLES.map((s) => ({ gap: 24, items: row(s) })),
      { gap: 24, items: [item('Conclusion', 50, 0, 14, 'bold')] },
      ...bodyLines([OUTRO, 'Defenders should monitor for the behaviours described in this report.'])
    ]);
    const table = blocks.find((b) => b.type === 'table');
    assert.ok(table, `${name}: geometry reconstructs a table`);
    // Header promotion may happen downstream (table interpreter); the column order is what varies.
    assert.deepEqual(table.table.headers || table.table.rows[0], name === 'filename_first' ? ['Filename', 'MD5'] : ['MD5', 'Filename']);
    results[name] = members(doc);
  }
  assert.deepEqual(results.filename_first, EXPECTED);
  assert.deepEqual(results.hash_first, EXPECTED);
});
