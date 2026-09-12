/**
 * Geometry-based PDF layout reconstruction (threat_library_pdf_v2).
 * Fixture: pdf.js text items for three pages of a browser-printed CJK report.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  collapseLetterSpacing,
  itemsToLines,
  isObservableOnlyLine,
  joinWrappedUrl,
  pagesToBlocks,
  plainTextToBlocks,
  PDF_LAYOUT_VERSION
} from './pdfLayout.js';
import { THREAT_LIBRARY_PDF_EXTRACTOR_VERSION, pdfToCanonicalDocument } from './pdfIngest.js';
import { annotateDocumentZones } from './documentZones.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const ITEMS = JSON.parse(fs.readFileSync(path.join(here, 'fixtures', 'kimsuky-appendix-pdf-items.json'), 'utf8'));

test('extractor version is the layout version (documents from v1 are rebuilt)', () => {
  assert.equal(THREAT_LIBRARY_PDF_EXTRACTOR_VERSION, PDF_LAYOUT_VERSION);
  assert.equal(PDF_LAYOUT_VERSION, 'threat_library_pdf_v2');
});

test('letter-spaced headings collapse; prose is untouched', () => {
  assert.equal(collapseLetterSpacing('附录 I O C'), '附录 IOC');
  assert.equal(collapseLetterSpacing('M D 5'), 'MD5');
  assert.equal(collapseLetterSpacing('C & C :'), 'C&C:');
  assert.equal(collapseLetterSpacing('A P T - C - 5 5 Kimsuky'), 'APT-C-55 Kimsuky');
  assert.equal(collapseLetterSpacing('the quick brown fox'), 'the quick brown fox');
  assert.equal(collapseLetterSpacing('a b'), 'a b');
});

test('items → lines: y-grouping, x-ordering, gap-based spacing, page-edge flag', () => {
  const p16 = ITEMS.pages.find((p) => p.page === 16);
  const lines = itemsToLines(p16.items, { pageHeight: p16.pageHeight });
  const texts = lines.map((l) => l.text);
  assert.ok(texts.includes('附录 IOC'), texts.join('\n'));
  assert.ok(texts.includes('MD5'));
  assert.ok(texts.includes('C&C:'));
  assert.ok(texts.includes('总结'));
  // Superscript citation stays on its line
  assert.ok(texts.some((t) => t.includes('[2][3]')));
  // Hash rows are separate lines in reading order
  const i1 = texts.indexOf('04272144d33668f99f7cf2255289e351');
  const i2 = texts.indexOf('3c64c75c9e6a3da7fbc766deb2081219');
  assert.ok(i1 >= 0 && i2 === i1 + 1);
  // Header (date + title) and footer (URL + page number) are page-edge lines
  const edges = lines.filter((l) => l.pageEdge).map((l) => l.text);
  assert.equal(edges.length, 2);
  assert.ok(edges.some((t) => t.startsWith('9/12/26')));
  assert.ok(edges.some((t) => /16\/18$/.test(t)));
});

test('observable-only rows and wrapped URL joining', () => {
  assert.equal(isObservableOnlyLine('http[:]//217[.]60[.]36[.]94/unicorn/uni.txt'), true);
  assert.equal(isObservableOnlyLine('107[.]172[.]249[.]140[:]443'), true);
  assert.equal(isObservableOnlyLine('[1]https://mp.weixin.qq.com/s/Ibz3FeA7twg-VCujA3cV_g'), true);
  assert.equal(isObservableOnlyLine('7479bedf5813a1527199f8958e898d19'), true);
  assert.equal(isObservableOnlyLine('MD5 7479bedf5813a1527199f8958e898d19'), false);
  assert.equal(isObservableOnlyLine('C&C:'), false);
  assert.equal(
    joinWrappedUrl('[2]https://dev.to/x/north-korea-linked-hackers-use-github-as-c2-infrastructure-to-', 'attack-south-korea-47aa'),
    '[2]https://dev.to/x/north-korea-linked-hackers-use-github-as-c2-infrastructure-to-attack-south-korea-47aa'
  );
  assert.equal(joinWrappedUrl('see https://vendor.example/report.', 'Conclusion'), null);
  assert.equal(joinWrappedUrl('https://a.example/x', 'https://b.example/y'), null);
});

test('pages → blocks: headings, list rows, page-edge blocks, merged paragraphs', () => {
  const { blocks } = pagesToBlocks(ITEMS.pages);
  const byText = (t) => blocks.find((b) => b.text === t);
  assert.equal(byText('附录 IOC').type, 'heading');
  assert.equal(byText('MD5').type, 'heading');
  assert.equal(byText('C&C:').type, 'heading');
  assert.equal(byText('参考链接').type, 'heading');
  assert.equal(byText('3.攻击组件分析').type, 'heading');
  assert.equal(byText('04272144d33668f99f7cf2255289e351').type, 'list_item');
  assert.equal(byText('107[.]172[.]249[.]140[:]443').layout, 'observable_row');
  const wrapped = blocks.find((b) => b.text.startsWith('[2]https://dev.to/'));
  assert.ok(wrapped && wrapped.text.endsWith('attack-south-korea-47aa'), 'wrapped reference URL re-joined');
  assert.equal(wrapped.citation, true);
  const edges = blocks.filter((b) => b.layout === 'page_edge');
  assert.equal(edges.length, 6, 'header + footer per page');
  // Body prose lines are merged into paragraphs (not one block per visual line)
  const prose = blocks.find((b) => b.text.startsWith('该载荷是一个经过高度混淆的'));
  assert.ok(prose && prose.text.length > 120 && prose.type === 'paragraph');
  // Reading order preserved: 总结 heading precedes its paragraph, appendix follows
  const order = blocks.map((b) => b.text);
  assert.ok(order.indexOf('总结') < order.findIndex((t) => t.startsWith('本次本次捕获的')));
  assert.ok(order.findIndex((t) => t.startsWith('本次本次捕获的')) < order.indexOf('附录 IOC'));
});

test('pages → blocks → zones: appendix strong, references negative, edges footer', () => {
  const { blocks } = pagesToBlocks(ITEMS.pages);
  const zoned = annotateDocumentZones({ title: 't', language: 'zh', blocks }, {});
  const z = (t) => zoned.blocks.find((b) => b.text === t)?.zone;
  assert.equal(z('04272144d33668f99f7cf2255289e351'), 'sample_table');
  assert.equal(z('http[:]//38[.]180[.]204[.]13/unicorn/uni.txt'), 'c2_section');
  assert.equal(z('107[.]172[.]249[.]140[:]443'), 'c2_section');
  assert.equal(z('[1]https://mp.weixin.qq.com/s/Ibz3FeA7twg-VCujA3cV_g'), 'reference_section');
  assert.ok(zoned.blocks.filter((b) => b.layout === 'page_edge').every((b) => b.zone === 'header_footer'));
});

test('plain-text fallback keeps observable rows and collapses letter spacing', () => {
  const r = plainTextToBlocks('附录 I O C\nM D 5\n04272144d33668f99f7cf2255289e351\n3c64c75c9e6a3da7fbc766deb2081219\nsome prose line', 1, 1);
  const texts = r.blocks.map((b) => `${b.type}:${b.text}`);
  assert.ok(texts.includes('list_item:04272144d33668f99f7cf2255289e351'));
  assert.ok(texts.some((t) => t.endsWith('附录 IOC')));
  assert.ok(texts.some((t) => t.endsWith('MD5')));
});

test('checked-in browser print PDF still extracts under the v2 layout path', async () => {
  const buf = fs.readFileSync(path.join(here, 'extract', 'fixtures', 'browser-print-cjk.pdf'));
  const r = await pdfToCanonicalDocument(buf, { fileName: 'browser-print-cjk.pdf' });
  assert.equal(r.document.meta.extractor, 'threat_library_pdf_v2');
  assert.equal(r.document.meta.layout_mode, 'geometry');
  assert.ok(r.document.blocks.length >= 1);
  assert.equal(r.requiresOcr, false);
});
