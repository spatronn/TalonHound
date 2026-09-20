import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parsePublicationDateValue,
  findDateMentions,
  extractHtmlPublicationDate,
  extractJsonLdPublicationDate,
  extractMetaPublicationDate,
  extractHtmlTimePublicationDate,
  extractVisiblePublicationDate,
  extractDocumentPublicationDate,
  detectReportPublicationDate,
  verifyAiPublicationDateHint,
  resolvePublicationDateUpdate,
  normalizeSuppliedPublicationDate,
  serializePublicationDate,
  publicationDateForExport,
  publishedDateOf,
  PUBLICATION_DATE_SOURCE_RANK
} from './publicationDate.js';

const NOW = new Date('2026-09-20T12:00:00Z');
const opts = { now: NOW };

// ---------------------------------------------------------------------------
// Value parsing
// ---------------------------------------------------------------------------

test('parse: ISO instant with offset keeps the instant and the stated calendar day', () => {
  const p = parsePublicationDateValue('2026-09-15T15:00:19+00:00', opts);
  assert.equal(p.precision, 'datetime');
  assert.equal(p.instant.toISOString(), '2026-09-15T15:00:19.000Z');
  assert.equal(p.date, '2026-09-15');
  // Timezone edge: 23:30 in UTC-4 is 03:30Z next day, but the source said the 15th.
  const late = parsePublicationDateValue('2026-09-15T23:30:00-04:00', opts);
  assert.equal(late.instant.toISOString(), '2026-09-16T03:30:00.000Z');
  assert.equal(late.date, '2026-09-15');
  assert.equal(parsePublicationDateValue('2026-09-14T15:50:37+03:00', opts).instant.toISOString(), '2026-09-14T12:50:37.000Z');
});

test('parse: date-only and offset-less values are calendar days at 00:00 UTC, never invented instants', () => {
  for (const raw of ['2026-09-15', '15 September 2026', 'September 15, 2026', 'Sep 08, 2026', 'Sept. 8, 2026', '15 Sep 2026', '2026年9月15日', '2026-09-15T10:00:00', 'Sep 10, 2026, 12:30 PM', '2026/09/15']) {
    const p = parsePublicationDateValue(raw, opts);
    assert.ok(p, `parses ${raw}`);
    assert.equal(p.precision, 'date', raw);
    assert.equal(p.date, raw.includes('08') || raw.includes(' 8,') ? '2026-09-08' : raw.includes('10') && raw.startsWith('Sep') ? '2026-09-10' : '2026-09-15', raw);
    assert.equal(p.instant.toISOString(), `${p.date}T00:00:00.000Z`);
  }
  assert.equal(parsePublicationDateValue('Mon, 15 Sep 2026 15:00:00 GMT', opts).precision, 'datetime');
});

test('parse: malformed, ambiguous numeric, out-of-range and far-future values are rejected', () => {
  for (const raw of ['', null, undefined, 'yesterday', '9/12/26', '12.09.2026', '2026-13-01', '2026-02-30', '1980-01-01', '2028-01-01', 'September 2026', '2026', 'x'.repeat(90)]) {
    assert.equal(parsePublicationDateValue(raw, opts), null, String(raw));
  }
});

test('findDateMentions reads unambiguous dates out of prose (including merged PDF cover text) and nothing else', () => {
  const m = findDateMentions('Report on the campaign.January 21, 2026that combines; see 2026-03-04 and 9/12/26 and March 2026', opts);
  assert.deepEqual(m.map((x) => x.parsed.date), ['2026-01-21', '2026-03-04']);
});

// ---------------------------------------------------------------------------
// URL / HTML sources (Infoblox / NCSC / DFIR shapes)
// ---------------------------------------------------------------------------

const INFOBLOX_LIKE = `<html><head>
<meta property="article:published_time" content="2026-09-15T15:00:19+00:00" />
<meta property="article:modified_time" content="2026-09-15T15:23:49+00:00" />
<script type="application/ld+json" class="yoast-schema-graph">{"@context":"https://schema.org","@graph":[{"@type":"Article","headline":"How Money Laundering, Scams, and Espionage Hide","datePublished":"2026-09-15T15:00:19+00:00","dateModified":"2026-09-15T15:23:49+00:00"},{"@type":"WebPage","datePublished":"2026-09-15T15:00:19+00:00"}]}</script>
</head><body><main><article><header class="entry-header"><p class="entry-meta"><time class="entry-time">September 15, 2026</time></p></header><p>Body mentions July 22, 2024 and October 23, 2025.</p></article>
<div class="related-posts"><time class="entry-time">April 10, 2026</time></div></main><footer>© 2026 Infoblox</footer></body></html>`;

test('URL 1+2: JSON-LD @graph Article datePublished wins with exact provenance (Infoblox acceptance shape)', () => {
  const d = extractHtmlPublicationDate(INFOBLOX_LIKE, opts);
  assert.equal(d.source, 'json_ld');
  assert.equal(d.raw_value, '2026-09-15T15:00:19+00:00');
  assert.equal(d.published_at, '2026-09-15T15:00:19.000Z');
  assert.equal(d.published_date, '2026-09-15');
  assert.equal(d.precision, 'datetime');
  assert.equal(d.evidence.selector, 'application/ld+json article.datePublished');
  // modified stamp is carried as context only, never as the published value
  assert.equal(d.modified_at, '2026-09-15T15:23:49+00:00');
});

test('URL 1: plain (non-graph) JSON-LD array / NewsArticle with a human date → date precision', () => {
  const html = `<script type="application/ld+json">[{"@type":["NewsArticle"],"datePublished":"15 September 2026","dateModified":"15 September 2026"}]</script>`;
  const d = extractJsonLdPublicationDate(html, opts);
  assert.equal(d.source, 'json_ld');
  assert.equal(d.published_date, '2026-09-15');
  assert.equal(d.precision, 'date');
  assert.equal(d.published_at, '2026-09-15T00:00:00.000Z');
});

test('URL: JSON-LD on a non-article node (Organization / Event) is ignored', () => {
  const html = `<script type="application/ld+json">{"@type":"Event","datePublished":"2026-09-01"}</script><script type="application/ld+json">{"@type":"Organization","foundingDate":"2001-01-01"}</script>`;
  assert.equal(extractJsonLdPublicationDate(html, opts).published_at, null);
});

test('URL 3: article:published_time when JSON-LD is absent; modified_time is never the value', () => {
  const html = `<head><meta property="article:modified_time" content="2026-09-18T10:00:00+00:00"><meta property="article:published_time" content="2026-09-15T15:00:19+00:00"></head>`;
  const d = extractHtmlPublicationDate(html, opts);
  assert.equal(d.source, 'og_article');
  assert.equal(d.published_date, '2026-09-15');
  assert.equal(d.evidence.selector, 'meta[property="article:published_time"]');
  assert.equal(d.modified_at, '2026-09-18T10:00:00+00:00');
});

test('URL 4: metadata fallback variants (datePublished / pubdate / sailthru.date / dc.date.issued / date)', () => {
  const cases = [
    ['<meta itemprop="datePublished" content="2026-09-15">', 'datepublished'],
    ['<meta name="pubdate" content="2026-09-15T08:00:00Z">', 'pubdate'],
    ['<meta name="sailthru.date" content="2026-09-15 08:00:00">', 'sailthru.date'],
    ['<meta name="DC.date.issued" content="2026-09-15">', 'dc.date.issued'],
    ['<meta name="date" content="September 15, 2026">', 'date']
  ];
  for (const [html, key] of cases) {
    const d = extractMetaPublicationDate(`<head>${html}<meta name="last-modified" content="2026-09-19"></head>`, opts);
    assert.equal(d.source, 'meta', html);
    assert.equal(d.published_date, '2026-09-15', html);
    assert.equal(d.evidence.selector, `meta[name="${key}"]`);
  }
  assert.equal(extractMetaPublicationDate('<meta name="last-modified" content="2026-09-19"><meta property="og:updated_time" content="2026-09-19">', opts).published_at, null);
});

test('URL 5: <time datetime> only in publication context; footer / related / updated times are skipped', () => {
  const labelled = `<main><div><h4>Published</h4> <time datetime="2026-09-15T12:00:00Z">15 September 2026</time></div>
    <div class="related"><time datetime="2026-06-04T12:00:00Z">4 Jun 2026</time></div></main>
    <footer><time datetime="2026-09-19">19 Sep 2026</time></footer>`;
  const d = extractHtmlTimePublicationDate(labelled, opts);
  assert.equal(d.source, 'html_time');
  assert.equal(d.published_date, '2026-09-15');
  assert.equal(d.evidence.selector, 'time[label]');

  const itemprop = `<article><time itemprop="datePublished" datetime="2026-09-15">Sep 15</time><time itemprop="dateModified" datetime="2026-09-18">Sep 18</time></article>`;
  assert.equal(extractHtmlTimePublicationDate(itemprop, opts).published_date, '2026-09-15');

  const updatedOnly = `<article><span>Updated: <time datetime="2026-09-18">Sep 18</time></span></article>`;
  assert.equal(extractHtmlTimePublicationDate(updatedOnly, opts).published_at, null);

  const noContext = `<article><time datetime="2026-09-18">Sep 18</time></article>`;
  assert.equal(extractHtmlTimePublicationDate(noContext, opts).published_at, null);
});

test('URL 6: visible "Published: <date>" label / post-date class inside the article', () => {
  const html = `<main><article><p class="post-date">September 15, 2026</p><p>On September 3, 2026 the actor registered domains. Copyright September 1, 2026.</p></article></main>`;
  const d = extractVisiblePublicationDate(html, opts);
  assert.equal(d.source, 'visible_date');
  assert.equal(d.published_date, '2026-09-15');
  const labelled = `<div><span>Published on: 15 September 2026</span><span>Last updated: 18 September 2026</span></div>`;
  assert.equal(extractVisiblePublicationDate(labelled, opts).published_date, '2026-09-15');
});

test('URL 7: multiple irrelevant dates (body, copyright, comments, latest-post widget, nav) → null', () => {
  const html = `<html><head><meta name="copyright" content="2026"></head><body>
    <nav><a>Archive: September 1, 2026</a></nav>
    <aside class="widget recent-posts"><span class="post-date">September 18, 2026</span></aside>
    <main><article><p>On September 3, 2026 the campaign began; samples were observed on September 5, 2026.</p>
    <div class="comments"><span class="post-date">September 19, 2026</span></div></article></main>
    <footer>© 2026 Vendor. Last updated September 19, 2026.</footer></body></html>`;
  const d = extractHtmlPublicationDate(html, opts);
  assert.equal(d.published_at, null);
  assert.equal(d.source, null);
  assert.equal(d.reason, 'no_publication_date_in_html');
});

test('URL 8: publication + modified both present → published wins, modified kept as context', () => {
  const html = `<script type="application/ld+json">{"@type":"BlogPosting","datePublished":"2026-08-24T14:28:41+00:00","dateModified":"2026-08-25T18:43:08+00:00"}</script>`;
  const d = extractHtmlPublicationDate(html, opts);
  assert.equal(d.published_date, '2026-08-24');
  assert.equal(d.modified_at, '2026-08-25T18:43:08+00:00');
});

test('URL 9: malformed metadata value falls through to the next source, malformed everywhere → null', () => {
  const html = `<script type="application/ld+json">{"@type":"Article","datePublished":"soon"}</script><meta property="article:published_time" content="not-a-date"><meta name="pubdate" content="2026-09-15">`;
  const d = extractHtmlPublicationDate(html, opts);
  assert.equal(d.source, 'meta');
  assert.equal(d.published_date, '2026-09-15');
  const bad = `<script type="application/ld+json">{"@type":"Article","datePublished":"soon"}</script><meta property="article:published_time" content="2026-99-99">`;
  assert.equal(extractHtmlPublicationDate(bad, opts).published_at, null);
});

test('URL 10: no date at all → null with a reason, never a guess from the URL path or fetch time', () => {
  const d = extractHtmlPublicationDate('<html><body><article><h1>Title</h1><p>Prose without a date.</p></article></body></html>', { ...opts, url: 'https://x.example/2026/08/24/post/' });
  assert.equal(d.published_at, null);
  assert.equal(d.reason, 'no_publication_date_in_html');
});

test('URL 11: timezone edge — instant preserved, published_date is the day the source stated', () => {
  const html = `<meta property="article:published_time" content="2026-09-15T23:30:00-04:00">`;
  const d = extractHtmlPublicationDate(html, opts);
  assert.equal(d.published_at, '2026-09-16T03:30:00.000Z');
  assert.equal(d.published_date, '2026-09-15');
  assert.equal(d.precision, 'datetime');
});

test('URL 12: date-only source → precision date, 00:00 UTC of that day', () => {
  const html = `<meta property="article:published_time" content="2026-09-15">`;
  const d = extractHtmlPublicationDate(html, opts);
  assert.equal(d.published_at, '2026-09-15T00:00:00.000Z');
  assert.equal(d.precision, 'date');
  assert.equal(d.published_date, '2026-09-15');
});

// ---------------------------------------------------------------------------
// PDF / canonical document
// ---------------------------------------------------------------------------

function pdfDoc(blocks, title = 'Report') {
  return {
    title,
    language: null,
    blocks: blocks.map((b, i) => ({ id: b.id || `p${b.page}-b${String(i + 1).padStart(2, '0')}`, type: b.type || 'paragraph', text: b.text, page: b.page, layout: b.layout })),
    meta: { adapter: 'pdf', extractor: 'threat_library_pdf_v3' }
  };
}

test('PDF 13: explicit cover / report date — labelled, byline-sized and merged-cover forms', () => {
  const labelled = pdfDoc([
    { page: 1, text: 'CYBER THREAT ANALYSIS', type: 'heading' },
    { page: 1, text: 'Publication date: 21 January 2026' },
    { page: 2, text: 'The actor has been active since March 3, 2025 and was observed on April 4, 2025.' }
  ]);
  let d = extractDocumentPublicationDate(labelled, { sourceType: 'pdf', ...opts });
  assert.equal(d.source, 'pdf_visible_date');
  assert.equal(d.published_date, '2026-01-21');
  assert.equal(d.evidence.signal, 'label');
  assert.equal(d.evidence.page, 1);

  // Browser-printed article: repeated print stamp on every page + a byline with time.
  const printed = pdfDoc([
    { page: 1, text: '9/12/26, 9:05 PM APT-C-55 attack chain analysis', layout: 'page_edge' },
    { page: 1, text: 'APT-C-55 attack chain analysis', type: 'heading' },
    { page: 1, text: '360 Threat Intelligence Center Sep 10, 2026, 12:30 PM' },
    { page: 1, text: 'Long body paragraph describing a multi-stage loader that hides its PowerShell stage inside a LNK file and collects host information before the second stage. '.repeat(2) },
    { page: 2, text: '9/12/26, 9:05 PM APT-C-55 attack chain analysis', layout: 'page_edge' },
    { page: 3, text: '9/12/26, 9:05 PM APT-C-55 attack chain analysis', layout: 'page_edge' }
  ]);
  d = extractDocumentPublicationDate(printed, { sourceType: 'pdf', ...opts });
  assert.equal(d.published_date, '2026-09-10');
  assert.equal(d.precision, 'date');
  assert.equal(d.evidence.signal, 'byline');
  // The same byline next to body prose that carries its own (activity) dates
  // is ambiguous: an unlabelled date is only trusted when it is the only one.
  const printedWithBodyDates = pdfDoc([
    ...printed.blocks.slice(0, 3).map((x) => ({ page: x.page, text: x.text, type: x.type, layout: x.layout })),
    { page: 1, text: 'Long body paragraph describing the campaign that started on 2026-08-01 and continued through August 15, 2026 with more prose to exceed the byline size limit. '.repeat(2) }
  ]);
  assert.equal(extractDocumentPublicationDate(printedWithBodyDates, { sourceType: 'pdf', ...opts }).reason, 'pdf_visible_date_ambiguous');

  // Cover page merged into one block that carries the title and the date.
  const cover = pdfDoc([
    { page: 1, text: 'PurpleBravo threat actors masquerade as recruiters.PurpleBravo Targeting of the IT Software Supply ChainCYBER THREAT ANALYSISNORTH KOREA first documented in November 2023.January 21, 2026that combines' },
    { page: 2, text: 'Executive Summary', type: 'heading' }
  ], 'PurpleBravo Targeting of the IT Software Supply Chain');
  d = extractDocumentPublicationDate(cover, { sourceType: 'pdf', ...opts });
  assert.equal(d.published_date, '2026-01-21');
  assert.equal(d.evidence.signal, 'cover');
});

test('PDF 14: multiple historical dates in the body / front matter without a label → null, not a guess', () => {
  const doc = pdfDoc([
    { page: 1, text: 'Threat Report', type: 'heading' },
    { page: 1, text: 'Incident timeline: March 3, 2026' },
    { page: 1, text: 'Second wave: March 9, 2026' },
    { page: 2, text: 'Prose.' }
  ]);
  const d = extractDocumentPublicationDate(doc, { sourceType: 'pdf', ...opts });
  assert.equal(d.published_at, null);
  assert.equal(d.reason, 'pdf_visible_date_ambiguous');
  // Negative context (as of / observed / first seen / from-until) never qualifies even when single.
  const negative = pdfDoc([{ page: 1, text: 'Data as of September 1, 2026' }, { page: 1, text: 'Activity observed between 2026-05-01 and 2026-06-01' }]);
  assert.equal(extractDocumentPublicationDate(negative, { sourceType: 'pdf', ...opts }).published_at, null);
  // A date deep in the body (page 3+) is never front matter.
  const deep = pdfDoc([{ page: 1, text: 'Title', type: 'heading' }, { page: 3, text: 'Published: September 1, 2026' }]);
  assert.equal(extractDocumentPublicationDate(deep, { sourceType: 'pdf', ...opts }).published_at, null);
});

test('PDF 15: a PDF whose only date is metadata CreationDate must NOT get a publication date', () => {
  const doc = pdfDoc([{ page: 1, text: 'Quarterly Threat Landscape', type: 'heading' }, { page: 1, text: 'Prepared by the research team.' }]);
  doc.meta.info = { CreationDate: "D:20260901120000+00'00'", ModDate: "D:20260905120000+00'00'" };
  doc.meta.pdf_creation_date = '2026-09-01T12:00:00Z';
  const d = extractDocumentPublicationDate(doc, { sourceType: 'pdf', ...opts });
  assert.equal(d.published_at, null);
  assert.equal(d.reason, 'no_date_in_front_matter');
  assert.equal(detectReportPublicationDate({ sourceType: 'pdf', document: doc, now: NOW }).published_at, null);
});

test('PDF 16: no date at all → null; empty / missing document → null without throwing', () => {
  assert.equal(extractDocumentPublicationDate(pdfDoc([{ page: 1, text: 'Nothing dated here.' }]), { sourceType: 'pdf', ...opts }).published_at, null);
  assert.equal(extractDocumentPublicationDate(null, opts).reason, 'document_empty');
  assert.equal(detectReportPublicationDate({ sourceType: 'pdf', document: null }).published_at, null);
  assert.equal(detectReportPublicationDate({ sourceType: 'url', html: '', document: null }).published_at, null);
});

test('detectReportPublicationDate: URL prefers HTML metadata and only falls back to the document byline', () => {
  const doc = { title: 'T', blocks: [{ id: 'b001', type: 'paragraph', text: 'Sep 14, 2026' }, { id: 'b002', type: 'paragraph', text: 'Body.' }], meta: { adapter: 'generic_html' } };
  const viaHtml = detectReportPublicationDate({ sourceType: 'url', html: INFOBLOX_LIKE, document: doc, now: NOW });
  assert.equal(viaHtml.source, 'json_ld');
  const viaDoc = detectReportPublicationDate({ sourceType: 'url', html: '<html><body><p>no metadata</p></body></html>', document: doc, now: NOW });
  assert.equal(viaDoc.source, 'visible_date');
  assert.equal(viaDoc.published_date, '2026-09-14');
});

// ---------------------------------------------------------------------------
// AI hint gate
// ---------------------------------------------------------------------------

test('AI hint is accepted only when the referenced evidence block literally carries that date', () => {
  const doc = pdfDoc([{ id: 'b1', page: 1, text: 'Published September 15, 2026 by the team' }, { id: 'b2', page: 1, text: 'Observed on September 3, 2026' }]);
  const ok = verifyAiPublicationDateHint({ value: '2026-09-15', evidence_block_ids: ['b1'] }, doc, opts);
  assert.equal(ok.source, 'ai');
  assert.equal(ok.published_date, '2026-09-15');
  assert.equal(ok.evidence.block_id, 'b1');
  assert.equal(verifyAiPublicationDateHint({ value: '2026-09-16', evidence_block_ids: ['b1'] }, doc, opts).reason, 'ai_hint_not_in_evidence');
  assert.equal(verifyAiPublicationDateHint({ value: '2026-09-03', evidence_block_ids: ['b2'] }, doc, opts).reason, 'ai_hint_not_in_evidence');
  assert.equal(verifyAiPublicationDateHint({ value: '2026-09-15', evidence_block_ids: [] }, doc, opts).reason, 'ai_hint_without_evidence');
  assert.equal(verifyAiPublicationDateHint({ value: 'soon', evidence_block_ids: ['b1'] }, doc, opts).reason, 'ai_hint_unparsable');
  assert.ok(PUBLICATION_DATE_SOURCE_RANK.ai < PUBLICATION_DATE_SOURCE_RANK.pdf_visible_date);
});

// ---------------------------------------------------------------------------
// Write policy (17–21)
// ---------------------------------------------------------------------------

const DETECTED = extractHtmlPublicationDate(INFOBLOX_LIKE, opts);

test('policy 17: known date is written with all four columns when the report has none', () => {
  const r = resolvePublicationDateUpdate({ published_at: null }, DETECTED);
  assert.equal(r.action, 'write');
  assert.equal(r.reason, 'was_null');
  assert.deepEqual(r.fields, {
    published_at: '2026-09-15T15:00:19.000Z',
    published_at_source: 'json_ld',
    published_at_precision: 'datetime',
    published_at_raw: '2026-09-15T15:00:19+00:00'
  });
});

test('policy 18: unknown stays unknown (no fields written, reason carried)', () => {
  const none = extractHtmlPublicationDate('<p>nothing</p>', opts);
  const r = resolvePublicationDateUpdate({ published_at: null }, none);
  assert.equal(r.action, 'keep');
  assert.equal(r.fields, null);
  assert.equal(r.reason, 'no_publication_date_in_html');
});

test('policy 19: an existing good value is never replaced by a null / failed detection (retry safety)', () => {
  const existing = { published_at: new Date('2026-09-15T15:00:19Z'), published_at_source: 'json_ld', published_at_precision: 'datetime' };
  assert.deepEqual(resolvePublicationDateUpdate(existing, null), { action: 'keep', reason: 'no_detection_keep_existing', fields: null });
  assert.equal(resolvePublicationDateUpdate(existing, extractHtmlPublicationDate('<p>x</p>', opts)).action, 'keep');
});

test('policy 20: THIB / manual values are durable; unknown provenance is kept', () => {
  assert.equal(resolvePublicationDateUpdate({ published_at: new Date('2026-01-01Z'), published_at_source: 'thib' }, DETECTED).reason, 'existing_thib');
  assert.equal(resolvePublicationDateUpdate({ published_at: new Date('2026-01-01Z'), published_at_source: 'manual' }, DETECTED).reason, 'existing_manual');
  assert.equal(resolvePublicationDateUpdate({ published_at: new Date('2026-01-01Z'), published_at_source: null }, DETECTED).reason, 'existing_unknown_provenance');
});

test('policy 21: reprocess only replaces a strictly weaker provenance; same rank / weaker keeps', () => {
  const weak = { published_at: new Date('2026-09-15T00:00:00Z'), published_at_source: 'visible_date', published_at_precision: 'date', published_at_raw: 'September 15, 2026' };
  const up = resolvePublicationDateUpdate(weak, DETECTED);
  assert.equal(up.action, 'write');
  assert.equal(up.reason, 'provenance_upgrade');
  const differentDay = { ...weak, published_at: new Date('2026-09-14T00:00:00Z'), published_at_raw: 'September 14, 2026' };
  assert.equal(resolvePublicationDateUpdate(differentDay, DETECTED).reason, 'stronger_source');
  const strong = { published_at: new Date('2026-09-15T15:00:19Z'), published_at_source: 'json_ld', published_at_precision: 'datetime' };
  const metaOnly = extractHtmlPublicationDate('<meta property="article:published_time" content="2026-09-16">', opts);
  assert.equal(resolvePublicationDateUpdate(strong, metaOnly).reason, 'existing_not_weaker');
  assert.equal(resolvePublicationDateUpdate(strong, DETECTED).reason, 'existing_not_weaker');
});

test('THIB supplied value normalises to the persisted shape (date-only and instant) or null', () => {
  assert.deepEqual(normalizeSuppliedPublicationDate('2026-09-15', 'thib'), {
    published_at: '2026-09-15T00:00:00.000Z', published_at_source: 'thib', published_at_precision: 'date', published_at_raw: '2026-09-15'
  });
  assert.equal(normalizeSuppliedPublicationDate('2026-09-15T15:00:19.000Z', 'thib').published_at_precision, 'datetime');
  assert.equal(normalizeSuppliedPublicationDate('not a date', 'thib'), null);
  assert.equal(normalizeSuppliedPublicationDate(null, 'thib'), null);
});

// ---------------------------------------------------------------------------
// Serialization (26) + export round-trip
// ---------------------------------------------------------------------------

test('serialize: published_date is the stated day; precision/source travel; null stays null', () => {
  assert.deepEqual(serializePublicationDate({ published_at: null }), {
    published_at: null, published_date: null, published_at_precision: null, published_at_source: null
  });
  const dateOnly = { published_at: new Date('2026-09-15T00:00:00Z'), published_at_precision: 'date', published_at_source: 'pdf_visible_date', published_at_raw: 'September 15, 2026' };
  assert.deepEqual(serializePublicationDate(dateOnly), {
    published_at: dateOnly.published_at, published_date: '2026-09-15', published_at_precision: 'date', published_at_source: 'pdf_visible_date'
  });
  // Instant late in a negative-offset zone: the day the source stated, not the UTC day.
  const late = { published_at: new Date('2026-09-16T03:30:00Z'), published_at_precision: 'datetime', published_at_source: 'og_article', published_at_raw: '2026-09-15T23:30:00-04:00' };
  assert.equal(serializePublicationDate(late).published_date, '2026-09-15');
  // Legacy row without provenance: UTC day, null provenance.
  assert.deepEqual(serializePublicationDate({ published_at: '2026-09-10T00:00:00.000Z' }), {
    published_at: '2026-09-10T00:00:00.000Z', published_date: '2026-09-10', published_at_precision: null, published_at_source: null
  });
  assert.equal(publishedDateOf({ published_at: '2026-09-10T22:00:00.000Z', published_at_raw: 'garbage' }), '2026-09-10');
});

test('THIB export: date-only travels as YYYY-MM-DD and re-imports with the same precision; instants as ISO UTC', () => {
  const dateOnly = { published_at: new Date('2026-09-15T00:00:00Z'), published_at_precision: 'date' };
  assert.equal(publicationDateForExport(dateOnly), '2026-09-15');
  assert.equal(normalizeSuppliedPublicationDate(publicationDateForExport(dateOnly), 'thib').published_at_precision, 'date');
  const instant = { published_at: new Date('2026-09-15T15:00:19Z'), published_at_precision: 'datetime' };
  assert.equal(publicationDateForExport(instant), '2026-09-15T15:00:19.000Z');
  assert.equal(publicationDateForExport({ published_at: null }), null);
});
