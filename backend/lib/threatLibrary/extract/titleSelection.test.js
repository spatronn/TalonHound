import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { hostBrandLabel, selectHtmlTitle, siteBrandNames } from './titleSelection.js';
import { extractCanonicalDocumentFromHtml } from './extractHtml.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const VENDOR_BLOG = fs.readFileSync(path.join(here, 'fixtures/vendor-blog-site-wide-og.html'), 'utf8');
const VENDOR_URL = 'https://hatching.io/blog/triage-insights-ep5-short/';
const ARTICLE_TITLE = 'Triage Insights: WinLol, a Rust Dropper Chain Delivering a WebRTC Remote Desktop RAT';

const pick = (html, url = 'https://www.vendor.com/blog/post') => selectHtmlTitle(html, { url });

test('site-wide og:title with an article-specific <title> / <h1>: the article title wins (18651 shape)', () => {
  const r = pick(VENDOR_BLOG, VENDOR_URL);
  assert.equal(r.title, ARTICLE_TITLE);
  assert.equal(r.source, 'title_tag');
  assert.deepEqual(r.rejected.map((x) => [x.source, x.reason]), [
    ['og_title', 'site_wide_brand_title'],
    ['twitter_title', 'site_wide_brand_title']
  ]);
  // The navigation "Blog." heading is never chosen.
  assert.notEqual(r.title, 'Blog.');
});

test('the canonical document carries the selected title and its provenance', () => {
  const out = extractCanonicalDocumentFromHtml(VENDOR_BLOG, { url: VENDOR_URL, finalUrl: VENDOR_URL, httpStatus: 200 });
  assert.equal(out.ok, true);
  assert.equal(out.document.title, ARTICLE_TITLE);
  assert.equal(out.document.meta.title_selection.source, 'title_tag');
  assert.equal(out.document.meta.title_selection.rejected[0].value, 'Hatching - Automated malware analysis solutions');
});

test('a correct article-specific og:title is kept (existing behaviour)', () => {
  assert.equal(pick('<meta property="og:title" content="Analysis of FooRAT"><title>Analysis of FooRAT | Vendor</title>').title, 'Analysis of FooRAT');
  // Brand-led but agreeing with the article: kept verbatim.
  assert.equal(
    pick('<meta property="og:title" content="Vendor - Analysis of FooRAT"><article><h1>Analysis of the FooRAT loader</h1></article>').title,
    'Vendor - Analysis of FooRAT'
  );
});

test('missing <h1> / no article evidence: nothing is rejected', () => {
  const r = pick('<meta property="og:title" content="Vendor - Security solutions"><title>Vendor - Security solutions</title>');
  assert.equal(r.title, 'Vendor - Security solutions');
  assert.deepEqual(r.rejected, []);
  assert.equal(pick('<title>Only a title tag</title>').title, 'Only a title tag');
  assert.equal(pick('<html><body><p>no title at all</p></body></html>').title, '');
});

test('conflicting metadata: brand-only og:title loses to the article heading', () => {
  const r = pick('<meta property="og:title" content="Vendor Blog"><title>Vendor Blog</title><main><h1>New FooRAT loader abuses DLL sideloading</h1></main>');
  assert.equal(r.title, 'New FooRAT loader abuses DLL sideloading');
  assert.equal(r.source, 'article_h1');
  // A weak overlap ("malware analysis") with a generic tagline is not agreement.
  const weak = pick('<meta property="og:title" content="Vendor - Automated malware analysis solutions"><title>New malware analysis: FooRAT</title>');
  assert.equal(weak.title, 'New malware analysis: FooRAT');
});

test('a correct og:title is never replaced by a different JSON-LD / <h1> headline (stored titles stay stable)', () => {
  // Prod report 15 shape: both titles are article-specific, the historical og:title wins.
  const html = `<script type="application/ld+json">{"@type":"NewsArticle","headline":"How Money Laundering, Scams, and Espionage Hide in a Web Full of Casino Garbage"}</script>
    <meta property="og:title" content="Illegal Gambling Sites Reveal Three Types of Cybercrime">
    <title>Illegal Gambling Sites Reveal Three Types of Cybercrime | Vendor</title>`;
  assert.equal(pick(html).title, 'Illegal Gambling Sites Reveal Three Types of Cybercrime');
  // Attribute values keep their historical cleaning (entities decoded, inner spacing kept).
  assert.equal(pick('<meta property="og:title" content="A &amp; B  exploits">').title, 'A & B  exploits');
});

test('JSON-LD headline replaces brand-only titles; publisher name becomes a site brand', () => {
  const html = `<script type="application/ld+json">{"@context":"https://schema.org","@type":"BlogPosting","headline":"FooRAT returns with a new loader","publisher":{"@type":"Organization","name":"Acme Labs"}}</script>
    <meta property="og:title" content="Acme Labs"><title>Something | Acme Labs</title>`;
  const r = pick(html, 'https://acme.example/blog/x');
  assert.equal(r.title, 'FooRAT returns with a new loader');
  assert.equal(r.source, 'json_ld');
  assert.ok(siteBrandNames(html, 'https://acme.example/').includes('Acme Labs'));
  // A JSON-LD WebSite name is a brand, not a headline.
  assert.equal(pick('<script type="application/ld+json">{"@type":"WebSite","name":"Acme"}</script><title>Real title</title>').title, 'Real title');
});

test('publisher-brand title vs article title, and host brand labels', () => {
  assert.equal(hostBrandLabel('https://hatching.io/blog/x'), 'hatching');
  assert.equal(hostBrandLabel('https://blog.talosintelligence.com/x'), 'talosintelligence');
  assert.equal(hostBrandLabel('https://www.ncsc.gov.uk/news/x'), 'ncsc');
  assert.equal(hostBrandLabel('not a url'), 'not a url');
  // og:site_name declares the brand even when it differs from the host.
  const r = pick('<meta property="og:site_name" content="Threat Lab"><meta property="og:title" content="Threat Lab | Research at scale"><title>WinLol dropper chain analysed</title>', 'https://example.org/p');
  assert.equal(r.title, 'WinLol dropper chain analysed');
  assert.deepEqual(r.site_names, ['Threat Lab']);
});

test('an explicit title hint is used as-is', () => {
  assert.equal(selectHtmlTitle(VENDOR_BLOG, { url: VENDOR_URL, hint: 'Analyst title' }).title, 'Analyst title');
});
