import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  extractPublisherIdentitySignals,
  resolveSourceIdentity,
  urlIdentityKey,
  SOURCE_IDENTITY_VERSION
} from './sourceIdentity.js';
import { stripTrackingParams, urlKeyOfCanonical, canonicalizeReportUrl } from './importIdentity.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const SECURELIST_HTML = readFileSync(path.join(here, 'fixtures/source-identity/securelist-121715-head.html'), 'utf8');
const SL_BARE = 'https://securelist.com/cyberstrikeai-attacks/121715/';
const SL_TR = 'https://securelist.com/tr/cyberstrikeai-attacks/121715/';

const keysOf = (identity) => identity.keys.map((k) => k.key);
const shareKey = (a, b) => keysOf(a).some((k) => keysOf(b).includes(k));

function page({ canonical, ogUrl, jsonLdUrl, wpRest, shortlink, hreflang = [] } = {}) {
  const head = [
    canonical ? `<link rel="canonical" href="${canonical}">` : '',
    ogUrl ? `<meta property="og:url" content="${ogUrl}">` : '',
    wpRest ? `<link rel="alternate" type="application/json" href="${wpRest}">` : '',
    shortlink ? `<link rel='shortlink' href='${shortlink}' />` : '',
    ...hreflang.map(([lang, href]) => `<link rel="alternate" hreflang="${lang}" href="${href}">`),
    jsonLdUrl ? `<script type="application/ld+json">{"@type":"BlogPosting","@id":"${jsonLdUrl}","headline":"x"}</script>` : ''
  ].join('\n');
  return `<!doctype html><html><head>${head}</head><body><article><p>body</p></article></body></html>`;
}

// --- Securelist regression (production reports 35700 / 35865) -----------------

test('Securelist: bare URL (301 → /tr/) proves the /tr/ identity and the WordPress post id', () => {
  const id = resolveSourceIdentity({ submittedUrl: SL_BARE, finalUrl: SL_TR, html: SECURELIST_HTML });
  assert.equal(id.version, SOURCE_IDENTITY_VERSION);
  const byKey = Object.fromEntries(id.keys.map((k) => [k.key, k.evidence]));
  assert.deepEqual(byKey['url:https://securelist.com/cyberstrikeai-attacks/121715'], ['submitted']);
  assert.deepEqual(byKey['url:https://securelist.com/tr/cyberstrikeai-attacks/121715'].sort(), ['canonical', 'json_ld', 'og_url', 'redirect']);
  assert.deepEqual(byKey['wp:securelist.com:121715'], ['wp_post']);
  assert.deepEqual(id.rejected, []);
});

test('Securelist: /tr/ URL and bare URL resolve to one logical article (either import order)', () => {
  const tr = resolveSourceIdentity({ submittedUrl: SL_TR, finalUrl: SL_TR, html: SECURELIST_HTML });
  const bare = resolveSourceIdentity({ submittedUrl: SL_BARE, finalUrl: SL_TR, html: SECURELIST_HTML });
  assert.ok(shareKey(tr, bare));
  assert.ok(keysOf(tr).includes('url:https://securelist.com/tr/cyberstrikeai-attacks/121715'));
  assert.ok(keysOf(tr).includes('wp:securelist.com:121715'));
});

test('Securelist: hreflang translations are recorded, never identity keys', () => {
  const id = resolveSourceIdentity({ submittedUrl: SL_TR, finalUrl: SL_TR, html: SECURELIST_HTML });
  assert.deepEqual(id.hreflang.map((h) => h.lang).sort(), ['es', 'pt-br', 'ru']);
  assert.ok(!keysOf(id).some((k) => k.includes('securelist.ru') || k.includes('latam.')));
});

test('no global locale-segment folding: /tr/, /en/, /de/ paths stay distinct without publisher evidence', () => {
  for (const seg of ['tr', 'en', 'de', 'fr']) {
    assert.notEqual(urlIdentityKey(`https://vendor.example/${seg}/post/1/`), urlIdentityKey('https://vendor.example/post/1/'));
  }
  const a = resolveSourceIdentity({ submittedUrl: 'https://vendor.example/de/post/1/' });
  const b = resolveSourceIdentity({ submittedUrl: 'https://vendor.example/post/1/' });
  assert.equal(shareKey(a, b), false);
});

// --- Safe normalisation ---------------------------------------------------------

test('safe normalisation: host case, default port, fragment, trailing slash, www, tracking params fold', () => {
  const base = urlIdentityKey('https://vendor.example/blog/post');
  for (const v of [
    'HTTPS://VENDOR.EXAMPLE/blog/post',
    'https://vendor.example:443/blog/post',
    'https://vendor.example/blog/post/',
    'https://vendor.example/blog/post#iocs',
    'https://www.vendor.example/blog/post',
    'https://vendor.example/blog/post?utm_source=x&utm_medium=email',
    'https://vendor.example/blog/post?fbclid=abc',
    'https://vendor.example/blog/post?gclid=1&mc_cid=2&_hsenc=3'
  ]) {
    assert.equal(urlIdentityKey(v), base, v);
  }
});

test('document-selecting query parameters, path case, scheme and other ports stay distinct', () => {
  const base = urlIdentityKey('https://vendor.example/view');
  for (const v of [
    'https://vendor.example/view?id=2',
    'https://vendor.example/view?p=2&utm_source=x',
    'https://vendor.example/View',
    'http://vendor.example/view',
    'https://vendor.example:8443/view',
    'https://vendor.example/view?ref=feed'
  ]) {
    assert.notEqual(urlIdentityKey(v), base, v);
  }
  // Only tracking pairs are removed; the rest keep their order.
  assert.equal(stripTrackingParams('https://v.example/x?b=2&utm_source=a&a=1'), 'https://v.example/x?b=2&a=1');
  assert.equal(urlKeyOfCanonical(canonicalizeReportUrl('https://www.v.example/x/?utm_id=1')), 'url:https://v.example/x');
});

// --- Redirects --------------------------------------------------------------------

test('redirect target is an identity key; a redirect to the site root is rejected', () => {
  const moved = resolveSourceIdentity({ submittedUrl: 'https://v.example/old-slug/', finalUrl: 'https://v.example/2026/new-slug/' });
  assert.deepEqual(moved.keys.find((k) => k.key === 'url:https://v.example/2026/new-slug').evidence, ['redirect']);
  const removed = resolveSourceIdentity({ submittedUrl: 'https://v.example/removed-post/', finalUrl: 'https://v.example/' });
  assert.deepEqual(keysOf(removed), ['url:https://v.example/removed-post']);
  assert.deepEqual(removed.rejected, [{ kind: 'redirect', value: 'https://v.example/', reason: 'root_path' }]);
});

// --- Publisher canonical metadata -------------------------------------------------

test('canonical URL corroborated by og:url is an identity key (canonical alias)', () => {
  const html = page({ canonical: 'https://v.example/research/apt-x', ogUrl: 'https://v.example/research/apt-x' });
  const id = resolveSourceIdentity({ submittedUrl: 'https://v.example/amp/research/apt-x', finalUrl: 'https://v.example/amp/research/apt-x', html });
  assert.deepEqual(id.keys.find((k) => k.key === 'url:https://v.example/research/apt-x').evidence.sort(), ['canonical', 'og_url']);
});

test('a lone uncorroborated canonical is recorded and rejected', () => {
  const html = page({ canonical: 'https://v.example/research/other-article' });
  const id = resolveSourceIdentity({ submittedUrl: 'https://v.example/research/apt-x', html });
  assert.deepEqual(keysOf(id), ['url:https://v.example/research/apt-x']);
  assert.deepEqual(id.rejected, [{ kind: 'canonical', value: 'https://v.example/research/other-article', reason: 'uncorroborated' }]);
});

test('canonical equal to the delivered URL needs no corroboration', () => {
  const html = page({ canonical: 'https://v.example/research/apt-x/' });
  const id = resolveSourceIdentity({ submittedUrl: 'https://v.example/research/apt-x?utm_source=feed', html });
  assert.deepEqual(id.keys.map((k) => [k.key, k.evidence]), [['url:https://v.example/research/apt-x', ['submitted', 'canonical']]]);
});

test('untrusted canonical metadata: cross-site canonical / og:url never become keys, even when they agree', () => {
  const html = page({
    canonical: 'https://victim-vendor.example/blog/real-report',
    ogUrl: 'https://victim-vendor.example/blog/real-report',
    jsonLdUrl: 'https://victim-vendor.example/blog/real-report'
  });
  const id = resolveSourceIdentity({ submittedUrl: 'https://attacker.example/copy', html });
  assert.deepEqual(keysOf(id), ['url:https://attacker.example/copy']);
  assert.deepEqual([...new Set(id.rejected.map((r) => r.reason))], ['cross_site']);
});

test('canonical pointing to an unrelated document (site root / parent listing) is rejected even when corroborated', () => {
  const root = resolveSourceIdentity({
    submittedUrl: 'https://v.example/blog/post-a',
    html: page({ canonical: 'https://v.example/', ogUrl: 'https://v.example/' })
  });
  assert.deepEqual(keysOf(root), ['url:https://v.example/blog/post-a']);
  assert.ok(root.rejected.every((r) => r.reason === 'root_path'));
  const listing = resolveSourceIdentity({
    submittedUrl: 'https://v.example/blog/post-a',
    html: page({ canonical: 'https://v.example/blog/', ogUrl: 'https://v.example/blog/' })
  });
  assert.deepEqual(keysOf(listing), ['url:https://v.example/blog/post-a']);
  assert.ok(listing.rejected.every((r) => r.reason === 'ancestor_of_document'));
});

test('canonical and og:url that disagree corroborate nothing', () => {
  const id = resolveSourceIdentity({
    submittedUrl: 'https://v.example/a/1',
    html: page({ canonical: 'https://v.example/a/2', ogUrl: 'https://v.example/a/3' })
  });
  assert.deepEqual(keysOf(id), ['url:https://v.example/a/1']);
  assert.equal(id.rejected.filter((r) => r.reason === 'uncorroborated').length, 2);
});

// --- Publisher article ids (WordPress) ----------------------------------------------

test('WordPress post id from REST alternate or shortlink; same post under two slugs shares the key', () => {
  const a = resolveSourceIdentity({ submittedUrl: 'https://v.example/blog/old-slug/', html: page({ shortlink: 'https://v.example/?p=4242' }) });
  const b = resolveSourceIdentity({ submittedUrl: 'https://v.example/blog/new-slug/', html: page({ wpRest: 'https://v.example/wp-json/wp/v2/posts/4242' }) });
  assert.ok(keysOf(a).includes('wp:v.example:4242'));
  assert.ok(shareKey(a, b));
});

test('similar paths with different publisher article ids stay different identities', () => {
  const a = resolveSourceIdentity({ submittedUrl: 'https://v.example/tr/campaign-x/121715/', html: page({ wpRest: 'https://v.example/wp-json/wp/v2/threat_response/121715' }) });
  const b = resolveSourceIdentity({ submittedUrl: 'https://v.example/tr/campaign-x/121716/', html: page({ wpRest: 'https://v.example/wp-json/wp/v2/threat_response/121716' }) });
  assert.equal(shareKey(a, b), false);
});

test('WordPress ids: subdirectory multisites, taxonomy routes, cross-site and conflicting ids', () => {
  const de = resolveSourceIdentity({ submittedUrl: 'https://v.example/de/post-x/', html: page({ wpRest: 'https://v.example/de/wp-json/wp/v2/posts/7' }) });
  const en = resolveSourceIdentity({ submittedUrl: 'https://v.example/post-y/', html: page({ wpRest: 'https://v.example/wp-json/wp/v2/posts/7' }) });
  assert.ok(keysOf(de).includes('wp:v.example/de:7'));
  assert.equal(shareKey(de, en), false, 'separate post-id spaces');

  const category = resolveSourceIdentity({ submittedUrl: 'https://v.example/category/apt/', html: page({ wpRest: 'https://v.example/wp-json/wp/v2/categories/12' }) });
  assert.ok(!keysOf(category).some((k) => k.startsWith('wp:')));
  assert.equal(category.rejected[0].reason, 'not_a_post_route');

  const cross = resolveSourceIdentity({ submittedUrl: 'https://mirror.example/x/', html: page({ wpRest: 'https://v.example/wp-json/wp/v2/posts/7' }) });
  assert.ok(!keysOf(cross).some((k) => k.startsWith('wp:')));

  const conflict = resolveSourceIdentity({
    submittedUrl: 'https://v.example/x/',
    html: page({ wpRest: 'https://v.example/wp-json/wp/v2/posts/7', shortlink: 'https://v.example/?p=8' })
  });
  assert.ok(!keysOf(conflict).some((k) => k.startsWith('wp:')));
  assert.equal(conflict.rejected.filter((r) => r.reason === 'conflicting_post_ids').length, 2);
});

// --- False positives: content-like signals are never identity -----------------------

test('identical titles, publication dates and IOC sets are not identity evidence', () => {
  // Two different articles whose pages are byte-identical except their URL.
  const html = '<html><head><title>APT-X targets energy</title><meta property="article:published_time" content="2026-11-02"></head><body>1.2.3.4 evil.example</body></html>';
  const a = resolveSourceIdentity({ submittedUrl: 'https://vendor-a.example/apt-x', html });
  const b = resolveSourceIdentity({ submittedUrl: 'https://vendor-b.example/apt-x-energy', html });
  const c = resolveSourceIdentity({ submittedUrl: 'https://vendor-a.example/apt-x-part-2', html });
  assert.equal(shareKey(a, b), false, 'different publishers, same incident');
  assert.equal(shareKey(a, c), false, 'same publisher, same campaign, different article');
});

test('signal extraction resolves relative hrefs, decodes entities and ignores #fragment JSON-LD ids', () => {
  const html = '<head><link rel="canonical" href="/research/a?x=1&amp;y=2"><script type="application/ld+json">{"@type":"Article","@id":"https://v.example/#article"}</script></head>';
  const s = extractPublisherIdentitySignals(html, 'https://v.example/research/a?x=1&y=2');
  assert.deepEqual(s.canonical, ['https://v.example/research/a?x=1&y=2']);
  assert.deepEqual(s.json_ld, []);
});
