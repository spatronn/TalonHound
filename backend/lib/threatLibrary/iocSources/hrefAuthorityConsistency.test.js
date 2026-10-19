/**
 * href / authority consistency: destination-only external IOC anchors must be
 * discovered AND suppress delegated body authority through the same evidence.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { extractGenericArticleDocument } from '../extract/extractHtml.js';
import { annotateSectionTree } from '../sectionTree/annotate.js';
import { applySectionTreeAuthority } from '../sectionTree/authority.js';
import { extractCandidatesFromDocument } from '../candidateExtraction.js';
import { isReportIndicatorMember } from '../indicatorMembership.js';
import {
  discoverIocSourcesFromBlocks,
  discoverIocSourcesFromHtml
} from './discover.js';
import { blockIsExternalIocReference } from './externalIocReference.js';
import { collectHyperlinks, HTML_BLOCKS_VERSION } from '../extract/htmlBlocks.js';

const REPORT_URL = 'https://publisher.example/blog/campaign';
const PACK_URL = 'https://github.com/publisher/iocs/tree/main/campaign';

const HREF_ONLY_HTML = `<!doctype html><html><body><article>
  <p>The loader beacons to 198.51.100.40:443 during stage two.</p>
  <h2>Indicators of Compromise</h2>
  <p>Indicators of Compromise can be found
  <a href="${PACK_URL}">here</a>.</p>
  <h2>References</h2>
  <p><a href="https://github.com/research-lab/deobfuscator">Our toolkit</a> is public.</p>
</article></body></html>`;

const HREF_ONLY_WITH_INTERNAL = `<!doctype html><html><body><article>
  <p>Narrative mentions microsoft.com and archive-example.org.</p>
  <h2>Indicators of Compromise</h2>
  <p>Indicators of Compromise can be found
  <a href="${PACK_URL}">here</a>.</p>
  <ul><li>47.90.180.205</li><li>47.252.11.99</li></ul>
  <h2>Analysis</h2>
  <p>Operators also used fijothi[.]com as a backend.</p>
</article></body></html>`;

test('htmlBlocks v7 preserves destination-only href on the pointer paragraph', () => {
  assert.equal(HTML_BLOCKS_VERSION, 'threat_library_html_v8');
  const doc = extractGenericArticleDocument(HREF_ONLY_HTML, { url: REPORT_URL });
  const pointer = doc.blocks.find((b) => /can be found/i.test(b.text || ''));
  assert.ok(pointer, 'pointer paragraph present');
  assert.equal(/github\.com/i.test(pointer.text), false, 'canonical text has no destination URL');
  assert.ok(Array.isArray(pointer.links) && pointer.links.length >= 1, 'structured links preserved');
  assert.match(pointer.links[0].href, /github\.com\/publisher\/iocs\/tree\/main\/campaign/i);
  assert.match(pointer.links[0].text, /here/i);
});

test('href-only: discovery and authority agree on the same pack URL', () => {
  const doc = extractGenericArticleDocument(HREF_ONLY_HTML, { url: REPORT_URL });
  const fromHtml = discoverIocSourcesFromHtml(HREF_ONLY_HTML, { reportUrl: REPORT_URL });
  const fromBlocks = discoverIocSourcesFromBlocks(doc.blocks, { reportUrl: REPORT_URL });
  assert.ok(fromHtml.some((f) => /publisher\/iocs\/tree\/main\/campaign/i.test(f.canonical_url)));
  assert.ok(fromBlocks.some((f) => /publisher\/iocs\/tree\/main\/campaign/i.test(f.canonical_url)));
  assert.equal(
    fromHtml.some((f) => /research-lab\/deobfuscator/i.test(f.canonical_url)),
    false,
    'ordinary toolkit GitHub link is not discovered'
  );

  const tree = annotateSectionTree(doc);
  assert.equal(tree.meta.external_ioc_pointer, true);
  assert.equal(tree.meta.delegated_scope, false);
  const body = tree.blocks.find((b) => /198\.51\.100\.40/.test(b.text || ''));
  assert.ok(body);
  assert.notEqual(body.tree_zone, 'delegated_ioc_scope');
  assert.ok(
    tree.blocks.some((b) => blockIsExternalIocReference(b, { headingText: 'Indicators of Compromise', reportUrl: REPORT_URL }))
  );
});

test('href-only empty IOC section: narrative IP is not an original Indicator', () => {
  const doc = extractGenericArticleDocument(HREF_ONLY_HTML, { url: REPORT_URL });
  const extracted = extractCandidatesFromDocument(doc);
  const applied = applySectionTreeAuthority(doc, extracted);
  const members = applied.candidates.filter((c) => isReportIndicatorMember(c));
  assert.equal(
    members.some((c) => c.normalized_value === '198.51.100.40'),
    false,
    'body narrative IP must not become an Indicator via delegated scope'
  );
  assert.equal(applied.external_ioc_pointer, true);
  assert.equal(applied.delegated_scope, false);
});

test('href-only plus explicit internal IPs: internals stay Indicators, narrative stays out', () => {
  const doc = extractGenericArticleDocument(HREF_ONLY_WITH_INTERNAL, { url: REPORT_URL });
  const tree = annotateSectionTree(doc);
  assert.equal(tree.meta.external_ioc_pointer, true);
  // Inventory under IOC section → no delegated scope either way.
  assert.equal(tree.meta.delegated_scope, false);

  const extracted = extractCandidatesFromDocument(doc);
  const applied = applySectionTreeAuthority(doc, extracted);
  const members = applied.candidates.filter((c) => isReportIndicatorMember(c)).map((c) => `${c.candidate_type}:${c.normalized_value}`);
  assert.ok(members.includes('ip:47.90.180.205'), members.join(','));
  assert.ok(members.includes('ip:47.252.11.99'), members.join(','));
  assert.equal(members.some((m) => /fijothi|microsoft\.com|archive-example/.test(m)), false, members.join(','));
});

test('vague download-here without href still delegates (body may be the only assertions)', () => {
  const blocks = [
    { id: 'p0', type: 'paragraph', text: 'The loader beacons to 198.51.100.40:443.' },
    { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
    { id: 'p1', type: 'paragraph', text: 'These indicators are also available for download here.' }
  ];
  const tree = annotateSectionTree({ blocks, meta: { source_url: REPORT_URL } });
  assert.equal(tree.meta.external_ioc_pointer, false);
  assert.equal(tree.meta.delegated_scope, true);
});

test('directory discovery does not imply auto-attach; file-level identity stays distinct', () => {
  const dir = 'https://github.com/eSentire/iocs/tree/main/Tycoon2FA';
  const file = 'https://github.com/eSentire/iocs/blob/main/Tycoon2FA/Tycoon2fa-iocs-03-23-2026.txt';
  const html = `<html><body><article>
    <h2>Indicators of Compromise</h2>
    <p>Indicators of Compromise can be found <a href="${dir}">here</a>.</p>
  </article></body></html>`;
  const found = discoverIocSourcesFromHtml(html, {
    reportUrl: 'https://www.esentire.com/blog/tycoon-2fa-operators-adopt-oauth-device-code-phishing'
  });
  assert.equal(found.length, 1);
  assert.match(found[0].canonical_url, /\/tree\/main\/Tycoon2FA/i);
  assert.equal(found[0].discovery_method, 'auto');
  assert.notEqual(found[0].canonical_url, file, 'directory URL is not the manually attached file URL');
});

test('collectHyperlinks resolves relative pack paths against the report URL', async () => {
  const { parseHtml } = await import('../extract/htmlBlocks.js');
  const html = `<p>Download indicators: <a href="/research/ioc/campaign.csv">campaign.csv</a></p>`;
  const node = parseHtml(html);
  const links = collectHyperlinks(node, 'https://vendor.example/blog/post');
  assert.ok(links.some((l) => l.href === 'https://vendor.example/research/ioc/campaign.csv'));
});
