/**
 * Selective external IOC reference discovery.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  discoverIocSourcesFromHtml,
  discoverIocSourcesFromText,
  scoreIocSourceCandidate,
  EXTERNAL_IOC_POINTER_RE
} from './discover.js';
import { annotateSectionTree } from '../sectionTree/annotate.js';

const ESENTIRE_HTML = `<!doctype html><html><body><article>
  <h1>Tycoon 2FA Operators Adopt OAuth Device Code Phishing</h1>
  <p>The kit relays through microsoft.com/devicelogin and a Cloudflare worker.</p>
  <h2>Indicators of Compromise</h2>
  <p>Indicators of Compromise can be found <a href="https://github.com/eSentire/iocs/tree/main/Tycoon2FA">here</a>.</p>
  <ul>
    <li>Specific operator-side IPs observed: 47.90.180.205 and 47.252.11.99.</li>
  </ul>
  <h2>References</h2>
  <ul>
    <li>eSentire IOC repository - Tycoon 2FA - https://github.com/eSentire/iocs/tree/main/Tycoon2FA</li>
    <li>Microsoft Learn - https://learn.microsoft.com/en-us/entra/identity/</li>
  </ul>
  <nav><a href="https://github.com/eSentire">GitHub</a><a href="https://twitter.com/eSentire">Twitter</a></nav>
</article></body></html>`;

test('eSentire shape: destination-only "here" under IOC heading discovers the GitHub pack', () => {
  const found = discoverIocSourcesFromHtml(ESENTIRE_HTML, {
    reportUrl: 'https://www.esentire.com/blog/tycoon-2fa-operators-adopt-oauth-device-code-phishing'
  });
  assert.ok(found.length >= 1);
  assert.match(found[0].canonical_url, /github\.com\/esentire\/iocs\/tree\/main\/Tycoon2FA/i);
  assert.equal(found[0].discovery_method, 'auto');
  assert.equal(found[0].source_type, 'github_dir');
  assert.ok(found[0].discovery_evidence.matched_cues.length);
  assert.ok(
    found[0].discovery_evidence.matched_cues.includes('external_pointer') ||
      found[0].discovery_evidence.matched_cues.some((c) => /ioc|indicator/i.test(c))
  );
  // Nav GitHub org root and Microsoft Learn must not be sources.
  assert.equal(
    found.some((f) => /twitter\.com|learn\.microsoft|github\.com\/esentire\/?$/i.test(f.canonical_url)),
    false
  );
});

test('ordinary research / tooling GitHub links are not discovered', () => {
  const html = `<html><body><article>
    <h2>Analysis</h2>
    <p>Our toolkit is publicly available at <a href="https://github.com/research-lab/deobfuscator">https://github.com/research-lab/deobfuscator</a>.</p>
    <p>See also <a href="https://github.com/tool-author/disassembler">the disassembler</a>.</p>
    <footer><a href="https://github.com/vendor">GitHub</a></footer>
  </article></body></html>`;
  const found = discoverIocSourcesFromHtml(html, { reportUrl: 'https://vendor.example/blog/post' });
  assert.deepEqual(found, []);
});

test('direct CSV IOC reference with text cues is discovered', () => {
  const html = `<html><body><article>
    <h2>Indicators</h2>
    <p>Download indicators: <a href="https://vendor.example/research/ioc/warden.csv">warden.csv</a></p>
  </article></body></html>`;
  const found = discoverIocSourcesFromHtml(html, { reportUrl: 'https://vendor.example/blog/warden' });
  assert.equal(found.length, 1);
  assert.match(found[0].canonical_url, /warden\.csv/);
  assert.equal(found[0].source_type, 'csv');
});

test('Markdown table pack URL in text is discovered', () => {
  const text =
    'Full IOC list (Markdown): https://vendor.example/iocs/campaign-pack.md — Indicators of Compromise are published separately.';
  const found = discoverIocSourcesFromText(text, { reportUrl: 'https://vendor.example/report' });
  assert.ok(found.some((f) => /campaign-pack\.md/.test(f.canonical_url)));
});

test('bare github.com/ never scores without textual IOC evidence', () => {
  const bare = scoreIocSourceCandidate({
    href: 'https://github.com/vendor',
    linkText: 'GitHub',
    surrounding: 'Follow us on GitHub',
    headingText: '',
    reportHost: 'vendor.example'
  });
  assert.ok(bare.score < 4 || !bare.hasTextEvidence);

  const social = scoreIocSourceCandidate({
    href: 'https://github.com/',
    linkText: '',
    surrounding: '',
    headingText: '',
    reportHost: null
  });
  assert.equal(acceptable(social), false);
});

function acceptable(r) {
  return r.score >= 4 && r.hasTextEvidence;
}

test('EXTERNAL_IOC_POINTER_RE matches publisher pointer phrasing', () => {
  assert.equal(EXTERNAL_IOC_POINTER_RE.test('Indicators of Compromise can be found here.'), true);
  assert.equal(EXTERNAL_IOC_POINTER_RE.test('IOCs are available on GitHub'), true);
  assert.equal(EXTERNAL_IOC_POINTER_RE.test('The loader beacons to 1.2.3.4'), false);
});

test('pointer-only IOC section with external dataset cue does not delegate body authority', () => {
  const pointer = annotateSectionTree({
    blocks: [
      { id: 'p0', type: 'paragraph', text: 'The loader beacons to 198.51.100.40:443.' },
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
      {
        id: 'p1',
        type: 'paragraph',
        text: 'All observables are available for download in our GitHub repository: https://github.com/vendor-example/iocs'
      }
    ]
  });
  assert.equal(pointer.meta.external_ioc_pointer, true);
  assert.equal(pointer.meta.delegated_scope, false);
  assert.notEqual(pointer.blocks.find((b) => b.id === 'p0').tree_zone, 'delegated_ioc_scope');
});

test('genuine internal inventory plus external pointer keeps IOC-section authority without body delegation', () => {
  const both = annotateSectionTree({
    blocks: [
      { id: 'p0', type: 'paragraph', text: 'Narrative mentions microsoft.com.' },
      { id: 'h1', type: 'heading', level: 2, text: 'Indicators of compromise' },
      {
        id: 'p1',
        type: 'paragraph',
        text: 'Indicators of Compromise can be found here: https://github.com/vendor-example/iocs/tree/main/Pack'
      },
      { id: 'p2', type: 'paragraph', text: '47.90.180.205' }
    ]
  });
  assert.equal(both.meta.delegated_scope, false);
  assert.equal(both.blocks.find((b) => b.id === 'p2').authoritative_zone, 'explicit_ioc_section');
});

test('unavailable / malformed destination URLs are still discoverable as rows (fetch is later)', () => {
  const html = `<html><body><article>
    <h2>Indicators of Compromise</h2>
    <p>IOCs are available on GitHub: <a href="https://github.com/vendor/iocs/tree/main/MissingPack">repository</a>.</p>
  </article></body></html>`;
  const found = discoverIocSourcesFromHtml(html, { reportUrl: 'https://vendor.example/r' });
  assert.equal(found.length, 1);
  assert.match(found[0].canonical_url, /MissingPack/);
});
