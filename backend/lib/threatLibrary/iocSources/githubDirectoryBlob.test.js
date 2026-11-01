/**
 * Talos posts link their IOC folder as a `/blob/` URL ending in "/"
 * ("The IOCs can also be found in our GitHub repository here" →
 * github.com/Cisco-Talos/IOCs/blob/main/2026/07/). Reports 35563 and 35573
 * got no linked IOC Source: the code-host "file must be a data pack" rule
 * rejected the extension-less path (tl-ioc-source-discovery-v4).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { discoverIocSourcesFromHtml } from './discover.js';
import { normalizeGitHubDirectoryUrl, parseGitHubUrl } from './github.js';
import { guessTypeFromUrl } from './sourceType.js';

const page = (href) => `<html><body><article>
<h2 id="indicators-of-compromise">Indicators of compromise</h2>
<p>The IOCs can also be found in our GitHub repository&nbsp;<a href="${href}" rel="noreferrer">here</a>.</p>
</article></body></html>`;

test('a /blob/ folder link is discovered as the tree folder (35563)', () => {
  const found = discoverIocSourcesFromHtml(page('https://github.com/Cisco-Talos/IOCs/blob/main/2026/07/'), {
    reportUrl: 'https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel/'
  });
  assert.equal(found.length, 1);
  assert.equal(found[0].canonical_url, 'https://github.com/Cisco-Talos/IOCs/tree/main/2026/07');
  assert.equal(found[0].source_type, 'github_dir');
});

test('the existing tree folder link is unchanged (35550)', () => {
  const found = discoverIocSourcesFromHtml(page('https://github.com/Cisco-Talos/IOCs/tree/main/2026/10'), {
    reportUrl: 'https://blog.talosintelligence.com/nik-c2-new-ai-enabled-framework/'
  });
  assert.equal(found.length, 1);
  assert.equal(found[0].canonical_url, 'https://github.com/Cisco-Talos/IOCs/tree/main/2026/10');
});

test('negative: a /blob/ link to a non-pack file is still rejected', () => {
  const found = discoverIocSourcesFromHtml(page('https://github.com/acme/tool/blob/main/src/main.go'), {
    reportUrl: 'https://blog.example.com/post/'
  });
  assert.equal(found.length, 0);
});

test('normalizeGitHubDirectoryUrl rewrites only folder-shaped blob URLs', () => {
  assert.equal(normalizeGitHubDirectoryUrl('https://github.com/o/r/blob/main/2026/02/'), 'https://github.com/o/r/tree/main/2026/02');
  assert.equal(normalizeGitHubDirectoryUrl('https://github.com/o/r/blob/main/2026/02/x.txt'), 'https://github.com/o/r/blob/main/2026/02/x.txt');
  assert.equal(normalizeGitHubDirectoryUrl('https://github.com/o/r/tree/main/2026/02/'), 'https://github.com/o/r/tree/main/2026/02/');
  assert.equal(normalizeGitHubDirectoryUrl('https://github.com/o/r/blob/main/'), 'https://github.com/o/r/blob/main/');
  assert.equal(guessTypeFromUrl(normalizeGitHubDirectoryUrl('https://github.com/o/r/blob/main/2026/02/')), 'github_dir');
  const p = parseGitHubUrl('https://github.com/o/r/blob/main/2026/02/');
  assert.equal(p.kind, 'dir');
  assert.equal(p.path, '2026/02');
});

test('raw refs/heads/<branch> URLs parse the branch as the ref (35554)', () => {
  const p = parseGitHubUrl('https://raw.githubusercontent.com/Cisco-Talos/IOCs/refs/heads/main/2026/09/clearfake-webdav-infection-chain.txt');
  assert.equal(p.kind, 'raw');
  assert.equal(p.ref, 'main');
  assert.equal(p.path, '2026/09/clearfake-webdav-infection-chain.txt');
  const plain = parseGitHubUrl('https://raw.githubusercontent.com/o/r/main/a/b.txt');
  assert.equal(plain.ref, 'main');
  assert.equal(plain.path, 'a/b.txt');
});
