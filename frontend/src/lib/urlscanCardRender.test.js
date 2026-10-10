/**
 * Render tests for the urlscan.io card UI. The JSX is compiled with the
 * esbuild that ships with Vite (no extra dependency) and rendered with
 * react-dom/server, so these assert the real markup: default disclosure
 * state, ARIA wiring, empty-section handling and data-derived content.
 * Click/keyboard behaviour is exercised in the browser harness.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { buildUrlscanView } from './urlscanScanView.js';

const here = fileURLToPath(new URL('.', import.meta.url));
const http403 = JSON.parse(readFileSync(new URL('./fixtures/urlscan-summary-http403.json', import.meta.url), 'utf8'));
const offDomain = JSON.parse(readFileSync(new URL('./fixtures/urlscan-summary-offdomain-redirect.json', import.meta.url), 'utf8'));
const clone = (o) => JSON.parse(JSON.stringify(o));

let mod;
let outDir;

test.before(async () => {
  const entry = `
    import React from 'react';
    import { renderToStaticMarkup } from 'react-dom/server';
    import Body, { DisclosureSection } from ${JSON.stringify(join(here, '../components/urlscan/UrlscanIntelligenceBody.jsx'))};
    import { UrlscanCardHeader } from ${JSON.stringify(join(here, '../components/UrlscanEnrichmentCard.jsx'))};
    export const renderBody = (props) => renderToStaticMarkup(React.createElement(Body, props));
    export const renderHeader = (props) => renderToStaticMarkup(React.createElement(UrlscanCardHeader, props));
    export const renderDisclosure = (props, child) => renderToStaticMarkup(React.createElement(DisclosureSection, props, child));
  `;
  const result = await build({
    stdin: { contents: entry, resolveDir: here, loader: 'jsx' },
    bundle: true,
    format: 'esm',
    platform: 'node',
    jsx: 'automatic',
    loader: { '.js': 'jsx' },
    write: false,
    logLevel: 'silent',
    // Bundled CommonJS deps (react-dom/server, axios) require Node builtins.
    banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" }
  });
  outDir = mkdtempSync(join(tmpdir(), 'urlscan-render-'));
  const file = join(outDir, 'bundle.mjs');
  writeFileSync(file, result.outputFiles[0].text);
  mod = await import(pathToFileURL(file).href);
});

test.after(() => {
  if (outDir) rmSync(outDir, { recursive: true, force: true });
});

const text = (html) => html.replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/\s+/g, ' ');

test('default view: conclusion, findings and page & hosting visible; technical evidence collapsed', () => {
  const html = mod.renderBody({ view: buildUrlscanView(http403) });
  const t = text(html);
  // Assessment
  assert.match(t, /Overall verdict Unclassified/);
  assert.match(t, /urlscan score 0 No verdict signal — not benign/);
  assert.match(t, /ML engine Malicious signal · 60/);
  assert.match(t, /Visibility Limited · HTTP 403/);
  // Findings, coverage first, with a non-colour cue for screen readers
  assert.ok(t.indexOf('Limited page visibility') < t.indexOf('Conflicting ML signal'));
  assert.match(t, /Caution: Limited page visibility/);
  assert.match(t, /2 technical observations · Self-issued TLS certificate · Long TLS validity period/);
  assert.doesNotMatch(t, /No urlscan classification/);
  // Page & hosting expanded
  assert.match(t, /Primary IP 45\.74\.61\.10/);
  assert.match(t, /ASN \/ Organization AS205397 · AS-69HOST 69HOST LLC, US/);
  // Collapsed sections: labelled triggers, hidden empty panels, no evidence rendered yet
  for (const [title, summary] of [
    ['Network activity', '2 requests · 1 IP · 1 domain · 2 HTTP errors'],
    ['TLS certificate', 'TLS 1.3 · Self-issued · 3650-day validity'],
    ['Related observables', '1 IP · 1 SHA256'],
    ['Scan history', '1 scan · latest 10/10/2026']
  ]) {
    assert.ok(t.includes(`${title} ${summary}`), `${title} summary`);
  }
  assert.equal((html.match(/aria-expanded="false"/g) || []).length, 5, '4 sections + technical observations collapsed');
  assert.doesNotMatch(t, /Valid until|HTTP errors \(4xx\/5xx\)|not a malware sample|Issuer blackhole/);
  assert.doesNotMatch(t, /Technologies/, 'empty technologies section is not rendered');
});

test('disclosure ARIA: trigger controls a labelled region; hidden when collapsed', () => {
  const closed = mod.renderDisclosure({ title: 'TLS certificate', summary: 'TLS 1.3' }, 'BODY');
  const id = closed.match(/aria-controls="([^"]+)"/)[1];
  const btnId = closed.match(/<button[^>]*id="([^"]+)"/)[1];
  assert.match(closed, new RegExp(`<div id="${id}" role="region" aria-labelledby="${btnId}" hidden=""`));
  assert.match(closed, /<button type="button"[^>]*aria-expanded="false"/);
  assert.doesNotMatch(closed, /BODY/);
  const open = mod.renderDisclosure({ title: 'TLS certificate', defaultOpen: true }, 'BODY');
  assert.match(open, /aria-expanded="true"/);
  assert.match(open, /BODY/);
  assert.doesNotMatch(open, /hidden=""/);
});

test('expanded evidence: network groups, TLS flags, related observables with provenance and copy labels, history', () => {
  const html = mod.renderBody({ view: buildUrlscanView(http403), defaultOpen: ['network', 'tls', 'related', 'history'] });
  const t = text(html);
  assert.match(t, /HTTP errors \(4xx\/5xx\) 2/);
  assert.match(t, /Response codes 403 ×2/);
  assert.match(t, /Issuer blackhole\.invalid Self-issued/);
  assert.match(t, /Validity period 3650 days Exceeds 398-day public CA limit/);
  assert.match(t, /Primary infrastructure IP 45\.74\.61\.10 .*Primary hosting IP · from page\.ip/);
  assert.match(t, /Response-body hashes SHA256 317123bb63824c1ec80c0dc9e19a4cfe02467432c055560b7dbb114414148909/);
  assert.match(t, /Primary HTTP response body — not a malware sample/);
  assert.match(html, /aria-label="Copy IP 45\.74\.61\.10"/);
  assert.match(html, /aria-label="Copy SHA256 317123bb/);
  assert.match(t, /Not added to TalonHound and not enriched automatically/);
  assert.match(t, /1 of 1 scan in the configured lookback window retrieved/);
  assert.match(html, /href="https:\/\/urlscan\.io\/result\/01a12594-300b-76cc-b97f-3b9e154c93fc\/" target="_blank" rel="noopener noreferrer" aria-label="Open urlscan\.io report for scan/);
});

test('multiple redirects, many related observables, technologies, and malicious verdict', () => {
  const s = clone(offDomain);
  s.detail_scans[0].redirects = [
    { from: 'http://a.example/', to: 'https://b.example/', status: 302 },
    { from: 'https://b.example/', to: 'https://quicksupport.fom.de/', status: 301 },
    { from: 'https://quicksupport.fom.de/', to: 'https://get.teamviewer.com/bcw-gruppe', status: 301 }
  ];
  s.classification = { state: 'malicious', label: 'Malicious', score: 100, categories: ['phishing'], brands: [] };
  s.detail_scans[0].verdicts.overall = { malicious: true, score: 100, has_verdicts: true, categories: ['phishing'], brands: [], tags: [] };
  const html = mod.renderBody({ view: buildUrlscanView(s), defaultOpen: ['network', 'related', 'technologies'] });
  const t = text(html);
  assert.equal((html.match(/<li[^>]*overflow-wrap:anywhere[^>]*>\s*<span[^>]*>30[12] /g) || []).length, 3, 'three redirect hops');
  for (const group of ['Primary infrastructure', 'Redirect infrastructure', 'Same-site resources', 'Third-party resources', 'Linked only (not contacted)', 'Response-body hashes', 'Downloads']) {
    assert.ok(t.includes(group), group);
  }
  assert.match(t, /Technologies 6 detected/);
  assert.match(t, /jQuery · JavaScript libraries/);
  assert.match(t, /Overall verdict Malicious/);
  assert.match(html, /inset 0 0 0 1px #7f1d1d/, 'malicious accent ring');
});

test('legacy v1 row: refresh note, no network/TLS/related sections', () => {
  const legacy = {
    scans: [{ scan_id: '01a12594-300b-76cc-b97f-3b9e154c93fc', page_title: '403 Forbidden', page_ip: '45.74.61.10', stats_requests: 2, scanned_at: '2026-10-10T11:30:37.899Z', match_relation: 'exact_url', exact_match: true }],
    detail_scans: [{ scan_id: '01a12594-300b-76cc-b97f-3b9e154c93fc', page_status: '403', page_asnname: 'AS-69HOST 69HOST LLC, US' }],
    ioc_category: 'url',
    evidence_assessment_label: 'No malicious evidence observed'
  };
  const t = text(mod.renderBody({ view: buildUrlscanView(legacy) }));
  assert.match(t, /Verdict detail not parsed/);
  assert.match(t, /Stored before detailed scan parsing\. Refresh to load/);
  assert.doesNotMatch(t, /Network activity|TLS certificate|Related observables/);
  assert.match(t, /Scan history/);
});

test('header: report link opens safely in a new tab; refresh shows busy state; no link without a result', () => {
  const html = mod.renderHeader({ canRefresh: true, refreshing: true, disabled: true, reportHref: 'https://urlscan.io/result/01a12594-300b-76cc-b97f-3b9e154c93fc/', onRefresh: () => {} });
  assert.match(html, /<a href="https:\/\/urlscan\.io\/result\/01a12594-300b-76cc-b97f-3b9e154c93fc\/" target="_blank" rel="noopener noreferrer"[^>]*aria-label="Open the urlscan\.io report for this scan \(opens in a new tab\)"/);
  assert.match(html, /<button type="button"[^>]*disabled=""[^>]*aria-busy="true"[^>]*>.*Refreshing…/);
  const idle = mod.renderHeader({ canRefresh: true, refreshing: false, disabled: false, reportHref: null, onRefresh: () => {} });
  assert.doesNotMatch(idle, /<a /);
  assert.match(text(idle), /Refresh/);
  assert.doesNotMatch(mod.renderHeader({ canRefresh: false, reportHref: null }), /<button/);
});

test('card delegates business rules to the view model (no duplicated state mapping in JSX)', () => {
  const card = readFileSync(new URL('../components/UrlscanEnrichmentCard.jsx', import.meta.url), 'utf8');
  assert.match(card, /urlscanPayloadState\(data\)/);
  assert.match(card, /urlscanRefreshErrorState\(/);
  assert.doesNotMatch(card, /status === 'api_key_missing'/);
  const body = readFileSync(new URL('../components/urlscan/UrlscanIntelligenceBody.jsx', import.meta.url), 'utf8');
  assert.doesNotMatch(body, /api\.(get|post)\(/, 'presentation component performs no requests');
});
