import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  hasUsefulWebAnalysis,
  formatBehaviorTagLabel,
  shortenContentSha256,
  formatHttpStatusLabel,
  formatContentLengthLabel,
  normalizeRedirectChainView,
  normalizeOutgoingLinksView,
  compactUrlForDisplay,
  WEB_ANALYSIS_UI_OUTGOING_PREVIEW,
  webAnalysisUntrustedUrlDisplay,
  isNonNavigableWebAnalysisUrlDisplay
} from './virustotalWebAnalysis.js';

describe('frontend virustotalWebAnalysis UI helpers', () => {
  test('hasUsefulWebAnalysis gates empty card', () => {
    assert.equal(hasUsefulWebAnalysis(null), false);
    assert.equal(hasUsefulWebAnalysis({}), false);
    assert.equal(hasUsefulWebAnalysis({ targeted_brand: { value: 'Allegro' } }), true);
  });

  test('behavior tag labels are user-friendly without changing machine value usage', () => {
    assert.equal(formatBehaviorTagLabel('password-input'), 'Password Input');
    assert.equal(formatBehaviorTagLabel('iframes'), 'Iframes');
  });

  test('content sha256 shortens for display', () => {
    const full = '235195e7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaacd04f3e1';
    assert.equal(shortenContentSha256(full), '235195e7…cd04f3e1');
  });

  test('HTTP / content-length labels', () => {
    assert.equal(formatHttpStatusLabel(200), '200 OK');
    assert.equal(formatHttpStatusLabel(418), '418');
    assert.equal(formatContentLengthLabel(764388), '746 KB');
  });

  test('outgoing links preview is bounded', () => {
    const links = {
      items: Array.from({ length: 20 }, (_, i) => `https://ex.invalid/${i}`),
      total_count: 34,
      truncated: true
    };
    const view = normalizeOutgoingLinksView(links);
    assert.equal(view.preview.length, WEB_ANALYSIS_UI_OUTGOING_PREVIEW);
    assert.equal(view.remaining, 34 - WEB_ANALYSIS_UI_OUTGOING_PREVIEW);
    assert.equal(view.truncated, true);
  });

  test('redirect chain accepts bounded object or array', () => {
    assert.deepEqual(
      normalizeRedirectChainView(['https://a', 'https://b']).items,
      ['https://a', 'https://b']
    );
    assert.equal(
      normalizeRedirectChainView({ items: ['https://a'], total_count: 3, truncated: true }).truncated,
      true
    );
  });

  test('long URLs compact for layout safety', () => {
    const long = 'https://example.invalid/very/long/path/with/query?x=' + 'a'.repeat(200);
    const shown = compactUrlForDisplay(long, 40);
    assert.ok(shown.length <= 40);
    assert.ok(shown.includes('…'));
  });

  test('redirect chain URLs render as non-navigable text (no href/anchor semantics)', () => {
    const malicious = 'http://62.60.226.140/files/payload/ZhMje1W.exe';
    const row = webAnalysisUntrustedUrlDisplay(malicious);
    assert.equal(row.element, 'span');
    assert.equal(row.href, null);
    assert.equal(row.onClick, null);
    assert.equal(row.role, null);
    assert.ok(isNonNavigableWebAnalysisUrlDisplay(row));
    assert.equal(row.title, malicious);
    assert.ok(row.text.includes('62.60.226.140'));
    assert.equal(row.style.cursor, 'text');
    assert.notEqual(row.style.color, '#93c5fd');
  });

  test('outgoing links URLs render as non-navigable text (no href/anchor semantics)', () => {
    const url = 'https://google.com/';
    const row = webAnalysisUntrustedUrlDisplay(url, { maxLen: 96 });
    assert.equal(row.element, 'span');
    assert.equal(row.href, null);
    assert.equal(row.onClick, null);
    assert.ok(isNonNavigableWebAnalysisUrlDisplay(row));
    assert.equal(row.title, url);
  });

  test('long malicious URL stays bounded and selectable without navigation hooks', () => {
    const long = 'http://62.60.226.140/files/' + 'a'.repeat(300) + '/ZhMje1W.exe';
    const row = webAnalysisUntrustedUrlDisplay(long, { maxLen: 72 });
    assert.ok(row.text.length <= 72);
    assert.equal(row.title, long);
    assert.equal(row.href, null);
    assert.equal(row.onClick, null);
    assert.equal(row.style.userSelect, 'text');
    assert.ok(isNonNavigableWebAnalysisUrlDisplay(row));
  });

  test('Open in VirusTotal remains an intentional navigable GUI link (separate helper)', async () => {
    // Regression guard: Web Analysis de-linking must not change VT GUI permalink helper.
    const { virusTotalGuiHref } = await import('./virustotalGuiLink.js');
    const href = virusTotalGuiHref({
      permalink: 'https://www.virustotal.com/gui/url/abc123'
    });
    assert.equal(href, 'https://www.virustotal.com/gui/url/abc123');
    assert.match(href, /^https:\/\/www\.virustotal\.com\/gui\//);
  });
});
