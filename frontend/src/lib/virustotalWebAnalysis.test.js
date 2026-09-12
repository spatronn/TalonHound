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
  WEB_ANALYSIS_UI_OUTGOING_PREVIEW
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
});
