import test from 'node:test';
import assert from 'node:assert/strict';
import { virusTotalGuiHref } from './virustotalGuiLink.js';

const VT_URL_ID = '08425c9691b5a3edb3235eb50ff3adee336a4cb024c71d266cb4621b1cabe1d5';

test('virusTotalGuiHref passes through a VirusTotal GUI permalink', () => {
  const href = virusTotalGuiHref({ permalink: `https://www.virustotal.com/gui/url/${VT_URL_ID}` });
  assert.equal(href, `https://www.virustotal.com/gui/url/${VT_URL_ID}`);
});

test('virusTotalGuiHref refuses an /api/v3 self-link (never rendered as a browser href)', () => {
  const href = virusTotalGuiHref({ permalink: `https://www.virustotal.com/api/v3/urls/${VT_URL_ID}` });
  assert.equal(href, null);
});

test('virusTotalGuiHref returns null for missing / non-string permalink', () => {
  assert.equal(virusTotalGuiHref(null), null);
  assert.equal(virusTotalGuiHref({}), null);
  assert.equal(virusTotalGuiHref({ permalink: null }), null);
  assert.equal(virusTotalGuiHref({ permalink: 42 }), null);
});

test('virusTotalGuiHref rejects a non-VirusTotal host', () => {
  assert.equal(virusTotalGuiHref({ permalink: 'https://evil.example.com/gui/url/x' }), null);
});
