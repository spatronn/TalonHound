/**
 * urlscan.io IOC-type eligibility on the real Intelligence tab. The panel JSX is
 * compiled with Vite's esbuild and rendered with react-dom/server; provider
 * cards are stubs that record whether they were mounted. The urlscan card is
 * the only frontend caller of the urlscan endpoints (asserted below), so a card
 * that is never mounted can never issue the cached GET or a refresh.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';

const here = fileURLToPath(new URL('.', import.meta.url));
const srcRoot = join(here, '..');

let mod;
let outDir;

test.before(async () => {
  const entry = `
    import React from 'react';
    import { renderToStaticMarkup } from 'react-dom/server';
    import { IntelligenceTabPanel, IntelligenceSummarySection } from ${JSON.stringify(join(srcRoot, 'intelligenceTab.jsx'))};
    import { AppConfirmContext, AppFeedbackContext } from ${JSON.stringify(join(srcRoot, 'lib/appChromeContext.jsx'))};
    export function renderPanel(props, mounted) {
      const stub = (key) => function StubCard() {
        mounted.push(key);
        return React.createElement('div', { 'data-provider-card': key });
      };
      const panel = React.createElement(IntelligenceTabPanel, {
        iocId: 42,
        active: true,
        canWrite: true,
        isAdmin: true,
        formatUserDateTime: (v) => String(v),
        isHashObservable: false,
        hasMeaningfulFileInfo: false,
        VirusTotalEnrichmentCard: stub('virustotal'),
        IpEnrichmentCard: stub('ipinfo'),
        AbuseIpdbEnrichmentCard: stub('abuseipdb'),
        UrlscanEnrichmentCard: stub('urlscan'),
        RdapEnrichmentCard: stub('rdap'),
        SpamhausDropEnrichmentCard: stub('spamhaus_drop'),
        ...props
      });
      const noop = async () => true;
      return renderToStaticMarkup(
        React.createElement(AppConfirmContext.Provider, { value: noop },
          React.createElement(AppFeedbackContext.Provider, { value: { notify: () => {} } }, panel))
      );
    }
    export const renderSummary = (props) => renderToStaticMarkup(React.createElement(IntelligenceSummarySection, props));
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
  outDir = mkdtempSync(join(tmpdir(), 'intel-urlscan-'));
  const file = join(outDir, 'bundle.mjs');
  writeFileSync(file, result.outputFiles[0].text);
  mod = await import(pathToFileURL(file).href);
});

test.after(() => {
  if (outDir) rmSync(outDir, { recursive: true, force: true });
});

const text = (html) => html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

function render(iocType, iocValue, extra = {}) {
  const mounted = [];
  const html = mod.renderPanel({ iocType, iocValue, ...extra }, mounted);
  const coverage = text(html).split('Provider coverage')[1]?.split('Analyst refs')[0] || '';
  return { mounted, html, coverage };
}

test('IP IOC (8.218.50.207): no urlscan card, no urlscan coverage entry, remaining cards still render', () => {
  const { mounted, html, coverage } = render('ip', '8.218.50.207');
  assert.deepEqual(mounted, ['virustotal', 'abuseipdb', 'ipinfo', 'spamhaus_drop']);
  assert.doesNotMatch(html, /data-provider-card="urlscan"/);
  assert.doesNotMatch(coverage, /urlscan/i);
  for (const label of ['VT', 'IPinfo', 'AbuseIPDB', 'Spamhaus']) assert.match(coverage, new RegExp(label));
});

test('IPv6 IOC: urlscan absent', () => {
  const { mounted, coverage } = render('ipv6', '2001:db8::1');
  assert.equal(mounted.includes('urlscan'), false);
  assert.doesNotMatch(coverage, /urlscan/i);
});

test('SHA256 IOC: urlscan absent from cards and coverage', () => {
  const sha = '8588d11874ab52a1637953dc5538984647023d00b529f695fbd0e40cf8e5e852';
  const { mounted, coverage } = render('sha256', sha, { isHashObservable: true });
  assert.deepEqual(mounted, ['virustotal']);
  assert.doesNotMatch(coverage, /urlscan/i);
});

test('domain IOC: urlscan card and coverage entry present', () => {
  const { mounted, coverage } = render('domain', 'example.org', { isRdapEligible: true });
  assert.deepEqual(mounted, ['virustotal', 'urlscan', 'rdap']);
  assert.match(coverage, /urlscan/);
});

test('URL IOC: urlscan card and coverage entry present', () => {
  const { mounted, coverage } = render('url', 'https://example.org/login');
  assert.ok(mounted.includes('urlscan'));
  assert.match(coverage, /urlscan/);
});

test('summary: a stale urlscan "not found" snapshot never surfaces for an IP IOC', () => {
  const snapshots = { virustotal: { status: 'success' }, urlscan: { status: 'not_found', assessment: 'no_results' } };
  const ip = text(mod.renderSummary({ providerSnapshots: snapshots, derivedProviderSnapshots: {}, iocType: 'ip' }));
  assert.doesNotMatch(ip, /urlscan/i);
  const domain = text(mod.renderSummary({ providerSnapshots: snapshots, derivedProviderSnapshots: {}, iocType: 'domain' }));
  assert.match(domain, /urlscan\s*:?\s*Not found/);
});

test('the urlscan card is the only frontend caller of the urlscan IOC endpoints', () => {
  const callers = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) { walk(full); continue; }
      if (!/\.(jsx?|tsx?)$/.test(name) || /\.test\.js$/.test(name)) continue;
      if (/\/enrichments\/urlscan/.test(readFileSync(full, 'utf8'))) callers.push(relative(srcRoot, full).replace(/\\/g, '/'));
    }
  };
  walk(srcRoot);
  assert.deepEqual(callers, ['components/UrlscanEnrichmentCard.jsx']);
});
