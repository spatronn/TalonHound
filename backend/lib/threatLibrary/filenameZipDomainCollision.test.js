/**
 * Dual-use file/gTLD suffixes (`.zip`) must not become domains from an
 * inherited C2 / Domains label alone (tl-type-resolver-v27). `.zip` remains a
 * valid TLD when the publisher defangs the host, types a Domain table cell, or
 * writes a multi-label hostname.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import {
  OBSERVABLE_TYPE_RESOLVER_VERSION,
  resolveDottedToken
} from './observableTypeResolver.js';

const SOURCE = 'https://vendor-research.example/blog/filename-zip-collision/';

function extract(html) {
  const r = extractCanonicalDocumentFromHtml(html, { url: SOURCE, finalUrl: SOURCE, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return extractCandidatesWithDiagnostics(r.document, { sourceUrl: SOURCE }).candidates;
}

test('type resolver contract is tl-type-resolver-v27', () => {
  assert.equal(OBSERVABLE_TYPE_RESOLVER_VERSION, 'tl-type-resolver-v27');
});

test('positive: bare YEMPlayer.zip / Pis2rayVPN.zip under inherited C2 label stay artifacts', () => {
  for (const name of ['YEMPlayer.zip', 'Pis2rayVPN.zip', 'yemplayer.zip']) {
    const r = resolveDottedToken(name, {
      surroundingText: name,
      declaredType: 'domain',
      form: 'standalone',
      strongZone: true,
      zone: 'c2_section',
      indicatorRow: true,
      blockType: 'code'
    });
    assert.equal(r.kind, 'technical_artifact', name);
    assert.equal(r.reason, 'file_extension', name);
  }
});

test('positive: div-grid File Name | C2 sample table does not promote .zip basenames', () => {
  const html = `<html lang="en"><body><article>
<h2>Threat Analysis</h2>
<div class="table striped">
  <div><div><strong>SHA256 Hash</strong></div><div><strong>File Name</strong></div><div><strong>C2 Address</strong></div></div>
  <div>
    <div>${'a'.repeat(64)}</div>
    <div><code>YEMPlayer.zip</code></div>
    <div>203[.]0[.]113[.]10</div>
  </div>
  <div>
    <div>${'b'.repeat(64)}</div>
    <div><code>Pis2rayVPN.zip</code></div>
    <div>203[.]0[.]113[.]10</div>
  </div>
</div>
<h2>Indicators of Compromise</h2>
<p>yemplayer[.]site</p>
</article></body></html>`;
  const candidates = extract(html);
  const zip = candidates.filter((c) => /yemplayer\.zip|pis2rayvpn\.zip/i.test(String(c.normalized_value || '')));
  assert.equal(zip.length, 2, 'both archive basenames extracted');
  for (const c of zip) {
    assert.equal(c.candidate_type, 'technical_artifact', c.normalized_value);
    assert.equal(c.is_ioc, false, c.normalized_value);
  }
  const site = candidates.find((c) => c.candidate_type === 'domain' && c.normalized_value === 'yemplayer.site');
  assert.ok(site, 'real .site host stays a domain');
  assert.equal(site.is_ioc, true);
});

test('negative: defanged evil[.]zip under Domains stays a domain', () => {
  const r = resolveDottedToken('evil[.]zip', {
    surroundingText: 'evil[.]zip',
    declaredType: 'domain',
    form: 'list_row',
    strongZone: true,
    zone: 'explicit_ioc_section'
  });
  assert.equal(r.kind, 'domain');
  assert.equal(r.reason, 'declared_network_type');
});

test('negative: typed Domain table cell archive-sync.war stays a domain', () => {
  const r = resolveDottedToken('archive-sync.war', {
    surroundingText: 'archive-sync.war',
    typeLabel: 'Domain',
    declaredType: 'domain',
    form: 'table_row',
    strongZone: true
  });
  assert.equal(r.kind, 'domain');
  assert.equal(r.reason, 'declared_network_type');
});

test('negative: multi-label cdn.files.zip under Domains stays a domain', () => {
  const r = resolveDottedToken('cdn.files.zip', {
    surroundingText: 'cdn.files.zip',
    declaredType: 'domain',
    form: 'list_row',
    strongZone: true,
    zone: 'explicit_ioc_section'
  });
  assert.equal(r.kind, 'domain');
  assert.equal(r.reason, 'declared_network_type');
});

test('negative: typed Domain IOC table keeps defanged .zip hosts as Indicator domains', () => {
  // Publisher-typed Domain cells (not a bare "Domain: value" prose prefix) are
  // the authoritative .zip-TLD reading; the dual-use gate must not demote them.
  const html = `<html lang="en"><body><article>
<h2>Indicators of Compromise</h2>
<table>
<tr><th>Indicator</th><th>Type</th></tr>
<tr><td>evil[.]zip</td><td>Domain</td></tr>
<tr><td>cdn.payload[.]zip</td><td>Domain</td></tr>
</table>
</article></body></html>`;
  const candidates = extract(html);
  assert.ok(candidates.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'evil.zip' && c.is_ioc));
  assert.ok(candidates.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'cdn.payload.zip' && c.is_ioc));
});
