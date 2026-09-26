/**
 * Explicit-table completeness diagnostics: asserted − created, not
 * survived-add() − created. Extraction eligibility is unchanged.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractCanonicalDocumentFromHtml } from './extract/extractHtml.js';
import { extractCandidatesWithDiagnostics, THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION } from './candidateExtraction.js';
import { compactExtractionDiagnostics } from './pipeline.js';
import { createExplicitTableAssertionTracker } from './explicitTableCompleteness.js';

const keyOf = (c) => `${c.candidate_type}:${c.normalized_value}`;

function extractFromHtml(html, url = 'https://vendor.example/research/completeness') {
  const r = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return extractCandidatesWithDiagnostics(r.document, { sourceUrl: url });
}

function iocTableHtml(rows, headers = ['Type', 'IOC', 'Note']) {
  const th = headers.map((h) => `<th>${h}</th>`).join('');
  const body = rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('\n');
  return `<html lang="en"><body><article>
<h2>Indicators of Compromise</h2>
<table><thead><tr>${th}</tr></thead><tbody>${body}</tbody></table>
</article></body></html>`;
}

function assertHealthyCompleteness(t, asserted, created) {
  assert.equal(t.values_asserted, asserted);
  assert.equal(t.candidates_created, created);
  assert.equal(t.explicit_identities, asserted);
  assert.deepEqual(t.missing_identities, []);
  assert.deepEqual(t.dropped_asserted_identities, []);
  assert.equal(t.inconsistent, false);
}

test('completeness contract is on tl-candidates-v10', () => {
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v10');
});

// ---------------------------------------------------------------------------
// Original blind spot, independent of the defanged-domain resolver fix
// ---------------------------------------------------------------------------

test('tracker: asserted identities that fail add() remain visible (25→14 style)', () => {
  const tracker = createExplicitTableAssertionTracker();
  const ips = ['203.0.113.10', '203.0.113.11', '203.0.113.12', '198.51.100.20', '198.51.100.21'];
  const urls = [
    'cdn.lab-example.com/js/a.js',
    'cdn.lab-example.com/js/b.js',
    'static-lab.example/js/c.js',
    'static-lab.example/js/d.js',
    'pay-lab.example/js/e.js',
    'pay-lab.example/js/f.js',
    'shop-lab.example/js/g.js',
    'js-lab.example/js/h.js',
    'js-lab.example/js/i.js'
  ];
  const domains = [
    'medbook-lab.example',
    'traffic-lab.example',
    'b8t-lab.example',
    'cdn-lab.example',
    'pay-lab.example',
    'static-lab.example',
    'cdn-js-lab.example',
    'js-static-lab.example',
    'jsnet-lab.example',
    'netlab-js.example',
    'news-lab.example'
  ];
  for (const ip of ips) tracker.rememberAsserted('ip', ip);
  for (const url of urls) tracker.rememberAsserted('url', url);
  for (const domain of domains) {
    tracker.rememberAsserted('domain', domain);
    tracker.rememberDropped('domain', domain, 'not_hostname_syntax');
  }
  const created = [
    ...ips.map((value) => ({ candidate_type: 'ip', normalized_value: value, table_rows: [{ explicit: true }] })),
    ...urls.map((value) => ({ candidate_type: 'url', normalized_value: value, table_rows: [{ explicit: true }] }))
  ];
  const result = tracker.finalize(created);
  assert.equal(result.explicit_identities, 25);
  assert.equal(result.candidates_created, 14);
  assert.equal(result.inconsistent, true);
  assert.equal(result.missing_identities.length, 11);
  assert.deepEqual(
    result.missing_identities.slice().sort(),
    domains.map((d) => `domain:${d}`).sort()
  );
  assert.equal(result.dropped_asserted_identities.length, 11);
  for (const dropped of result.dropped_asserted_identities) {
    assert.equal(dropped.type, 'domain');
    assert.equal(dropped.reason, 'not_hostname_syntax');
    assert.equal(domains.includes(dropped.value), true);
  }
});

test('tracker: asserted == created is complete', () => {
  const tracker = createExplicitTableAssertionTracker();
  tracker.rememberAsserted('ip', '203.0.113.77');
  tracker.rememberAsserted('domain', 'op-console.shop');
  const result = tracker.finalize([
    { candidate_type: 'ip', normalized_value: '203.0.113.77', table_rows: [{ explicit: true }] },
    { candidate_type: 'domain', normalized_value: 'op-console.shop', table_rows: [{ explicit: true }] }
  ]);
  assert.equal(result.explicit_identities, 2);
  assert.equal(result.candidates_created, 2);
  assert.deepEqual(result.missing_identities, []);
  assert.deepEqual(result.dropped_asserted_identities, []);
  assert.equal(result.inconsistent, false);
});

test('tracker: duplicate assertions collapse to one identity', () => {
  const tracker = createExplicitTableAssertionTracker();
  tracker.rememberAsserted('domain', 'op-console.shop');
  tracker.rememberAsserted('domain', 'op-console.shop');
  tracker.rememberDropped('domain', 'op-console.shop', 'not_hostname_syntax');
  tracker.rememberDropped('domain', 'op-console.shop', 'not_hostname_syntax');
  const result = tracker.finalize([]);
  assert.equal(result.explicit_identities, 1);
  assert.deepEqual(result.missing_identities, ['domain:op-console.shop']);
  assert.equal(result.dropped_asserted_identities.length, 1);
  assert.equal(result.inconsistent, true);
});

// ---------------------------------------------------------------------------
// Extract integration: existing validation can reject a table-asserted IOC
// ---------------------------------------------------------------------------

test('extract: table-asserted IP dropped by embedded_in_dns_hostname is inconsistent, not created', () => {
  const html = iocTableHtml(
    [
      ['IP', '203.0.113.77', ''],
      ['Domain', 'op-console[.]shop', ''],
      ['Domain', '128.200.178.68.host.example.net', '128.200.178.68']
    ],
    ['Type', 'Indicator', 'Indicator']
  );
  const { candidates, diagnostics } = extractFromHtml(html);
  const t = diagnostics.explicit_tables;
  const keys = new Set(candidates.filter((c) => c.is_ioc !== false).map(keyOf));

  assert.ok(keys.has('ip:203.0.113.77'));
  assert.ok(keys.has('domain:op-console.shop'));
  assert.ok(keys.has('domain:128.200.178.68.host.example.net'));
  assert.equal(keys.has('ip:128.200.178.68'), false, 'embedded IP prefix must not become a candidate');

  assert.equal(t.values_asserted >= 4, true, `values_asserted=${t.values_asserted}`);
  assert.equal(t.inconsistent, true);
  assert.equal(t.missing_identities.includes('ip:128.200.178.68'), true);
  const dropped = t.dropped_asserted_identities.find((d) => d.type === 'ip' && d.value === '128.200.178.68');
  assert.ok(dropped, 'dropped_asserted_identities must keep the rejected assertion');
  assert.equal(dropped.reason, 'embedded_in_dns_hostname');
  assert.equal(candidates.some((c) => c.candidate_type === 'ip' && c.normalized_value === '128.200.178.68'), false);

  const compact = compactExtractionDiagnostics(diagnostics);
  assert.equal(compact.explicit_tables.inconsistent, true);
  assert.equal(
    compact.explicit_tables.dropped_asserted_identities.some((d) => d.value === '128.200.178.68'),
    true
  );
});

test('extract: healthy typed table is complete', () => {
  const html = iocTableHtml([
    ['IP', '203.0.113.77', 'C2'],
    ['Domain', 'op-console[.]shop', 'Operator console'],
    ['URL', 'skimmer-cdn[.]shop/js/load.js', 'Skimmer URL']
  ]);
  const { candidates, diagnostics } = extractFromHtml(html);
  const t = diagnostics.explicit_tables;
  assertHealthyCompleteness(t, 3, 3);
  const keys = new Set(candidates.filter((c) => c.source_assertion === 'explicit_ioc').map(keyOf));
  assert.deepEqual([...keys].sort(), [
    'domain:op-console.shop',
    'ip:203.0.113.77',
    'url:skimmer-cdn.shop/js/load.js'
  ]);
});

test('extract: duplicate table rows do not create a false missing identity', () => {
  const html = iocTableHtml([
    ['Domain', 'op-console[.]shop', 'first'],
    ['Domain', 'op-console[.]shop', 'second'],
    ['IP', '203.0.113.77', 'C2']
  ]);
  const { candidates, diagnostics } = extractFromHtml(html);
  const t = diagnostics.explicit_tables;
  assert.equal(t.values_asserted, 3);
  assert.equal(t.explicit_identities, 2);
  assert.equal(t.candidates_created, 2);
  assert.deepEqual(t.missing_identities, []);
  assert.deepEqual(t.dropped_asserted_identities, []);
  assert.equal(t.inconsistent, false);
  assert.equal(candidates.filter((c) => c.candidate_type === 'domain' && c.normalized_value === 'op-console.shop').length, 1);
});

test('extract: defanged Domain row is complete as the refanged identity', () => {
  const html = iocTableHtml([['Domain', 'op-console[.]shop', 'Operator console']]);
  const { candidates, diagnostics } = extractFromHtml(html);
  assertHealthyCompleteness(diagnostics.explicit_tables, 1, 1);
  assert.equal(diagnostics.explicit_tables.missing_identities.includes('domain:op-console[.]shop'), false);
  const domain = candidates.find((c) => c.candidate_type === 'domain');
  assert.equal(domain.normalized_value, 'op-console.shop');
});

test('extract: Domain row and URL row stay distinct identities', () => {
  const html = iocTableHtml([
    ['Domain', 'skimmer-cdn[.]shop', 'Skimmer host'],
    ['URL', 'skimmer-cdn[.]shop/js/load.js', 'Skimmer URL']
  ]);
  const { candidates, diagnostics } = extractFromHtml(html);
  assertHealthyCompleteness(diagnostics.explicit_tables, 2, 2);
  const keys = new Set(candidates.filter((c) => c.source_assertion === 'explicit_ioc').map(keyOf));
  assert.equal(keys.has('domain:skimmer-cdn.shop'), true);
  assert.equal(keys.has('url:skimmer-cdn.shop/js/load.js'), true);
});

test('extract: deferred dotted Domain row that materializes is not reported dropped', () => {
  const html = iocTableHtml([
    ['Domain', 'op-console[.]shop', 'Operator console'],
    ['IP', '203.0.113.77', 'C2']
  ]);
  const { candidates, diagnostics } = extractFromHtml(html);
  assertHealthyCompleteness(diagnostics.explicit_tables, 2, 2);
  const domain = candidates.find((c) => c.normalized_value === 'op-console.shop');
  assert.equal(domain.candidate_type, 'domain');
  assert.equal(domain.source_assertion, 'explicit_ioc');
});

// ---------------------------------------------------------------------------
// Sanitized 25-identity explicit table (Gambit-shaped: 5 IP + 11 Domain + 9 URL)
// ---------------------------------------------------------------------------

const SANITIZED_25 = {
  ips: ['203.0.113.10', '203.0.113.11', '203.0.113.12', '198.51.100.20', '198.51.100.21'],
  domains: [
    'op-console.shop',
    'traffic-lab.example',
    'b8t-lab.shop',
    'cdn.netlfjs-lab.com',
    'x1opay-lab.co',
    'static-js-lab.com',
    'cdn.js-static-lab.com',
    'js-static-lab.com',
    'jsnetlify-lab.com',
    'netlifyjs-lab.com',
    'newssjs-lab.com'
  ],
  urls: [
    'b8t-lab.shop/js/sby.js',
    'cdn.netlfjs-lab.com/js/cts.js',
    'cdn.netlfjs-lab.com/js/vla.js',
    'x1opay-lab.co/js/eut.js',
    'x1opay-lab.co/js/l.js',
    'static-js-lab.com/js/bmws.js',
    'static-js-lab.com/js/nrt.js',
    'cdn.js-static-lab.com/js/tgo.js',
    'cdn.js-static-lab.com/js/pps.js'
  ]
};

test('extract: sanitized 25-row explicit table is complete (5 IP + 11 Domain + 9 URL)', () => {
  const rows = [
    ...SANITIZED_25.ips.map((ip) => ['IP', ip, 'C2']),
    ...SANITIZED_25.domains.map((d) => ['Domain', d.replace(/\./g, '[.]'), 'Skimmer host']),
    ...SANITIZED_25.urls.map((u) => ['URL', u.replace(/\./g, '[.]'), 'Skimmer URL'])
  ];
  assert.equal(rows.length, 25);
  const { candidates, diagnostics } = extractFromHtml(iocTableHtml(rows), 'https://vendor.example/research/skimmer-campaign');
  const t = diagnostics.explicit_tables;
  assertHealthyCompleteness(t, 25, 25);

  const explicit = candidates.filter((c) => c.source_assertion === 'explicit_ioc');
  const byType = { ip: 0, domain: 0, url: 0 };
  for (const c of explicit) byType[c.candidate_type] = (byType[c.candidate_type] || 0) + 1;
  assert.deepEqual(byType, { ip: 5, domain: 11, url: 9 });

  const keys = new Set(explicit.map(keyOf));
  for (const ip of SANITIZED_25.ips) assert.equal(keys.has(`ip:${ip}`), true, ip);
  for (const domain of SANITIZED_25.domains) assert.equal(keys.has(`domain:${domain}`), true, domain);
  for (const url of SANITIZED_25.urls) assert.equal(keys.has(`url:${url}`), true, url);

  assert.equal(
    candidates.some((c) => c.candidate_type === 'domain' && c.normalized_value === 'vendor.example' && c.assessment === 'malicious'),
    false,
    'publisher host is not promoted'
  );
  assert.equal(diagnostics.type_resolution.rejected_values.not_hostname_syntax, undefined);
});
