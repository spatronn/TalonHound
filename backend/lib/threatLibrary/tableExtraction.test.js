/**
 * Structured IOC tables across formats and languages (tl-table-v1 /
 * tl-candidates-v4 / threat_library_pdf_v3 / threat_library_html_v2).
 *
 * Fixture: real pdf.js geometry of the three IoC pages of a browser-printed
 * vendor report (Host Indicators / Network Indicators tables whose SHA256 cells
 * wrap onto a second line while Type / Description cells are vertically
 * centred). Expected set = 12 SHA256 + 2 IP + 2 IP:port explicit assertions.
 *
 * Nothing here is vendor-specific: the same tables are also rendered as
 * English HTML, Turkish HTML, HTML with unrecognisable headers, plain text and
 * Markdown, and must produce the identical normalized identity set.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pagesToBlocks, joinWrappedCellFragments, PDF_LAYOUT_VERSION } from './pdfLayout.js';
import { createCanonicalDocument, createTableBlock, flattenTableText } from './canonicalDocument.js';
import { extractCanonicalDocumentFromHtml, THREAT_LIBRARY_HTML_EXTRACTOR_VERSION } from './extract/extractHtml.js';
import { plainTextToCanonicalDocument } from './urlIngest.js';
import {
  extractCandidatesWithDiagnostics,
  extractCandidatesFromDocument,
  summarizeCandidateSet,
  THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION
} from './candidateExtraction.js';
import { interpretIocTable, parseDeclaredType, headerIntent, looksLikeIocTableHeader } from './tableSemantics.js';
import { annotateDocumentZones } from './documentZones.js';
import { mergeAiCandidateUpdates, decideCandidateReuse, isDocumentContractCurrent, mergeAnalysisProgress } from './pipeline.js';
import { partitionCandidatesForAi } from './ai/analyze.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { refangObservable } from './defang.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const pdfItems = JSON.parse(fs.readFileSync(path.join(here, 'fixtures', 'pivotc2-ioc-tables-pdf-items.json'), 'utf8'));
const expected = JSON.parse(fs.readFileSync(path.join(here, 'fixtures', 'pivotc2-ioc-tables-expected.json'), 'utf8'));

const expectedKeys = new Set([
  ...expected.sha256.map((h) => `sha256:${h}`),
  ...expected.ip.map((ip) => `ip:${ip}`),
  ...expected.ip_port.map((e) => `ip:${e.ip}`)
]);

const keyOf = (c) => `${c.candidate_type}:${c.normalized_value}`;

/** Explicit, deterministic IOC identities of a candidate set. */
function explicitSet(candidates) {
  return new Set(
    candidates
      .filter((c) => c.is_ioc !== false && (c.source_assertion === 'explicit_ioc' || c.source_assertion === 'explicit_c2'))
      .map(keyOf)
  );
}

function assertSetEquality(actual, wanted, label) {
  const missing = [...wanted].filter((k) => !actual.has(k));
  const extra = [...actual].filter((k) => !wanted.has(k));
  assert.deepEqual({ missing, extra }, { missing: [], extra: [] }, `${label}: set diff`);
}

/** The 16 rows as (type, indicator, description) triples — shared by every rendering below. */
const HOST_ROWS = [
  ['SHA256', '2d338ffc8cc80293575c6800c059e33eb41e967907c20ba7687b2231c50837db', 'fortirun.bin – CVE-2025-25249 exploit'],
  ['SHA256', 'cc7f0660d56405cbdff157033d3e35305f063e62efaff6501d11e6a34e7bd151', 'payload.js – PivotC2 stager'],
  ['SHA256', 'eb4d8aab4e687839c5478a7a3819b0a7a857555ed50fc159c026e99764a0c8a0', 'payload2.js – PivotC2 stager'],
  ['SHA256', 'fe7da807a2b37a2bbd8c27830a9acc0d86ad8128f38489c493873c7e410c0408', 'payload_new.js – PivotC2 stager'],
  ['SHA256', 'd99fa14f5e7dfe17e437f167f3f9550ebeda496960710dde81d41748bd7749e4', 'PivotC2 client (decoded) on 46.151.29[.]58:8443'],
  ['SHA256', '005e6014fb8fd47249691756f5af3b3d53bfae82df88a71277e53e13fe94cb9f', 'PivotC2 client (encoded) on 46.151.29[.]58:8443'],
  ['SHA256', '550f99193f9e90d93b70af1ab050a2d44f1830259ea165568dafc518e761c589', 'PivotC2 client (decoded) on 146.103.99[.]177:8443'],
  ['SHA256', '08fa6abac9c132deff4f120a7fcfe5bf17c797b87dbbc3f261d5cf0c077c0a2e', 'PivotC2 client (encoded) on 146.103.99[.]177:8443'],
  ['SHA256', 'a9bea5f89984d47dd60216b0a0b064e8c7e8057e0c10509faa4a2d8d641eb73b', 'PivotC2 client (decoded) on 146.103.99[.]177:9443'],
  ['SHA256', '1bf2c5976f2abbe147ae7be140ed69af2c25092f563786400aecd0231229be19', 'PivotC2 client (encoded) on 146.103.99[.]177:8443'],
  ['SHA256', 'c25a27b506fbae62010caf2abff699df5c94d29f056fa7ccfb5f3170d917c8cb', 'run.ps1 – Process injection script'],
  ['SHA256', 'd4911736986cf8affb29106fb8e8b74e00e52d5f762dce9025f2cfe431cf2140', 'payload.b64 – Injected payload']
];
const NETWORK_ROWS = [
  ['IP Address', '46[.]151[.]29[.]58', 'PivotC2 Node'],
  ['IP Address', '146[.]103[.]99[.]177', 'PivotC2 Node'],
  ['IP Address & Port', '45[.]138[.]16[.]182:9130', 'obfs4proxy TOR Bridge'],
  ['IP Address & Port', '89[.]217[.]174[.]207:9001', 'obfs4proxy TOR Bridge']
];

function htmlTable(headers, rows) {
  const th = headers.map((h) => `<th>${h}</th>`).join('');
  const body = rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('\n');
  return `<table><thead><tr>${th}</tr></thead><tbody>${body}</tbody></table>`;
}

function articleHtml({ lang, headings, headers, hostRows, networkRows, extra = '' }) {
  return `<html lang="${lang}"><head><title>${headings.title}</title></head><body>
<header><nav><a href="https://vendor.example/">Home</a><a href="https://vendor.example/blog/">Blog</a></nav></header>
<article>
<h1>${headings.title}</h1>
<p>${headings.intro} https://fortiguard.example/psirt/FG-IR-25-000 and https://attack.mitre.org/techniques/T1190/.</p>
<pre>diagnose sys session filter daddr 46.151.29.58</pre>
<p>${headings.mitigation} https://docs.vendor.example/hardening. Internal ranges such as 10.0.0.0/24 and 192.168.1.0/24 were scanned.</p>
${extra}
<h2>${headings.iocs}</h2>
<h3>${headings.host}</h3>
${htmlTable(headers, hostRows)}
<h3>${headings.network}</h3>
${htmlTable(headers, networkRows)}
<h2>${headings.references}</h2>
<ul><li>https://www.fortinet.example/blog/psirt-blogs/analysis</li><li>https://socradar.example/blog/cve-2025-25249-pivotc2-fortigate-rat/</li></ul>
<p>Permalink: https://socradar.example/blog/cve-2025-25249-pivotc2-fortigate-rat/</p>
</article>
<footer>© 2026 vendor</footer></body></html>`;
}

const EN = {
  title: 'CVE-2025-25249 exploitation delivers a FortiGate post-exploitation RAT',
  intro: 'The initial stager downloads hxxps[://]146[.]103[.]99[.]177:8443/0c5b767095 as described in',
  mitigation: 'Apply the patch and follow the',
  iocs: 'IoCs',
  host: 'Host Indicators',
  network: 'Network Indicators',
  references: 'References'
};

function extractFromHtml(html, url = 'https://socradar.example/blog/cve-2025-25249-pivotc2-fortigate-rat/') {
  const r = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
  assert.equal(r.ok, true, `extraction failed: ${r.code}`);
  return extractCandidatesWithDiagnostics(r.document, { sourceUrl: url });
}

// ---------------------------------------------------------------------------
// Contract versions
// ---------------------------------------------------------------------------

test('internal contracts bumped for structured table extraction (product VERSION untouched)', () => {
  assert.equal(PDF_LAYOUT_VERSION, 'threat_library_pdf_v3');
  assert.equal(THREAT_LIBRARY_HTML_EXTRACTOR_VERSION, 'threat_library_html_v2');
  assert.equal(THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, 'tl-candidates-v10');
  const version = fs.readFileSync(path.join(here, '..', '..', '..', 'VERSION'), 'utf8').trim();
  assert.equal(version, '0.1.1-beta.11');
});

// ---------------------------------------------------------------------------
// PDF geometry → canonical tables
// ---------------------------------------------------------------------------

test('PDF: wrapped hash cells and centred type/description cells reconstruct as complete table rows', () => {
  const { blocks } = pagesToBlocks(pdfItems);
  const tables = blocks.filter((b) => b.type === 'table');
  assert.equal(tables.length, 4, 'host table (2 pages) + network table (2 pages)');
  for (const t of tables) {
    assert.deepEqual(t.table.headers, ['Type', 'Indicator', 'Description'], `${t.id} header row by typography`);
    for (const row of t.table.rows) assert.equal(row.length, 3, `${t.id} row width`);
  }
  const rows = tables.flatMap((t) => t.table.rows);
  assert.equal(rows.length, 16);
  const hashes = rows.filter((r) => r[0] === 'SHA256').map((r) => r[1]);
  assert.deepEqual(hashes, expected.sha256, 'every SHA256 whole, in source order');
  assert.ok(hashes.includes('005e6014fb8fd47249691756f5af3b3d53bfae82df88a71277e53e13fe94cb9f'), 'leading zeros preserved');
  for (const h of hashes) assert.equal(typeof h, 'string');
  // No hex fragment leaked into a heading / paragraph block
  const fragments = blocks.filter((b) => b.type !== 'table' && /^[a-f0-9]{6,20}$/i.test(b.text));
  assert.deepEqual(fragments.map((b) => b.text), []);
  // Description cells keep their text; indicator cells never absorb it
  const decoded = rows.find((r) => r[1].startsWith('d99fa14f'));
  assert.equal(decoded[2], 'PivotC2 client (decoded) on 46.151.29[.]58:8443');
  const networkRows = rows.filter((r) => /^IP Address/.test(r[0]));
  assert.deepEqual(networkRows, NETWORK_ROWS);
  // Repeated marketing banner and page edges never became table rows
  assert.equal(rows.some((r) => r.some((c) => /Dark Web|Scan for Leaks/.test(c))), false);
  assert.ok(blocks.some((b) => b.layout === 'page_edge' && /socradar\.io/.test(b.text)), 'footer URL kept as page-edge block');
});

test('PDF: row integrity — no cross-row contamination between type / indicator / description', () => {
  const { blocks } = pagesToBlocks(pdfItems);
  const rows = blocks.filter((b) => b.type === 'table').flatMap((t) => t.table.rows);
  const byHash = new Map(HOST_ROWS.map((r) => [r[1], r]));
  for (const r of rows) {
    if (r[0] !== 'SHA256') continue;
    const want = byHash.get(r[1]);
    assert.ok(want, `unexpected hash row ${r[1]}`);
    assert.deepEqual(r, want);
  }
});

test('wrapped cell fragments: hex runs and URL paths re-join without a space, prose with one', () => {
  assert.equal(joinWrappedCellFragments(['2d338ffc8cc80293575c6800c059e33eb41e967907c20ba7687', 'b2231c50837db']), '2d338ffc8cc80293575c6800c059e33eb41e967907c20ba7687b2231c50837db');
  assert.equal(joinWrappedCellFragments(['005e6014fb8fd47249691756f5af3b3d53bfae82df88a71277e53', 'e13fe94cb9f']), '005e6014fb8fd47249691756f5af3b3d53bfae82df88a71277e53e13fe94cb9f');
  assert.equal(joinWrappedCellFragments(['https://evil.example/path/', 'payload.bin']), 'https://evil.example/path/payload.bin');
  assert.equal(joinWrappedCellFragments(['PivotC2 client (decoded) on', '46.151.29[.]58:8443']), 'PivotC2 client (decoded) on 46.151.29[.]58:8443');
  assert.equal(joinWrappedCellFragments(['obfs4proxy', 'TOR Bridge']), 'obfs4proxy TOR Bridge');
});

// ---------------------------------------------------------------------------
// Exact set equality across formats
// ---------------------------------------------------------------------------

test('PDF fixture: explicit IOC set equals the 16 source assertions exactly', () => {
  const { blocks } = pagesToBlocks(pdfItems);
  const doc = createCanonicalDocument({ title: 'fixture', blocks, meta: { extractor: PDF_LAYOUT_VERSION, adapter: 'pdf' } });
  const { candidates, diagnostics } = extractCandidatesWithDiagnostics(doc);
  assertSetEquality(explicitSet(candidates), expectedKeys, 'pdf');

  const t = diagnostics.explicit_tables;
  assert.equal(t.explicit_tables, 4);
  assert.equal(t.rows_seen, 16);
  assert.equal(t.rows_valid, 16);
  assert.equal(t.rows_rejected, 0);
  assert.equal(t.candidates_created, 16);
  assert.equal(t.explicit_identities, 16);
  assert.equal(t.inconsistent, false);
  assert.deepEqual(t.missing_identities, []);
  assert.deepEqual(t.dropped_asserted_identities, []);

  // Every explicit row is resolved deterministically — no AI needed to rediscover it
  const explicit = candidates.filter((c) => expectedKeys.has(keyOf(c)));
  assert.equal(explicit.length, 16);
  for (const c of explicit) {
    assert.equal(c.assessment, 'malicious', keyOf(c));
    assert.equal(c.ai_needed, false, keyOf(c));
    assert.equal(c.decision_source, 'deterministic', keyOf(c));
    assert.equal(c.evidence_tier, 'A', keyOf(c));
    assert.ok(Array.isArray(c.table_rows) && c.table_rows.length >= 1, `${keyOf(c)} carries row provenance`);
    assert.ok(c.table_rows[0].table_id && Number.isInteger(c.table_rows[0].row_index), keyOf(c));
    assert.ok(c.table_rows[0].description, `${keyOf(c)} keeps its description`);
  }
  const summary = summarizeCandidateSet(candidates);
  assert.equal(summary.explicit_assertions, 16);
  assert.equal(summary.table_assertions, 16);
  assert.equal(summary.ai_needed, 0, 'no AI-needed candidate on the IoC pages');

  // Duplicate descriptions never collapse distinct hashes
  const decodedEncoded = candidates.filter((c) => c.table_rows?.[0]?.description?.startsWith('PivotC2 client'));
  assert.equal(decodedEncoded.length, 6);

  // IP:port rows: IP identity + port provenance, faithful source spelling, no fake URL/domain
  const bridge = candidates.find((c) => c.normalized_value === '45.138.16.182');
  assert.equal(bridge.candidate_type, 'ip');
  assert.deepEqual(bridge.parsed.ports, [9130]);
  assert.equal(bridge.original_value, '45[.]138[.]16[.]182:9130');
  assert.equal(bridge.source_assertion, 'explicit_c2');
  assert.equal(bridge.table_rows[0].declared_type, 'ip');
  assert.equal(bridge.table_rows[0].type_cell, 'IP Address & Port');
  assert.equal(candidates.some((c) => c.candidate_type === 'url' && /45\.138\.16\.182/.test(c.normalized_value)), false);
  assert.equal(candidates.some((c) => c.candidate_type === 'domain'), false);

  // Description-contained endpoints do not create extra assertions: the node IPs
  // come only from their own Network Indicators rows (one table row each), and
  // 8443 / 9443 are related metadata of the hash rows, not ports of the IP.
  const node1 = candidates.find((c) => c.normalized_value === '46.151.29.58');
  assert.equal(node1.table_rows.length, 1);
  assert.equal(node1.table_rows[0].type_cell, 'IP Address');
  assert.equal(node1.parsed.ports, undefined);
  const node2 = candidates.find((c) => c.normalized_value === '146.103.99.177');
  assert.equal(node2.table_rows.length, 1);
  assert.equal(node2.parsed.ports, undefined);
  const encodedRow = candidates.find((c) => c.normalized_value.startsWith('005e6014'));
  assert.deepEqual(encodedRow.table_rows[0].related_values, ['46.151.29.58:8443']);

  // The report's own URL (page footer) is provenance, never a finding
  const src = candidates.find((c) => c.candidate_type === 'url' && c.normalized_value === expected.source_url);
  assert.ok(src, 'footer URL is extracted');
  assert.equal(src.assessment, 'context_only');
  assert.notEqual(src.source_assertion, 'explicit_ioc');
});

test('English HTML: DOM tables give the identical explicit set; nav / advisory / MITRE / source links are not IOCs', () => {
  const html = articleHtml({ lang: 'en', headings: EN, headers: ['Type', 'Indicator', 'Description'], hostRows: HOST_ROWS, networkRows: NETWORK_ROWS });
  const { candidates, diagnostics } = extractFromHtml(html);
  assertSetEquality(explicitSet(candidates), expectedKeys, 'html-en');
  assert.equal(diagnostics.explicit_tables.explicit_tables, 2);
  assert.equal(diagnostics.explicit_tables.rows_valid, 16);
  assert.equal(diagnostics.explicit_tables.inconsistent, false);
  assert.deepEqual(diagnostics.explicit_tables.missing_identities, []);
  assert.deepEqual(diagnostics.explicit_tables.dropped_asserted_identities, []);

  const urls = candidates.filter((c) => c.candidate_type === 'url');
  for (const u of urls) {
    assert.notEqual(u.source_assertion, 'explicit_ioc', `${u.normalized_value} must not be an explicit IOC`);
    assert.notEqual(u.assessment, 'malicious', u.normalized_value);
  }
  const own = candidates.find((c) => c.candidate_type === 'url' && /socradar\.example/.test(c.normalized_value));
  assert.equal(own.assessment, 'context_only');
  assert.equal(own.is_report_source, true);
  // RFC1918 example ranges are context-only without AI; hunting command IP aggregates onto the explicit candidate
  const rfc = candidates.find((c) => c.normalized_value === '10.0.0.0/24' || c.normalized_value === '10.0.0.0');
  assert.ok(rfc, 'private example range extracted');
  assert.equal(rfc.assessment, 'context_only');
  assert.equal(rfc.ai_needed, false);
  assert.equal(rfc.reserved_address, true);
  assert.ok(
    rfc.policy_decision === 'context_only_reserved_address' || rfc.policy_decision === 'context_only_narrative_with_authoritative_scope'
  );
  const node1 = candidates.find((c) => c.normalized_value === '46.151.29.58');
  assert.ok(node1.occurrences.some((o) => o.form === 'table_row'));
  assert.ok(node1.occurrences.some((o) => o.block_type === 'code'), 'hunting command occurrence aggregated');
  assert.equal(node1.assessment, 'malicious');
  assert.equal(node1.ai_needed, false);
  // Domains of reference links are only URL host metadata (never standalone candidates)
  assert.equal(candidates.some((c) => c.candidate_type === 'domain' && /attack\.mitre|fortiguard|docs\.vendor/.test(c.normalized_value)), false);
});

test('Turkish HTML headers (Tür | Gösterge | Açıklama) with Turkish type labels are interpreted by intent', () => {
  const tr = { ...EN, iocs: 'Uzlaşma Göstergeleri', host: 'Dosya Göstergeleri', network: 'Ağ Göstergeleri', references: 'Kaynaklar' };
  const hostRows = HOST_ROWS.map((r) => ['SHA256 Özeti', r[1], r[2]]);
  const networkRows = NETWORK_ROWS.map((r) => [r[0] === 'IP Address' ? 'IP Adresi' : 'IP Adresi ve Port', r[1], r[2]]);
  const html = articleHtml({ lang: 'tr', headings: tr, headers: ['Tür', 'Gösterge', 'Açıklama'], hostRows, networkRows });
  const { candidates, diagnostics } = extractFromHtml(html);
  assertSetEquality(explicitSet(candidates), expectedKeys, 'html-tr');
  assert.equal(diagnostics.explicit_tables.rows_valid, 16);
  const bridge = candidates.find((c) => c.normalized_value === '89.217.174.207');
  assert.deepEqual(bridge.parsed.ports, [9001]);
  assert.equal(bridge.table_rows[0].declared_type, 'ip');
});

test('unknown-language headers: row structure and type-cell syntax alone prove the table', () => {
  const xx = { ...EN, iocs: 'Ⴀ ᲠᲐ Ⴄ', host: 'ᲰᲝᲡᲢ', network: 'ᲥᲡᲔᲚᲘ', references: 'ᲬᲧᲐᲠᲝᲔᲑᲘ' };
  const html = articleHtml({ lang: 'ka', headings: xx, headers: ['ᲢᲘᲞᲘ', 'ᲛᲐᲩᲕᲔᲜᲔᲑᲔᲚᲘ', 'ᲐᲦᲬᲔᲠᲐ'], hostRows: HOST_ROWS, networkRows: NETWORK_ROWS });
  const { candidates, diagnostics } = extractFromHtml(html);
  assertSetEquality(explicitSet(candidates), expectedKeys, 'html-unknown-language');
  const table = diagnostics.explicit_tables.tables.find((t) => t.kind === 'ioc_table');
  assert.ok(table.columns.some((c) => c.intent === 'type' && c.method === 'content'));
  assert.ok(table.columns.some((c) => c.intent === 'indicator' && c.method === 'content'));
});

test('HTML cells split across inline tags / <wbr> / entities still yield whole values', () => {
  const rows = [
    ['<b>SHA256</b>', '<code>005e6014fb8fd47249691756f5af3b3d<wbr>53bfae82df88a71277e53e13fe94cb9f</code>', 'PivotC2 client &ndash; encoded'],
    ['IP&nbsp;Address &amp; Port', '<span>45[.]138</span><span>[.]16[.]182</span>:9130', 'obfs4proxy TOR Bridge']
  ];
  const html = `<html><body><article><h2>Indicators of Compromise</h2>${htmlTable(['Type', 'Indicator', 'Description'], rows)}</article></body></html>`;
  const { candidates } = extractFromHtml(html);
  const keys = explicitSet(candidates);
  assert.ok(keys.has('sha256:005e6014fb8fd47249691756f5af3b3d53bfae82df88a71277e53e13fe94cb9f'));
  assert.ok(keys.has('ip:45.138.16.182'));
  assert.deepEqual(candidates.find((c) => c.normalized_value === '45.138.16.182').parsed.ports, [9130]);
});

test('plain text: Markdown pipe table and tab-aligned rows are explicit IOC tables', () => {
  const md = [
    '## Indicators', '',
    '| Type | Indicator | Description |', '|---|---|---|',
    ...HOST_ROWS.map((r) => `| ${r[0]} | ${r[1]} | ${r[2]} |`)
  ].join('\n');
  const aligned = ['Network', '', 'Type\tIndicator\tDescription', ...NETWORK_ROWS.map((r) => r.join('\t'))].join('\n');
  const doc = plainTextToCanonicalDocument(`Intro paragraph.\n\n${md}\n\n${aligned}\n`, { title: 't' });
  assert.equal(doc.blocks.filter((b) => b.type === 'table').length, 2);
  const { candidates, diagnostics } = extractCandidatesWithDiagnostics(doc);
  assertSetEquality(explicitSet(candidates), expectedKeys, 'plain-text');
  assert.equal(diagnostics.explicit_tables.rows_valid, 16);
});

// ---------------------------------------------------------------------------
// Table interpreter semantics
// ---------------------------------------------------------------------------

test('table interpreter: declared type is a hint validated against value syntax; mismatch is flagged, not silently retyped', () => {
  const block = createTableBlock({
    id: 't', headers: ['Type', 'Indicator', 'Description'],
    rows: [
      ['SHA256', 'd41d8cd98f00b204e9800998ecf8427e', 'md5 mislabelled as sha256'],
      ['Domain', 'update-check.example-cdn.net', 'declared domain'],
      ['Domain', 'payload.js', 'declared domain but filename shape → accepted because source declared it'],
      ['E-mail', 'actor@mail.example', 'unsupported type'],
      ['SHA256', '', 'empty indicator'],
      ['Version', '7.4.8', 'not an observable']
    ]
  });
  const r = interpretIocTable(block);
  assert.equal(r.kind, 'ioc_table');
  assert.equal(r.explicit, true);
  const rows = r.rows;
  assert.equal(rows[0].status, 'valid');
  assert.equal(rows[0].values[0].candidate_type, 'md5');
  assert.equal(rows[0].values[0].declared_type_mismatch, true);
  assert.equal(rows[1].values[0].candidate_type, 'domain');
  assert.equal(rows[2].status, 'valid', 'declared hostname overrides the filename heuristic');
  assert.equal(rows[3].status, 'rejected');
  assert.equal(rows[4].status, 'rejected');
  assert.equal(rows[4].reason, 'empty_indicator');
  assert.equal(rows[5].status, 'rejected');
  assert.equal(rows[5].reason, 'no_observable');
  assert.equal(r.stats.rows_valid, 3);
  assert.equal(r.stats.rows_rejected, 3);
});

test('table interpreter: non-IOC tables are never explicit (versions, ATT&CK, victims)', () => {
  const versions = interpretIocTable(createTableBlock({ id: 'v', headers: ['Product', 'Affected', 'Fixed'], rows: [['FortiOS', '7.4.0-7.4.7', '7.4.8'], ['FortiSwitchManager', '7.2.0', '7.2.6']] }));
  assert.equal(versions.kind, 'not_ioc_table');
  const attack = interpretIocTable(createTableBlock({ id: 'a', headers: ['Tactic', 'ID', 'Technique'], rows: [['Initial Access', 'T1190', 'Exploit Public-Facing Application'], ['Execution', 'T1059.004', 'Unix Shell']] }));
  assert.equal(attack.kind, 'identifier_table');
  assert.equal(attack.explicit, false);
  const victims = interpretIocTable({ id: 'x', section_heading: 'Targeted organizations', table: { headers: ['Organization', 'IP'], rows: [['Acme', '203.0.113.5'], ['Foo', '198.51.100.7']] } });
  assert.equal(victims.kind, 'ioc_table');
  assert.equal(victims.explicit, false);
  assert.equal(victims.reason, 'negative_context');
});

test('table interpreter: multi-language header intents and declared types', () => {
  assert.equal(headerIntent('Indicator'), 'indicator');
  assert.equal(headerIntent('Gösterge'), 'indicator');
  assert.equal(headerIntent('指标'), 'indicator');
  assert.equal(headerIntent('Tür'), 'type');
  assert.equal(headerIntent('Beschreibung'), 'description');
  assert.equal(headerIntent('描述'), 'description');
  assert.equal(headerIntent('Product'), null);
  assert.deepEqual(parseDeclaredType('IP Address & Port'), { label: 'IP Address & Port', type: 'ip', endpoint: true });
  assert.equal(parseDeclaredType('SHA-256').type, 'sha256');
  assert.equal(parseDeclaredType('IP 地址').type, 'ip');
  assert.equal(parseDeclaredType('Alan Adı').type, 'domain');
  assert.equal(parseDeclaredType('fortirun.bin'), null);
  assert.equal(looksLikeIocTableHeader('Type Indicator Description'), true);
  assert.equal(looksLikeIocTableHeader('Tür Gösterge Açıklama'), true);
  assert.equal(looksLikeIocTableHeader('Frequently Asked Questions'), false);
});

test('zones: IoCs / Host Indicators headings and a table header row open an explicit section; the table proves itself without one', () => {
  const blocks = [
    { id: 'b1', type: 'heading', text: 'IoCs' },
    { id: 'b2', type: 'heading', text: 'Host Indicators' },
    { id: 'b3', type: 'heading', text: 'Type Indicator Description' },
    { id: 'b4', type: 'paragraph', text: 'SHA256 2d338ffc8cc80293575c6800c059e33eb41e967907c20ba7687b2231c50837db fortirun.bin' },
    { id: 'b5', type: 'heading', text: 'Frequently Asked Questions' },
    createTableBlock({ id: 'b6', headers: ['ᲢᲘᲞᲘ', 'ᲛᲐᲩᲕᲔᲜᲔᲑᲔᲚᲘ'], rows: [['IP', '46[.]151[.]29[.]58'], ['SHA256', HOST_ROWS[0][1]]] })
  ];
  const annotated = annotateDocumentZones({ blocks });
  const zone = (id) => annotated.blocks.find((b) => b.id === id).zone;
  assert.equal(zone('b1'), 'explicit_ioc_section');
  assert.equal(zone('b2'), 'explicit_ioc_section');
  assert.equal(zone('b3'), 'explicit_ioc_section', 'table header row does not reset the zone');
  assert.equal(zone('b4'), 'explicit_ioc_section');
  assert.equal(zone('b5'), 'report_body');
  assert.equal(zone('b6'), 'explicit_ioc_section', 'unlabelled table under a body heading still proves itself');
  assert.equal(annotated.blocks.find((b) => b.id === 'b6').zone_reason, 'ioc_table');
});

test('defang: bracketed scheme forms and IP:port refang before splitting', () => {
  assert.equal(refangObservable('hxxps[://]146[.]103[.]99[.]177:8443/0c5b'), 'https://146.103.99.177:8443/0c5b');
  assert.equal(refangObservable('http[:]//evil[.]example/x'), 'http://evil.example/x');
  assert.equal(refangObservable('45[.]138[.]16[.]182:9130'), '45.138.16.182:9130');
  assert.equal(refangObservable('005e6014fb8fd47249691756f5af3b3d53bfae82df88a71277e53e13fe94cb9f'), '005e6014fb8fd47249691756f5af3b3d53bfae82df88a71277e53e13fe94cb9f');
});

// ---------------------------------------------------------------------------
// Persistence, AI partition and merge
// ---------------------------------------------------------------------------

test('evidence record persists row provenance and flattened table text keeps every cell', () => {
  const { blocks } = pagesToBlocks(pdfItems);
  const doc = createCanonicalDocument({ title: 'fixture', blocks });
  const candidates = extractCandidatesFromDocument(doc);
  const c = candidates.find((x) => x.normalized_value.startsWith('005e6014'));
  const record = buildCandidateEvidenceRecord(c);
  assert.equal(record.table_rows.length, 1);
  assert.equal(record.table_rows[0].declared_type, 'sha256');
  assert.equal(record.table_rows[0].raw_value, '005e6014fb8fd47249691756f5af3b3d53bfae82df88a71277e53e13fe94cb9f');
  assert.equal(record.occurrences[0].form, 'table_row');
  assert.equal(record.occurrences[0].table_row, 5);
  const table = blocks.find((b) => b.type === 'table');
  for (const row of table.table.rows) for (const cell of row) assert.ok(table.text.includes(cell), `flattened text carries ${cell}`);
  assert.equal(flattenTableText(table.table), table.text);
});

test('AI partition: explicit table rows are resolved context, only body mentions go to the model', () => {
  const html = articleHtml({ lang: 'en', headings: EN, headers: ['Type', 'Indicator', 'Description'], hostRows: HOST_ROWS, networkRows: NETWORK_ROWS });
  const { candidates } = extractFromHtml(html);
  const partition = partitionCandidatesForAi(candidates);
  const toClassify = new Set(partition.toClassify.map(keyOf));
  for (const k of expectedKeys) assert.equal(toClassify.has(k), false, `${k} must not be sent for classification`);
  assert.equal(partition.explicit.length >= 16, true);
  // Only body-prose URLs need the model (stager + advisory / MITRE / docs links); the
  // reference-list URL and the permalink are resolved deterministically as context.
  assert.ok(toClassify.has('url:https://146.103.99.177:8443/0c5b767095'));
  for (const k of toClassify) assert.equal(k.startsWith('url:'), true, `${k} unexpectedly needs AI`);
  assert.equal(toClassify.size, 1, 'only the operational body stager URL needs the model when tables already curate IOCs');
  assert.equal(toClassify.has('url:https://docs.vendor.example/hardening'), false);
  assert.equal(toClassify.has('url:https://fortiguard.example/psirt/FG-IR-25-000'), false);
  assert.equal(toClassify.has('url:https://attack.mitre.org/techniques/T1190/'), false);
  assert.equal(toClassify.has('url:https://www.fortinet.example/blog/psirt-blogs/analysis'), false, 'reference list row is context');
  assert.equal(toClassify.has('url:https://socradar.example/blog/cve-2025-25249-pivotc2-fortigate-rat/'), false, 'permalink is source metadata');
});

test('merge: final set = deterministic ∪ AI-classified; AI never replaces or drops explicit candidates', () => {
  const html = articleHtml({ lang: 'en', headings: EN, headers: ['Type', 'Indicator', 'Description'], hostRows: HOST_ROWS, networkRows: NETWORK_ROWS });
  const { candidates } = extractFromHtml(html);
  const before = new Set(candidates.map(keyOf));
  const aiOnlyD = {
    candidate_updates: [
      { candidate_type: 'url', normalized_value: 'https://146.103.99.177:8443/0c5b767095', assessment: 'malicious', role: 'payload_hosting', confidence: 0.8 },
      // Model tries to demote an explicit hash and to invent a new indicator
      { candidate_type: 'sha256', normalized_value: HOST_ROWS[0][1], assessment: 'context_only', role: 'reference', confidence: 0.2 },
      { candidate_type: 'ip', normalized_value: '203.0.113.9', assessment: 'malicious', role: 'command_and_control', confidence: 0.99 }
    ]
  };
  const merged = mergeAiCandidateUpdates(candidates, aiOnlyD);
  assert.deepEqual(new Set(merged.map(keyOf)), before, 'identity set unchanged by merge');
  assertSetEquality(explicitSet(merged), expectedKeys, 'merge');
  const d = merged.find((c) => c.candidate_type === 'url' && c.normalized_value.includes('0c5b767095'));
  assert.equal(d.assessment, 'malicious');
  assert.equal(d.decision_source, 'ai');
  const a = merged.find((c) => c.normalized_value === HOST_ROWS[0][1]);
  assert.equal(a.assessment, 'malicious', 'explicit assertion survives a demoting AI update');
  assert.equal(a.confidence >= 0.9, true);
  assert.equal(merged.some((c) => c.normalized_value === '203.0.113.9'), false, 'AI cannot add indicators');

  // AI returned nothing → deterministic explicit set intact
  const none = mergeAiCandidateUpdates(candidates, { candidate_updates: [] });
  assertSetEquality(explicitSet(none), expectedKeys, 'merge-empty');
  const nul = mergeAiCandidateUpdates(candidates, null);
  assertSetEquality(explicitSet(nul), expectedKeys, 'merge-null');
});

test('typed IOC table: defanged Domain rows stay domains; scheme-less URL rows stay URLs; host is independent', () => {
  const html = `<html lang="en"><body><article>
<h2>Indicators of Compromise</h2>
<table>
<thead><tr><th>Type</th><th>IOC</th><th>Note</th></tr></thead>
<tbody>
<tr><td>IP</td><td>203.0.113.77</td><td>C2</td></tr>
<tr><td>Domain</td><td>op-console[.]shop</td><td>Operator console</td></tr>
<tr><td>Domain</td><td>skimmer-cdn[.]shop</td><td>Skimmer host</td></tr>
<tr><td>URL</td><td>skimmer-cdn[.]shop/js/load.js</td><td>Skimmer URL</td></tr>
</tbody>
</table>
</article></body></html>`;
  const { candidates, diagnostics } = extractFromHtml(html, 'https://vendor.example/research/skimmer-campaign');
  const byKey = new Map(candidates.map((c) => [keyOf(c), c]));
  assert.equal(diagnostics.type_resolution.rejected_values.not_hostname_syntax, undefined);
  assert.ok(byKey.has('domain:op-console.shop'), 'defanged Domain row must become a domain candidate');
  assert.ok(byKey.has('domain:skimmer-cdn.shop'), 'Domain row that is also a URL host stays an independent domain');
  assert.ok(byKey.has('url:skimmer-cdn.shop/js/load.js'), 'scheme-less URL row stays a URL');
  assert.equal(byKey.get('domain:op-console.shop').source_assertion, 'explicit_ioc');
  assert.equal(byKey.get('domain:skimmer-cdn.shop').source_assertion, 'explicit_ioc');
  assert.equal(byKey.get('url:skimmer-cdn.shop/js/load.js').source_assertion, 'explicit_ioc');
  assert.equal(byKey.has('domain:vendor.example'), false, 'report host is not promoted as a finding');
  assert.equal(diagnostics.explicit_tables.values_asserted, 4);
  assert.equal(diagnostics.explicit_tables.candidates_created, 4);
  assert.equal(diagnostics.explicit_tables.inconsistent, false);
  assert.deepEqual(diagnostics.explicit_tables.missing_identities, []);
  assert.deepEqual(diagnostics.explicit_tables.dropped_asserted_identities, []);
});

test('retry: outdated extraction contract or rebuilt document refreshes candidates and starts a new analysis run', () => {
  const base = { existingCount: 46, resumePreferred: true, refreshCandidates: false, documentRebuilt: false };
  assert.deepEqual(decideCandidateReuse({ ...base, priorExtractionVersion: 'tl-candidates-v3' }), { extractionChanged: true, shouldReuseCandidates: false });
  assert.deepEqual(decideCandidateReuse({ ...base, priorExtractionVersion: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION }), { extractionChanged: false, shouldReuseCandidates: true });
  assert.deepEqual(decideCandidateReuse({ ...base, priorExtractionVersion: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, documentRebuilt: true }), { extractionChanged: true, shouldReuseCandidates: false });
  assert.deepEqual(decideCandidateReuse({ ...base, priorExtractionVersion: THREAT_LIBRARY_CANDIDATE_EXTRACTION_VERSION, existingCount: 0 }), { extractionChanged: false, shouldReuseCandidates: false });
  // The production PivotC2 report: pdf_v2 document + tl-candidates-v3 → rebuilt from the stored upload
  const blocks = [{ id: 'p1-b01', type: 'paragraph', text: 'x', page: 1 }];
  assert.equal(isDocumentContractCurrent({ source_type: 'pdf' }, { blocks, meta: { extractor: 'threat_library_pdf_v2' } }), false);
  assert.equal(isDocumentContractCurrent({ source_type: 'url' }, { blocks, meta: { extractor: 'threat_library_html_v1' } }), false);
});

test('analysis_progress stage writes keep candidate_extraction_version', () => {
  const merged = mergeAnalysisProgress(
    { candidate_extraction_version: 'tl-candidates-v9' },
    { stage: 'analyzing', analysis_chunks_total: 2 }
  );
  assert.equal(merged.stage, 'analyzing');
  assert.equal(merged.candidate_extraction_version, 'tl-candidates-v9');
});
