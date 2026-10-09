/**
 * Historical publisher observation vs import time, current reputation,
 * same-report attribution and CVE grounding (tl-candidates-v20,
 * tl-observation-v1, tl-vuln-grounding-v1, semantic-v10).
 *
 * Regression case (prod report 18643, CISA AA26-281A, published 2026-10-08,
 * imported 2026-10-09): Table 11 row `120.36.250[.]48 | 5/25/2023 | 5/25/2023`
 * under the line "IP Address First Seen Last Seen". The stored evidence kept
 * one of the two dates (whichever unlabelled column was wider on that page),
 * nothing structured said the publisher observed the value in 2023, and the
 * AI summary read "Microsoft Exchange (CVE-2019-0708)" — a CVE the PDF never
 * mentions, joined to a product the report discusses for password spraying.
 * Nothing below names that report, value or CVE as a special case.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCanonicalDocument, createTableBlock } from './canonicalDocument.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';
import { buildCandidateEvidenceRecord } from './evidencePolicy.js';
import { extractReportCandidates, observationNotAfterFor } from './extractionStages.js';
import {
  buildRowObservation,
  dateColumnMeaning,
  inferSlashDateOrder,
  parseDateCell,
  recoverHeaderLabels,
  serializeSourceObservation
} from './sourceObservation.js';
import { serializeThreatContextClaim } from './iocThreatContext.js';
import { serializeThreatReportIndicator } from './mcpThreatReport.js';
import { buildValidatedRelationships } from './pipeline.js';
import { normalizeEntityName } from './constants.js';
import {
  buildVulnerabilityIndex,
  canonicalCveId,
  groundAiVulnerabilities,
  groundStoredVulnerabilities,
  groundSummaryVulnerabilities
} from './vulnerabilityGrounding.js';
import { resolveManualIocConfidenceProvenance } from '../manualIocCreate.js';
import { buildConfidenceSourceDescription } from '../iocConfidence.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const libDir = path.resolve(here, '..');

const REPORT_2026 = { id: 1, source_url: null, published_at: '2026-10-08T00:00:00.000Z' };

function para(id, text, page = 1) {
  return { id, type: 'paragraph', text, page };
}
function heading(id, text, page = 1) {
  return { id, type: 'heading', text, page };
}

function candidatesOf(doc, report = REPORT_2026) {
  return extractReportCandidates(report, doc).candidates;
}
function byValue(candidates, value) {
  return candidates.find((c) => c.normalized_value === value);
}

// ---------------------------------------------------------------------------
// Date reading primitives
// ---------------------------------------------------------------------------

test('slash-date order comes from the document itself; ambiguous documents keep raw text only', () => {
  assert.equal(inferSlashDateOrder(['5/25/2023', '3/15/2021']), 'mdy');
  assert.equal(inferSlashDateOrder(['25/5/2023', '3/4/2021']), 'dmy');
  assert.equal(inferSlashDateOrder(['5/6/2021', '1/2/2022']), null);
  assert.equal(inferSlashDateOrder(['25/5/2023', '5/25/2023']), null, 'conflicting proof is no proof');
  assert.deepEqual(parseDateCell('5/25/2023', 'mdy'), { raw: '5/25/2023', date: '2023-05-25', marker: null });
  assert.equal(parseDateCell('5/6/2021', null).date, null);
  assert.equal(parseDateCell('5/6/2021', null).ambiguous, true);
  assert.equal(parseDateCell('5/5/2021', null).date, '2021-05-05', 'equal components need no order');
  assert.equal(parseDateCell('2023-05-25', null).date, '2023-05-25');
  assert.equal(parseDateCell('May 25, 2023', null).date, '2023-05-25');
  assert.equal(parseDateCell('25 May 2023', null).date, '2023-05-25');
  assert.equal(parseDateCell('1/18/2027*', 'mdy').marker, '*');
  assert.equal(parseDateCell('2/30/2023', 'mdy').date, null, 'impossible calendar day');
  assert.equal(parseDateCell('Infrastructure', 'mdy'), null);
});

test('column labels: first/last/observed vs non-observation dates', () => {
  assert.equal(dateColumnMeaning('First Seen'), 'first_seen');
  assert.equal(dateColumnMeaning('Last Seen'), 'last_seen');
  assert.equal(dateColumnMeaning('Date'), 'observed');
  assert.equal(dateColumnMeaning('Expiration Date'), 'not_observation');
  assert.equal(dateColumnMeaning('Registered'), 'not_observation');
  assert.equal(dateColumnMeaning('Description'), null);
});

test('header line above a headerless table is recovered only when it agrees with the columns', () => {
  const shape = { width: 3, indicatorColumns: [0], dateColumns: [1, 2] };
  assert.deepEqual(recoverHeaderLabels('IP Address First Seen Last Seen', shape), ['ip address', 'first seen', 'last seen']);
  // Page chrome before the labels (PDF running header) is tolerated.
  assert.deepEqual(recoverHeaderLabels('FBI | CISA | NSA | NCSC-UK IP Address First Seen Last Seen', shape), ['ip address', 'first seen', 'last seen']);
  // A prose line, or labels that disagree with the columns, recover nothing.
  assert.equal(recoverHeaderLabels('The actors used the following infrastructure in 2023.', shape), null);
  assert.equal(recoverHeaderLabels('Name Type First Seen Last Seen', shape), null);
  assert.equal(recoverHeaderLabels('First Seen Last Seen IP Address', shape), null);
});

test('row observation: footnoted and post-publication dates are evidence, not observations', () => {
  const obs = buildRowObservation({
    cells: ['1421.client.example[.]com', '1/18/2019', '1/18/2027*'],
    headers: ['Domain', 'First Seen', 'Last Seen'],
    indicatorColumns: [0],
    slashOrder: 'mdy',
    notAfter: '2026-10-08'
  });
  assert.equal(obs.first_seen, '2019-01-18');
  assert.equal(obs.last_seen, null);
  assert.equal(obs.latest, '2019-01-18');
  assert.equal(obs.dates[1].excluded, 'footnote_qualified');
  const future = buildRowObservation({
    cells: ['198.51.100.9', '2023-01-02', '2027-01-01'],
    headers: null,
    indicatorColumns: [0],
    notAfter: '2026-10-08'
  });
  assert.equal(future.latest, '2023-01-02');
  assert.equal(future.dates[1].excluded, 'after_publication');
  assert.equal(future.basis, 'row_dates', 'unlabelled dates are a window, never named first/last seen');
  assert.equal(future.first_seen, null);
});

test('observation upper bound is the publication day, never later than today', () => {
  const now = new Date('2026-10-09T12:00:00Z');
  assert.equal(observationNotAfterFor({ published_at: '2026-10-08T00:00:00Z' }, now), '2026-10-08');
  assert.equal(observationNotAfterFor({ published_at: null }, now), '2026-10-09');
  assert.equal(observationNotAfterFor({ published_at: '2027-01-01T00:00:00Z' }, now), '2026-10-09');
});

// ---------------------------------------------------------------------------
// Historical publisher observation (required regression)
// ---------------------------------------------------------------------------

function historicalDoc() {
  return createCanonicalDocument({
    title: 'Joint advisory',
    language: 'en',
    blocks: [
      heading('h1', 'Appendix A: Indicators of Compromise', 19),
      para('p1', 'See Table 1 for a list of observed IOCs.', 19),
      heading('h2', 'Table 1. IP Addresses', 19),
      createTableBlock({ id: 't1', page: 19, headers: ['IP Address', 'First Seen'], rows: [['1.2.3.4', '2023-05-25']] })
    ]
  });
}

test('a 2026 import of a row "1.2.3.4 | 2023-05-25" keeps the 2023 publisher observation separate from import time', () => {
  const c = byValue(candidatesOf(historicalDoc()), '1.2.3.4');
  assert.ok(c, 'publisher-declared row stays an Indicator');
  assert.equal(c.is_ioc, true);
  assert.equal(c.source_assertion, 'explicit_ioc');
  const ev = buildCandidateEvidenceRecord(c);
  assert.deepEqual(serializeSourceObservation(ev), {
    source: 'publisher_table_row',
    earliest: '2023-05-25',
    latest: '2023-05-25',
    first_seen: '2023-05-25',
    last_seen: null,
    precision: 'date',
    basis: 'labelled_columns'
  });
  // Nothing in the persisted record claims the publisher observed it in 2026.
  assert.doesNotMatch(JSON.stringify(ev.source_observation), /2026/);
  assert.equal(c.evidence_text, '1.2.3.4 | 2023-05-25');
});

test('PDF appendix: headerless page table under its label line keeps BOTH dates of the row (no widest-column loss)', () => {
  const doc = createCanonicalDocument({
    title: 'Advisory',
    language: 'en',
    blocks: [
      heading('h1', 'Appendix A: Indicators of Compromise', 19),
      para('p1', 'See Table 11 for a list of observed IOCs.', 19),
      heading('h2', 'Table 11. IP Addresses', 29),
      para('p2', 'IP Address First Seen Last Seen', 29),
      createTableBlock({
        id: 't1',
        page: 29,
        rows: [
          ['1.34.140[.]5', '3/15/2023', '3/20/2023'],
          ['198.51.7[.]48', '5/25/2023', '5/25/2023'],
          ['203.0.113[.]9', '12/26/2023', '7/30/2024']
        ]
      }),
      para('p3', 'FBI | CISA | NSA | NCSC-UK IP Address First Seen Last Seen', 42),
      createTableBlock({ id: 't2', page: 42, rows: [['192.0.2[.]48', '3/15/2021', '3/18/2021'], ['192.0.2[.]49', '6/7/2024', '6/11/2024']] })
    ]
  });
  const candidates = candidatesOf(doc);
  const first = byValue(candidates, '1.34.140.5');
  assert.equal(first.evidence_text, '1.34.140[.]5 | 3/15/2023 | 3/20/2023');
  const ev = buildCandidateEvidenceRecord(first);
  assert.equal(ev.source_observation.first_seen, '2023-03-15');
  assert.equal(ev.source_observation.last_seen, '2023-03-20');
  assert.equal(ev.source_observation.basis, 'labelled_columns');
  assert.deepEqual(ev.table_rows[0].cells.map((c) => c.text), ['3/15/2023', '3/20/2023']);
  const paged = buildCandidateEvidenceRecord(byValue(candidates, '192.0.2.48'));
  assert.equal(paged.source_observation.first_seen, '2021-03-15');
  assert.equal(paged.source_observation.last_seen, '2021-03-18');
  for (const c of candidates.filter((x) => x.candidate_type === 'ip')) {
    assert.equal(c.is_ioc, true, `${c.normalized_value} stays an Indicator`);
    assert.equal(c.assessment, 'malicious');
  }
});

test('row dates do not change membership, typing or assessment (same identities with and without date columns)', () => {
  const withDates = createCanonicalDocument({
    title: 'Advisory',
    language: 'en',
    blocks: [
      heading('h1', 'Indicators of Compromise'),
      createTableBlock({ id: 't1', headers: ['Domain', 'First Seen', 'Last Seen'], rows: [['evil[.]example', '1/2/2023', '1/30/2023'], ['bad[.]example', '2/2/2022', '2/9/2022']] })
    ]
  });
  const without = createCanonicalDocument({
    title: 'Advisory',
    language: 'en',
    blocks: [
      heading('h1', 'Indicators of Compromise'),
      createTableBlock({ id: 't1', headers: ['Domain', 'First Seen', 'Last Seen'], rows: [['evil[.]example', '', ''], ['bad[.]example', '', '']] })
    ]
  });
  const shape = (cs) => cs.map((c) => `${c.candidate_type}:${c.normalized_value}:${c.is_ioc}:${c.assessment}:${c.source_assertion}`).sort();
  assert.deepEqual(shape(candidatesOf(withDates)), shape(candidatesOf(without)));
});

test('a value without a dated row has no source_observation (never back-filled from publication / import)', () => {
  const doc = createCanonicalDocument({
    title: 'Advisory',
    language: 'en',
    blocks: [
      heading('h1', 'Indicators of Compromise'),
      createTableBlock({ id: 't1', headers: ['IP Address', 'Description'], rows: [['198.51.100.7', 'C2 server']] })
    ]
  });
  const ev = buildCandidateEvidenceRecord(byValue(candidatesOf(doc), '198.51.100.7'));
  assert.equal(ev.source_observation, undefined);
  assert.equal(serializeSourceObservation(ev), null);
});

// ---------------------------------------------------------------------------
// Threat Context / MCP: observation, publication and import stay distinct
// ---------------------------------------------------------------------------

function claimRow(evidence) {
  return {
    role: 'malicious_infrastructure',
    assessment: 'malicious',
    confidence: '0.900',
    evidence_text: '1.2.3.4 | 5/25/2023 | 5/25/2023',
    section: 'explicit_ioc_section',
    page_number: 42,
    evidence,
    report_id: 7,
    report_public_id: 'r-7',
    report_title: 'Advisory',
    published_at: '2026-10-08T00:00:00.000Z',
    published_at_precision: 'date',
    published_at_source: 'pdf_visible_date',
    report_created_at: '2026-10-09T16:51:33.814Z',
    tlp: 'clear',
    source_name: 'advisory.pdf',
    source_type: 'pdf',
    report_summary: null
  };
}

test('Threat Context claim carries the publisher observation next to (not instead of) publication and import dates', () => {
  const evidence = {
    occurrence_count: 1,
    occurrences: [],
    source_observation: {
      source: 'publisher_table_row', earliest: '2023-05-25', latest: '2023-05-25',
      first_seen: '2023-05-25', last_seen: '2023-05-25', precision: 'date', basis: 'labelled_columns', rows: 1
    }
  };
  const claim = serializeThreatContextClaim(claimRow(evidence));
  assert.equal(claim.source_observation.first_seen, '2023-05-25');
  assert.equal(claim.source_observation.last_seen, '2023-05-25');
  assert.equal(claim.report.published_date, '2026-10-08');
  assert.equal(claim.report.created_at, '2026-10-09T16:51:33.814Z');
  // Publisher claim untouched.
  assert.equal(claim.assessment, 'malicious');
  assert.equal(claim.role, 'malicious_infrastructure');
  assert.equal(serializeThreatContextClaim(claimRow({ occurrences: [] })).source_observation, null);
  const indicator = serializeThreatReportIndicator({ public_id: 'c1', normalized_value: '1.2.3.4', candidate_type: 'ip', evidence });
  assert.equal(indicator.source_observation.earliest, '2023-05-25');
});

// ---------------------------------------------------------------------------
// Current clean reputation never rewrites publisher ground truth
// ---------------------------------------------------------------------------

test('enrichment code never writes publisher evidence, IOC status, IOC confidence or attribution', () => {
  const servicesDir = path.resolve(libDir, '..', 'services');
  const files = [libDir, servicesDir].flatMap((dir) => fs.readdirSync(dir)
    .filter((f) => /(?:enrich|virustotal|abuseipdb|ipinfo|spamhaus|rdap)/i.test(f))
    .filter((f) => f.endsWith('.js') && !/\.test\.js$/.test(f))
    .map((f) => path.join(dir, f)));
  assert.ok(files.length >= 6, `enrichment modules found: ${files.join(', ')}`);
  for (const file of files) {
    const f = path.basename(file);
    const src = fs.readFileSync(file, 'utf8');
    assert.doesNotMatch(src, /threat_report_candidates/i, `${f} must not touch Threat Library candidates`);
    assert.doesNotMatch(src, /UPDATE\s+ioc_items/i, `${f} must not rewrite IOC status / confidence`);
    assert.doesNotMatch(src, /(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:ioc_threat_actors|ioc_threat_classifications|threat_relationships)/i, `${f} must not change attribution`);
  }
});

// ---------------------------------------------------------------------------
// Same report != direct IOC relationship
// ---------------------------------------------------------------------------

const ATTRIBUTION_DOC = createCanonicalDocument({
  title: 'Actor A campaign',
  language: 'en',
  blocks: [
    para('b1', 'Actor A uses Tool B to steal sensitive data from mail servers.'),
    para('b2', 'Actor A operates 5.6.7.8 as its command server.'),
    heading('b3', 'Table 1. IP Addresses'),
    createTableBlock({ id: 'b4', headers: ['IP Address', 'First Seen'], rows: [['1.2.3.4', '5/25/2023'], ['5.6.7.8', '6/1/2023']] })
  ]
});

function attributionContext() {
  const entityByRef = new Map();
  const add = (id, entity_type, name) => {
    const row = { id, portable_id: `entity--${id}`, entity_type, name, names: [name] };
    entityByRef.set(normalizeEntityName(name), row);
    entityByRef.set(name, row);
  };
  add(1, 'threat_actor', 'Actor A');
  add(2, 'tool', 'Tool B');
  const candByKey = new Map([
    ['ip:1.2.3.4', { id: 11, portable_id: 'indicator--11', candidate_type: 'ip', normalized_value: '1.2.3.4', original_value: '1.2.3.4', matched_ioc_id: 101 }],
    ['ip:5.6.7.8', { id: 12, portable_id: 'indicator--12', candidate_type: 'ip', normalized_value: '5.6.7.8', original_value: '5.6.7.8', matched_ioc_id: 102 }]
  ]);
  return { entityByRef, candByKey };
}

test('an IOC table in an Actor A / Tool B report creates no IOC → actor/tool relationship without observable evidence', () => {
  const { entityByRef, candByKey } = attributionContext();
  const { rows, rejected } = buildValidatedRelationships({
    relationships: [
      { subject_kind: 'candidate', subject_ref: '1.2.3.4', relationship_type: 'attributed_to', object_kind: 'entity', object_ref: 'Actor A', confidence: 0.9, evidence_block_ids: ['b4'] },
      { subject_kind: 'entity', subject_ref: 'Actor A', relationship_type: 'uses', object_kind: 'candidate', object_ref: '1.2.3.4', confidence: 0.9, evidence_block_ids: ['b1'] },
      { subject_kind: 'entity', subject_ref: 'Tool B', relationship_type: 'communicates_with', object_kind: 'candidate', object_ref: '1.2.3.4', confidence: 0.9, evidence_block_ids: [] }
    ],
    entityByRef,
    candByKey,
    document: ATTRIBUTION_DOC,
    report: { source_url: null }
  });
  assert.equal(rows.length, 0, 'co-mention in the same report is not a relationship');
  assert.equal(rejected.length, 3);
});

test('an explicit observable-specific sentence still yields the relationship', () => {
  const { entityByRef, candByKey } = attributionContext();
  const { rows } = buildValidatedRelationships({
    relationships: [
      { subject_kind: 'entity', subject_ref: 'Actor A', relationship_type: 'operates', object_kind: 'candidate', object_ref: '5.6.7.8', confidence: 0.9, evidence_block_ids: ['b2'] }
    ],
    entityByRef,
    candByKey,
    document: ATTRIBUTION_DOC,
    report: { source_url: null }
  });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].object_ioc_id, 102);
});

// ---------------------------------------------------------------------------
// CVE grounding
// ---------------------------------------------------------------------------

const CVE_DOC = createCanonicalDocument({
  title: 'Advisory',
  language: 'en',
  blocks: [
    para('b1', 'The actors use password spraying against Microsoft Exchange servers.'),
    para('b2', 'Affected Products: CVE-2019-0708, CVE-2021- 3199.'),
    createTableBlock({ id: 'b3', headers: ['CVE', 'Vendor', 'Product'], rows: [['CVE-2021-3199', 'ONLYOFFICE', 'DocumentServer']] }),
    para('b4', 'Remote Desktop Services is affected by CVE-2019-0708, also known as BlueKeep.')
  ]
});

test('CVE ids are canonicalized across line wraps and typographic dashes', () => {
  assert.equal(canonicalCveId('CVE-2021- 3199'), 'CVE-2021-3199');
  assert.equal(canonicalCveId('cve‑2019‑0708'), 'CVE-2019-0708');
  const idx = buildVulnerabilityIndex(CVE_DOC);
  assert.ok(idx.cves.has('CVE-2021-3199'), 'line-wrapped id counts as grounded');
});

test('document mentioning Microsoft Exchange and CVE-2019-0708 separately never yields "Microsoft Exchange (CVE-2019-0708)"', () => {
  const idx = buildVulnerabilityIndex(CVE_DOC);
  const r = groundSummaryVulnerabilities('Actors exploit ONLYOFFICE, Microsoft Exchange (CVE-2019-0708), and SoftEther VPN.', idx);
  assert.equal(r.changed, true);
  assert.doesNotMatch(r.summary, /Exchange \(CVE/);
  assert.match(r.summary, /Microsoft Exchange, and SoftEther VPN\./);
  assert.match(r.summary, /The report also references CVE-2019-0708\./, 'the grounded CVE stays as a plain reference');
  assert.deepEqual(r.unpaired, [{ cve: 'CVE-2019-0708', phrase: 'Microsoft Exchange' }]);
});

test('an explicitly stated product/CVE pairing is preserved (sentence and table row)', () => {
  const idx = buildVulnerabilityIndex(CVE_DOC);
  const s = 'Actors exploit ONLYOFFICE (CVE-2021-3199) and Remote Desktop Services (CVE-2019-0708).';
  const r = groundSummaryVulnerabilities(s, idx);
  assert.equal(r.changed, false);
  assert.equal(r.summary, s);
  assert.equal(groundSummaryVulnerabilities('They abused CVE-2021-3199 (ONLYOFFICE).', idx).changed, false);
});

test('a CVE the source never mentions is removed from the summary, entities and relationships', () => {
  const doc = createCanonicalDocument({
    title: 'Advisory',
    language: 'en',
    blocks: [para('b1', 'The actors spray passwords against Microsoft Exchange servers and exploit CVE-2021-3199 in ONLYOFFICE.')]
  });
  const out = groundAiVulnerabilities({
    summary: 'Actors exploit Microsoft Exchange (CVE-2019-0708) and ONLYOFFICE (CVE-2021-3199). They also used CVE-2021-2021.',
    entities: [
      { entity_type: 'vulnerability', name: 'CVE-2019-0708' },
      { entity_type: 'vulnerability', name: 'CVE-2021-3199' },
      { entity_type: 'threat_actor', name: 'Actor A', aliases: ['CVE-2021-2021'] }
    ],
    relationships: [
      { subject_kind: 'entity', subject_ref: 'Actor A', relationship_type: 'exploits', object_kind: 'entity', object_ref: 'CVE-2019-0708' },
      { subject_kind: 'entity', subject_ref: 'Actor A', relationship_type: 'exploits', object_kind: 'entity', object_ref: 'CVE-2021-3199' }
    ]
  }, doc);
  assert.equal(out.value.summary, 'Actors exploit Microsoft Exchange and ONLYOFFICE (CVE-2021-3199). They also used.');
  assert.deepEqual(out.value.entities.map((e) => e.name), ['CVE-2021-3199', 'Actor A']);
  assert.deepEqual(out.value.entities[1].aliases, []);
  assert.deepEqual(out.value.relationships.map((r) => r.object_ref), ['CVE-2021-3199']);
  assert.deepEqual(out.diagnostics.entities_removed, ['CVE-2019-0708']);
  assert.deepEqual(out.diagnostics.summary_removed_cves.sort(), ['CVE-2019-0708', 'CVE-2021-2021']);
});

test('stored-result grounding (Refresh extraction) is subtractive: ungrounded entity links + summary only', () => {
  const doc = createCanonicalDocument({ title: 'Advisory', language: 'en', blocks: [para('b1', 'Exchange servers were sprayed. CVE-2021-3199 affects ONLYOFFICE.')] });
  const r = groundStoredVulnerabilities({
    summary: 'Targets Microsoft Exchange (CVE-2019-0708) and ONLYOFFICE (CVE-2021-3199).',
    entities: [{ entity_id: 482, name: 'CVE-2019-0708' }, { entity_id: 493, name: 'CVE-2021-3199' }, { entity_id: 473, name: 'Integrity Technology Group' }]
  }, doc);
  assert.deepEqual(r.entity_ids_removed, [482]);
  assert.equal(r.summary, 'Targets Microsoft Exchange and ONLYOFFICE (CVE-2021-3199).');
  const untouched = groundStoredVulnerabilities({ summary: 'No vulnerabilities here.', entities: [] }, doc);
  assert.equal(untouched.summary_changed, false);
});

test('without a source document the gate abstains (never strips what it cannot verify)', () => {
  const r = groundAiVulnerabilities({ summary: 'Product (CVE-2019-0708).', entities: [{ entity_type: 'vulnerability', name: 'CVE-2019-0708' }] }, null);
  assert.equal(r.value.summary, 'Product (CVE-2019-0708).');
  assert.equal(r.value.entities.length, 1);
});

// ---------------------------------------------------------------------------
// Confidence provenance: report assertion strength, not a manual entry
// ---------------------------------------------------------------------------

test('Threat Library confidence is recorded as the source entry confidence, not "Manual entry"', () => {
  const sourceRow = { name: 'Threat_Library', default_confidence: 'medium' };
  assert.deepEqual(
    resolveManualIocConfidenceProvenance({ confidence: 'high' }, sourceRow, 'high', { confidenceOrigin: 'source_entry' }),
    { confidence_source: 'source_entry', confidence_source_name: 'Threat_Library' }
  );
  // Manual Add IOC unchanged.
  assert.equal(resolveManualIocConfidenceProvenance({ confidence: 'high' }, sourceRow, 'high').confidence_source, 'manual_entry');
  assert.equal(buildConfidenceSourceDescription('source_entry', 'Threat_Library'), 'Threat_Library entry confidence');
});

test('reviewService creates Threat Library IOCs with source-entry confidence provenance', () => {
  const src = fs.readFileSync(path.join(here, 'reviewService.js'), 'utf8');
  assert.match(src, /confidenceOrigin:\s*'source_entry'/);
});
