/**
 * IOC API/MCP metadata hydration — classification + report-tag semantics.
 *
 *   classifications = canonical effective set (IOC Details):
 *     (feed proposals via the controlled feed vocabulary − analyst suppressions)
 *       ∪ analyst classifications
 *   tags            = the IOC's own tags + report tags its own report evidence names
 *   report_context_tags = every linked report tag (report context, not IOC tags)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  hydrateIocApiMetadata,
  splitReportTags,
  effectiveClassificationsFromParts
} from './iocApiMetadata.js';
import { iocPairKey } from './iocThreatClassifications.js';

const IOC = { id: 3484907, observable_type: 'sha256', threat_classification: 'unknown' };

// Stored per-feed evidence of the reference CLOSEDQUORUM sample (prod shape).
const OTX_EVIDENCE = {
  ioc_item_id: IOC.id,
  ioc_observable_type: 'sha256',
  source_name: 'AlienVault OTX',
  category: 'threat-intel',
  note: 'Auto-imported from AlienVault OTX (subscribed pulses) | pulse_id=6ab431db415b8cd13de69a7e | tags=closedquorum,ai models,windows malware,windows credentials,crypto,infostealer,lsass,password stealer',
  feed_key: 'alienvault-otx'
};
const MB_EVIDENCE = {
  ioc_item_id: IOC.id,
  ioc_observable_type: 'sha256',
  source_name: 'MalwareBazaar:abuse.ch',
  category: 'CLOSEDQUORUM',
  note: 'Auto-imported from MalwareBazaar CSV | file_name=gohno.exe | file_type=exe | signature=CLOSEDQUORUM | tags=CLOSEDQUORUM,exe',
  feed_key: 'malwarebazaar-abusech'
};
const TF_EVIDENCE = {
  ioc_item_id: IOC.id,
  ioc_observable_type: 'sha256',
  source_name: 'ThreatFox:abuse.ch',
  category: 'payload',
  note: 'Auto-imported from ThreatFox API | ioc_id=1929789 | threat_type=payload | malware=Logedrut | confidence=high',
  feed_key: 'threatfox-abusech'
};
const REPORT = { id: '891705d9-f621-4549-8a56-8a38b4b0e9ec', title: 'The Closed Quorum', tlp: 'clear' };

function reportTagRow(name, iocEvidence, report = REPORT) {
  return {
    ioc_id: IOC.id,
    tag_id: name.length,
    name,
    type: 'context',
    report_id: report.id,
    report_title: report.title,
    tlp: report.tlp,
    ioc_evidence: iocEvidence
  };
}

function makePool({ junction = [], evidence = [], suppressions = [], tags = [], reportTags = [] } = {}) {
  const queries = [];
  return {
    queries,
    query: async (sql, params = []) => {
      const q = String(sql).replace(/\s+/g, ' ').trim();
      queries.push(q);
      if (q.includes('threat_report_tags rt')) return { rows: reportTags };
      if (q.includes('FROM ioc_threat_classifications')) {
        return { rows: junction.map((slug) => ({ ioc_id: IOC.id, ioc_observable_type: IOC.observable_type, classification_slug: slug })) };
      }
      if (q.includes('FROM ioc_feed_source_evidence e')) return { rows: evidence };
      if (q.includes('FROM ioc_threat_classification_overrides')) return { rows: suppressions };
      if (q.includes('ioc_tags it')) {
        return {
          rows: tags.map((t) => ({
            seed_id: (params[0] || [])[0],
            name: t.name,
            type: t.type ?? 'context',
            origins: t.origins,
            source_name: t.source_name ?? null
          }))
        };
      }
      throw new Error(`Unexpected SQL: ${q.slice(0, 120)}`);
    }
  };
}

async function hydrate(pool, row = IOC) {
  const map = await hydrateIocApiMetadata(pool, [row]);
  return map.get(iocPairKey(row.id, row.observable_type));
}

// --- classification ---------------------------------------------------------

test('reference IOC: OTX infostealer evidence yields credential_theft; raw provider strings never become slugs', async () => {
  const meta = await hydrate(makePool({ evidence: [OTX_EVIDENCE, MB_EVIDENCE, TF_EVIDENCE] }));
  // OTX "infostealer" → credential_theft (controlled feed vocabulary). MalwareBazaar
  // category "CLOSEDQUORUM" (a family name) and ThreatFox category "payload" are not
  // vocabulary terms, so they propose nothing.
  assert.deepEqual(meta.classifications, ['credential_theft']);
  assert.deepEqual(meta.classification_context, [
    { classification: 'credential_theft', sources: [{ type: 'feed', source_name: 'AlienVault OTX' }] }
  ]);
  assert.ok(!meta.classifications.includes('closedquorum'));
  assert.ok(!meta.classifications.includes('payload'));
});

test('no normalizable evidence keeps classifications empty (not [unknown])', async () => {
  const meta = await hydrate(makePool({ evidence: [MB_EVIDENCE, TF_EVIDENCE] }));
  assert.deepEqual(meta.classifications, []);
  assert.deepEqual(meta.classification_context, []);
});

test('analyst suppression removes a feed proposal (low-trust provider assertion does not stick)', async () => {
  const meta = await hydrate(makePool({
    evidence: [OTX_EVIDENCE],
    suppressions: [{ ioc_id: IOC.id, ioc_observable_type: 'sha256', classification_slug: 'credential_theft', source_name: null }]
  }));
  assert.deepEqual(meta.classifications, []);
});

test('manual analyst classification is preserved alongside feed proposals', async () => {
  const meta = await hydrate(makePool({ junction: ['malware'], evidence: [OTX_EVIDENCE] }));
  assert.deepEqual(meta.classifications, ['credential_theft', 'malware']);
  const malware = meta.classification_context.find((c) => c.classification === 'malware');
  assert.deepEqual(malware.sources, [{ type: 'analyst' }]);
});

test('analyst classification equal to a feed proposal shows once with both provenances', async () => {
  const meta = await hydrate(makePool({ junction: ['credential_theft'], evidence: [OTX_EVIDENCE] }));
  assert.deepEqual(meta.classifications, ['credential_theft']);
  assert.deepEqual(meta.classification_context[0].sources, [
    { type: 'feed', source_name: 'AlienVault OTX' },
    { type: 'analyst' }
  ]);
});

test('legacy column classification (no junction rows) stays an analyst classification', async () => {
  const meta = await hydrate(makePool({ evidence: [] }), { ...IOC, threat_classification: 'malware' });
  assert.deepEqual(meta.classifications, ['malware']);
});

test('conflicting feed proposals are each listed with their own asserting source, deduped', async () => {
  const urlhaus = { ...OTX_EVIDENCE, source_name: 'URLhaus:abuse.ch', category: null, note: 'x | tags=malware_download,infostealer' };
  const meta = await hydrate(makePool({ evidence: [OTX_EVIDENCE, urlhaus] }));
  assert.deepEqual(meta.classifications, ['credential_theft', 'dropper_downloader']);
  assert.deepEqual(
    meta.classification_context.find((c) => c.classification === 'credential_theft').sources.map((s) => s.source_name),
    ['AlienVault OTX', 'URLhaus:abuse.ch']
  );
});

test('effectiveClassificationsFromParts: source-specific suppression only hides that source', () => {
  const out = effectiveClassificationsFromParts({
    feed: [{ value: 'phishing', source_name: 'Feed A', source_names: ['Feed A'] }],
    analystSlugs: [],
    suppressions: [{ classification_slug: 'phishing', source_name: 'Feed B' }]
  });
  assert.deepEqual(out.classifications, ['phishing']);
});

// --- tags: report context vs IOC assertion -----------------------------------

const CONTEXT_ONLY_REPORT_TAGS = ['banking', 'government', 'healthcare', 'espionage', 'phishing', 'ransomware'];

test('report tags without IOC-specific evidence are report context, never IOC tags', async () => {
  const meta = await hydrate(makePool({
    tags: [{ name: 'infostealer', origins: ['integration'], source_name: 'AlienVault OTX' }],
    reportTags: CONTEXT_ONLY_REPORT_TAGS.map((name) => reportTagRow(name, false))
  }));
  assert.deepEqual(meta.tags, ['infostealer']);
  for (const name of CONTEXT_ONLY_REPORT_TAGS) {
    assert.ok(!meta.tags.includes(name), `${name} must not become an IOC tag`);
    assert.ok(!meta.tag_context.some((c) => c.tag === name));
    // ...but the report tag is not lost: it stays visible as report context.
    const ctx = meta.report_context_tags.find((c) => c.tag === name);
    assert.deepEqual(ctx, { tag: name, ioc_evidence: false, reports: [{ id: REPORT.id, title: REPORT.title, tlp: 'clear' }] });
  }
});

test('report tag named by the IOC\'s own report evidence is an IOC tag with evidence provenance', async () => {
  const meta = await hydrate(makePool({ reportTags: [reportTagRow('banking', true), reportTagRow('powershell', false)] }));
  assert.deepEqual(meta.tags, ['banking']);
  assert.equal(meta.tags_detail[0].origin, 'threat_library');
  assert.deepEqual(meta.tag_context, [{
    tag: 'banking',
    sources: [{ type: 'threat_library', report_id: REPORT.id, title: REPORT.title, tlp: 'clear', basis: 'ioc_evidence' }]
  }]);
  assert.deepEqual(meta.report_context_tags.map((t) => [t.tag, t.ioc_evidence]), [['banking', true], ['powershell', false]]);
});

test('explicit IOC tag equal to a context-only report tag is kept (direct), report adds no provenance', async () => {
  const meta = await hydrate(makePool({
    tags: [{ name: 'credential theft', origins: ['integration'], source_name: 'AlienVault OTX' }],
    reportTags: [reportTagRow('credential theft', false), reportTagRow('banking', false)]
  }));
  assert.deepEqual(meta.tags, ['credential theft']);
  assert.deepEqual(meta.tag_context, [{
    tag: 'credential theft',
    sources: [{ type: 'direct', origin: 'integration', source_name: 'AlienVault OTX' }]
  }]);
  assert.ok(meta.report_context_tags.some((t) => t.tag === 'credential theft'));
});

test('splitReportTags keeps only evidence-backed reports on the IOC-level side', () => {
  const other = { id: 'r2', title: 'Other', tlp: 'green' };
  const out = splitReportTags([{
    name: 'winpot',
    type: 'threat',
    reports: [
      { id: REPORT.id, title: REPORT.title, tlp: 'clear', ioc_evidence: false },
      { id: other.id, title: other.title, tlp: other.tlp, ioc_evidence: true }
    ]
  }]);
  assert.deepEqual(out.iocLevel, [{ name: 'winpot', type: 'threat', reports: [other] }]);
  assert.equal(out.context[0].reports.length, 2);
  assert.equal(out.context[0].ioc_evidence, true);
});

test('hydration stays a constant number of queries (no N+1)', async () => {
  const pool = makePool({ evidence: [OTX_EVIDENCE] });
  await hydrateIocApiMetadata(pool, [IOC, { ...IOC, id: IOC.id + 1 }, { ...IOC, id: IOC.id + 2 }]);
  const single = makePool({ evidence: [OTX_EVIDENCE] });
  await hydrateIocApiMetadata(single, [IOC]);
  assert.equal(pool.queries.length, single.queries.length);
});
