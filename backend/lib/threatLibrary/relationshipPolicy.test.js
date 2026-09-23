/**
 * Relationship policy: AI proposes, deterministic policy decides.
 * Regression: Zscaler "Vidar Virtual Machine-Based String Obfuscation" persisted
 * `Vidar (malware) --uses--> Zscaler (organization)` at 0.95 with no evidence.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  RELATIONSHIP_REJECTIONS,
  buildEvidenceIndex,
  isPublisherEndpoint,
  normalizeRelationshipType,
  publisherTokens,
  validateRelationship
} from './relationshipPolicy.js';
import { buildValidatedRelationships } from './pipeline.js';
import { normalizeEntityName } from './constants.js';

const entity = (entity_type, name, aliases = []) => ({ kind: 'entity', entity_type, names: [name, ...aliases] });
const cand = (candidate_type, value, original = value) => ({ kind: 'candidate', candidate_type, names: [value, original] });

// Blocks copied (shortened) from the production canonical document of the Vidar report.
const VIDAR_DOC = {
  title: 'Vidar Virtual Machine-Based String Obfuscation | ThreatLabz',
  meta: { source_host: 'www.zscaler.com' },
  blocks: [
    { id: 'b001', type: 'paragraph', text: 'Zscaler Blog' },
    { id: 'b019', type: 'paragraph', text: 'Vidar is an information stealer that was first observed in 2018. Across its iterations, Vidar has continued to improve its string obfuscation.' },
    { id: 'b040', type: 'paragraph', text: 'Vidar decrypts its strings with a custom virtual machine and an ARX-based stream cipher.' },
    { id: 'b070', type: 'heading', text: 'Zscaler Coverage' },
    { id: 'b071', type: 'paragraph', text: 'Zscaler’s multilayered cloud security platform detects indicators related to Vidar at various levels.' },
    { id: 'b075', type: 'paragraph', text: 'Zscaler MDR detects Vidar using these detection analytics:' },
    { id: 'b085', type: 'paragraph', text: 'Disclaimer: This blog post has been created by Zscaler for informational purposes only.' }
  ]
};
const VIDAR_REPORT = {
  source_url: 'https://www.zscaler.com/blogs/security-research/vidar-adds-virtual-machine-and-custom-stream-ciphers-string-obfuscation',
  source_name: 'www.zscaler.com'
};

function vidarContext() {
  const entityByRef = new Map();
  const add = (id, entity_type, name) => {
    const row = { id, portable_id: `entity--${id}`, entity_type, name, names: [name] };
    entityByRef.set(normalizeEntityName(name), row);
    entityByRef.set(name, row);
  };
  add(1, 'malware', 'Vidar');
  add(2, 'organization', 'Zscaler');
  return { entityByRef, candByKey: new Map() };
}

test('malware --uses--> organization without evidence is rejected (type policy)', () => {
  const verdict = validateRelationship(
    { relationship_type: 'uses', confidence: 0.95 },
    entity('malware', 'Vidar'),
    entity('organization', 'Zscaler')
  );
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, RELATIONSHIP_REJECTIONS.INCOMPATIBLE_TYPES);
});

test('Vidar regression: "Vidar uses Zscaler" is never persisted by the pipeline', () => {
  const { entityByRef, candByKey } = vidarContext();
  const { rows, rejected } = buildValidatedRelationships({
    relationships: [
      { subject_kind: 'entity', subject_ref: 'Vidar', relationship_type: 'uses', object_kind: 'entity', object_ref: 'Zscaler', confidence: 0.95, evidence_block_ids: [] }
    ],
    entityByRef,
    candByKey,
    document: VIDAR_DOC,
    report: VIDAR_REPORT
  });
  assert.equal(rows.length, 0);
  assert.deepEqual(rejected.map((r) => r.reason), [RELATIONSHIP_REJECTIONS.INCOMPATIBLE_TYPES]);
});

test('publisher co-mention is not evidence: "Vidar targets Zscaler" citing the coverage block is rejected', () => {
  const { entityByRef, candByKey } = vidarContext();
  // Type-valid (malware targets organization) and the cited block names both —
  // but Zscaler is the publisher describing its own detections.
  const { rows, rejected } = buildValidatedRelationships({
    relationships: [
      { subject_kind: 'entity', subject_ref: 'Vidar', relationship_type: 'targets', object_kind: 'entity', object_ref: 'Zscaler', confidence: 0.95, evidence_block_ids: ['b075'] }
    ],
    entityByRef,
    candByKey,
    document: VIDAR_DOC,
    report: VIDAR_REPORT
  });
  assert.equal(rows.length, 0);
  assert.equal(rejected[0].reason, RELATIONSHIP_REJECTIONS.PUBLISHER_WITHOUT_QUOTE);
});

test('publisher with an explicit verbatim relationship statement is not rejected automatically', () => {
  const doc = {
    meta: { source_host: 'www.microsoft.com' },
    blocks: [
      { id: 'p1', text: 'Microsoft Threat Intelligence tracks this actor.' },
      { id: 'p2', text: 'In this campaign, Storm-2035 impersonates Microsoft support staff in Teams chats to deliver the loader.' }
    ]
  };
  const report = { source_url: 'https://www.microsoft.com/en-us/security/blog/x', source_name: 'www.microsoft.com' };
  const subject = entity('threat_actor', 'Storm-2035');
  const object = entity('organization', 'Microsoft');
  const opts = { requireEvidence: true, evidenceIndex: buildEvidenceIndex(doc), publisherTokens: publisherTokens(report, doc) };
  assert.equal(isPublisherEndpoint(object, opts.publisherTokens), true);

  const quoted = validateRelationship(
    { relationship_type: 'impersonates', evidence_text: 'Storm-2035 impersonates Microsoft support staff in Teams chats', evidence_block_ids: ['p2'] },
    subject,
    object,
    opts
  );
  assert.equal(quoted.ok, true);
  assert.equal(quoted.block_id, 'p2');

  const blockOnly = validateRelationship({ relationship_type: 'impersonates', evidence_block_ids: ['p2'] }, subject, object, opts);
  assert.equal(blockOnly.ok, false);
  assert.equal(blockOnly.reason, RELATIONSHIP_REJECTIONS.PUBLISHER_WITHOUT_QUOTE);
});

test('a non-publisher organization in an evidenced relationship is kept (organizations are not banned)', () => {
  const doc = { blocks: [{ id: 'x1', text: 'APT28 targets Acme Energy with spear-phishing lures.' }] };
  const verdict = validateRelationship(
    { relationship_type: 'targets', evidence_block_ids: ['x1'] },
    entity('threat_actor', 'APT28'),
    entity('organization', 'Acme Energy'),
    { requireEvidence: true, evidenceIndex: buildEvidenceIndex(doc), publisherTokens: ['zscaler'] }
  );
  assert.equal(verdict.ok, true);
});

test('valid malware / tool / infrastructure relationships with evidence are kept', () => {
  const doc = {
    blocks: [
      { id: 'a', text: 'The PurpleBravo group deployed BeaverTail against developers.' },
      { id: 'b', text: 'InvisibleFerret uses PyObfuscate and OSRipper to hide its payload.' },
      { id: 'c', text: 'VectraRAT beacons to verify-cloud[.]digital over HTTPS.' },
      { id: 'd', text: 'PivotC2 exploits CVE-2025-25249 on FortiGate devices.' }
    ]
  };
  const opts = { requireEvidence: true, evidenceIndex: buildEvidenceIndex(doc), publisherTokens: [] };
  const cases = [
    [{ relationship_type: 'uses', evidence_block_ids: ['a'] }, entity('threat_actor', 'PurpleBravo'), entity('malware', 'BeaverTail')],
    [{ relationship_type: 'uses', evidence_block_ids: ['b'] }, entity('malware', 'InvisibleFerret'), entity('tool', 'PyObfuscate')],
    [{ relationship_type: 'communicates-with', evidence_block_ids: ['c'] }, entity('malware', 'VectraRAT'), cand('domain', 'verify-cloud.digital')],
    [{ relationship_type: 'exploits', evidence_block_ids: ['d'] }, entity('malware', 'PivotC2'), entity('vulnerability', 'CVE-2025-25249')]
  ];
  for (const [rel, s, o] of cases) {
    const v = validateRelationship(rel, s, o, opts);
    assert.equal(v.ok, true, `${s.names[0]} ${rel.relationship_type} ${o.names[0]}`);
  }
});

test('type-valid relationship without evidence naming both endpoints is rejected', () => {
  const doc = {
    blocks: [
      { id: 'p16-b165', text: 'InvisibleFerret is a Python-based, multi-platform RAT incorporating modular functionality.' },
      { id: 'other', text: 'BeaverTail is a JavaScript infostealer.' }
    ]
  };
  const opts = { requireEvidence: true, evidenceIndex: buildEvidenceIndex(doc), publisherTokens: [] };
  // No citation at all.
  const none = validateRelationship({ relationship_type: 'uses' }, entity('threat_actor', 'Lazarus group'), entity('malware', 'DTrack'), opts);
  assert.equal(none.reason, RELATIONSHIP_REJECTIONS.NO_EVIDENCE);
  // Cited block exists but does not name the subject (production p16-b165 pattern).
  const wrongBlock = validateRelationship(
    { relationship_type: 'uses', evidence_block_ids: ['p16-b165'] },
    entity('threat_actor', 'PurpleBravo'),
    entity('malware', 'InvisibleFerret'),
    opts
  );
  assert.equal(wrongBlock.reason, RELATIONSHIP_REJECTIONS.NO_EVIDENCE);
  // A quote the model invented (not in the document) is not evidence.
  const invented = validateRelationship(
    { relationship_type: 'uses', evidence_text: 'PurpleBravo uses InvisibleFerret' },
    entity('threat_actor', 'PurpleBravo'),
    entity('malware', 'InvisibleFerret'),
    opts
  );
  assert.equal(invented.reason, RELATIONSHIP_REJECTIONS.NO_EVIDENCE);
});

test('whole-term mention: a name inside a longer word does not count', () => {
  const doc = { blocks: [{ id: 'z', text: 'Vidarr uses Telegram for exfiltration.' }] };
  const v = validateRelationship(
    { relationship_type: 'uses', evidence_block_ids: ['z'] },
    entity('malware', 'Vidar'),
    entity('tool', 'Telegram'),
    { requireEvidence: true, evidenceIndex: buildEvidenceIndex(doc), publisherTokens: [] }
  );
  assert.equal(v.ok, false);
});

test('unknown relationship types are rejected; spelling variants normalize', () => {
  assert.equal(normalizeRelationshipType(' Communicates With '), 'communicates_with');
  assert.equal(normalizeRelationshipType('delivered-by'), 'delivered_by');
  const v = validateRelationship({ relationship_type: 'related_to' }, entity('malware', 'Vidar'), entity('organization', 'Zscaler'));
  assert.equal(v.reason, RELATIONSHIP_REJECTIONS.UNKNOWN_TYPE);
});

test('existing production combinations keep passing the type policy (no over-narrowing)', () => {
  const ok = [
    ['malware', 'uses', 'tool'],
    ['threat_actor', 'uses', 'malware'],
    ['threat_actor', 'overlaps_with', 'threat_actor'],
    ['threat_actor', 'overlaps_with', 'campaign'],
    ['threat_actor', 'operates', 'campaign'],
    ['malware', 'exploits', 'vulnerability'],
    ['malware', 'is_detected_as', 'malware']
  ];
  for (const [s, t, o] of ok) {
    assert.equal(validateRelationship({ relationship_type: t }, entity(s, 'A'), entity(o, 'B')).ok, true, `${s} ${t} ${o}`);
  }
  assert.equal(validateRelationship({ relationship_type: 'delivered_by' }, entity('malware', 'A'), cand('domain', 'exploit.in')).ok, true);
  // Rejected combinations found in production.
  const bad = [
    ['malware', 'uses', 'organization'],
    ['malware', 'communicates_with', 'organization'],
    ['threat_actor', 'uses', 'campaign']
  ];
  for (const [s, t, o] of bad) {
    assert.equal(validateRelationship({ relationship_type: t }, entity(s, 'A'), entity(o, 'B')).ok, false, `${s} ${t} ${o}`);
  }
  // Hashes are files: a hash cannot be a communicates_with target.
  assert.equal(validateRelationship({ relationship_type: 'communicates_with' }, entity('malware', 'A'), cand('sha256', 'a'.repeat(64))).ok, false);
});

test('accepted pipeline rows keep evidence fields in the existing shape (block_id = anchoring block)', () => {
  const entityByRef = new Map();
  for (const [id, type, name] of [[1, 'malware', 'InvisibleFerret'], [2, 'tool', 'PyObfuscate']]) {
    const row = { id, portable_id: `entity--${id}`, entity_type: type, name, names: [name] };
    entityByRef.set(normalizeEntityName(name), row);
  }
  const document = {
    blocks: [
      { id: 'b1', text: 'InvisibleFerret is a RAT.' },
      { id: 'b2', text: 'InvisibleFerret uses PyObfuscate to hide strings.' }
    ]
  };
  const { rows } = buildValidatedRelationships({
    relationships: [
      {
        subject_kind: 'entity',
        subject_ref: 'InvisibleFerret',
        relationship_type: 'Uses',
        object_kind: 'entity',
        object_ref: 'PyObfuscate',
        confidence: 0.9,
        role: null,
        evidence_text: 'InvisibleFerret uses PyObfuscate to hide strings.',
        evidence_block_ids: ['b1', 'b2']
      }
    ],
    entityByRef,
    candByKey: new Map(),
    document,
    report: { source_url: 'https://www.recordedfuture.com/research/x' }
  });
  assert.equal(rows.length, 1);
  const r = rows[0];
  assert.equal(r.relationship_type, 'uses');
  assert.equal(r.subject_entity_id, 1);
  assert.equal(r.object_entity_id, 2);
  assert.equal(r.confidence, 0.9);
  assert.equal(r.evidence_text, 'InvisibleFerret uses PyObfuscate to hide strings.');
  assert.equal(r.block_id, 'b2');
  assert.match(r.portable_id, /^relationship--/);
});

// --- Evidence beyond the literal "cited block names both" rule ---------------
// Shapes below are taken from production reports (read-only review, 35 rows).

const ev = (blocks) => ({ requireEvidence: true, evidenceIndex: buildEvidenceIndex({ blocks }), publisherTokens: [] });

test('model cited the wrong block: a sentence elsewhere in the report that states it still supports it', () => {
  const opts = ev([
    { id: 'p3-b13', type: 'paragraph', text: 'PurpleBravo uses a variety of custom and open-source malware and tools in its operations, including BeaverTail, InvisibleFerret, GolangGhost, and PylangGhost.' },
    { id: 'p16-b165', type: 'paragraph', text: 'InvisibleFerret is a Python-based, multi-platform RAT.' }
  ]);
  const v = validateRelationship({ relationship_type: 'uses', evidence_block_ids: ['p16-b165'] }, entity('threat_actor', 'PurpleBravo'), entity('malware', 'BeaverTail'), opts);
  assert.equal(v.ok, true);
  assert.equal(v.basis, 'sentence');
  assert.equal(v.block_id, 'p3-b13');
});

test('section context: heading/section names the subject, a later block of the same short section names the object', () => {
  const opts = ev([
    { id: 'h1', type: 'heading', text: 'InvisibleFerret' },
    { id: 'p1', type: 'paragraph', text: 'InvisibleFerret consists of three primary components:' },
    { id: 'p2', type: 'paragraph', text: '2. The Windows keylogger uses Python libraries, including pyWinhook, pyperclip, psutil, and pywin32.' },
    { id: 'h2', type: 'heading', text: 'Capabilities and Commands' },
    { id: 'p3', type: 'paragraph', text: 'It relies on requests for HTTP.' }
  ]);
  const v = validateRelationship({ relationship_type: 'uses' }, entity('malware', 'InvisibleFerret'), entity('tool', 'pyWinhook'), opts);
  assert.equal(v.ok, true);
  assert.equal(v.basis, 'section');
  assert.equal(v.block_id, 'p2');
  // Different section: "requests" sits under another heading that never names InvisibleFerret.
  const other = validateRelationship({ relationship_type: 'uses' }, entity('malware', 'InvisibleFerret'), entity('tool', 'requests'), opts);
  assert.equal(other.ok, false);
});

test('section context is bounded: a long section is not treated as one statement', () => {
  const blocks = [{ id: 'h', type: 'heading', text: 'Background' }, { id: 'a', type: 'paragraph', text: 'Vidar appeared in 2018.' }];
  for (let i = 0; i < 10; i += 1) blocks.push({ id: `f${i}`, type: 'paragraph', text: `Filler paragraph ${i}.` });
  blocks.push({ id: 'z', type: 'paragraph', text: 'Lumma is sold as a service.' });
  const v = validateRelationship({ relationship_type: 'uses' }, entity('malware', 'Vidar'), entity('malware', 'Lumma'), ev(blocks));
  assert.equal(v.reason, RELATIONSHIP_REJECTIONS.NO_EVIDENCE);
});

test('tables are never relationship evidence (rows enumerate, they do not state a predicate)', () => {
  const table = {
    id: 'b018',
    type: 'table',
    text: 'Attribute | Detail ¶ Name | VectraRAT ¶ Actor aliases | Vectra on HackForums and Exploit.in ¶ Delivery observed | Amadey loader, ClickFix pages'
  };
  const opts = ev([table]);
  assert.equal(validateRelationship({ relationship_type: 'uses', evidence_block_ids: ['b018'] }, entity('malware', 'VectraRAT'), entity('tool', 'Exploit.in'), opts).ok, false);
  // Production #13: even the SAME row is not evidence — a MITRE table row
  // enumerates ("PivotC2's portscan command or … SoftPerfect Network Scanner"),
  // it does not state that PivotC2 uses SoftPerfect.
  const row = ev([{ id: 'p41-b278', type: 'table', text: 'Tactic | ID | Technique | Procedure ¶ Discovery | T1046 | Network Service Discovery | The threat actors conducted port scanning (via PivotC2’s portscan command or auto-mode, SoftPerfect Network Scanner) across CIDR blocks' }]);
  assert.equal(validateRelationship({ relationship_type: 'uses' }, entity('malware', 'PivotC2'), entity('tool', 'SoftPerfect Network Scanner'), row).reason, RELATIONSHIP_REJECTIONS.NO_EVIDENCE);
});

test('aliases count as names', () => {
  const opts = ev([{ id: 'b', type: 'paragraph', text: 'Kimsuky uses the BabyShark loader in fake installer lures.' }]);
  const v = validateRelationship({ relationship_type: 'uses' }, entity('threat_actor', 'APT-C-55', ['Kimsuky']), entity('malware', 'BabyShark'), opts);
  assert.equal(v.ok, true);
});

test('a bare reference ("the C2 server") without the name anywhere nearby is not evidence', () => {
  const opts = ev([
    { id: 'h', type: 'heading', text: '/data/config/sys_vd_root+root.conf.gz' },
    { id: 'b', type: 'paragraph', text: 'Code comments reference an unrecovered module (fortidecrypt.js) designed to decrypt ENC-formatted passwords.' }
  ]);
  assert.equal(validateRelationship({ relationship_type: 'uses' }, entity('malware', 'PivotC2'), entity('tool', 'fortidecrypt.js'), opts).ok, false);
});

test('an indicator the candidate policy classified context only cannot become infrastructure', () => {
  const opts = ev([{ id: 'b', type: 'paragraph', text: 'VectraRAT is sold on HackForums, with a parallel listing on Exploit.in.' }]);
  const forum = { ...cand('domain', 'exploit.in', 'Exploit.in'), assessment: 'context_only' };
  const v = validateRelationship({ relationship_type: 'delivered_by' }, entity('malware', 'VectraRAT'), forum, opts);
  assert.equal(v.reason, RELATIONSHIP_REJECTIONS.NON_MALICIOUS_INDICATOR);
  // The same shape with a malicious candidate passes; `targets` is exempt.
  const panel = { ...cand('domain', 'verify-cloud.digital'), assessment: 'malicious' };
  const d2 = ev([{ id: 'c', type: 'paragraph', text: 'VectraRAT is delivered through ClickFix pages on verify-cloud[.]digital.' }]);
  assert.equal(validateRelationship({ relationship_type: 'delivered_by' }, entity('malware', 'VectraRAT'), panel, d2).ok, true);
  const victim = { ...cand('domain', 'acme-energy.example'), assessment: 'context_only' };
  const d3 = ev([{ id: 'v', type: 'paragraph', text: 'APT28 targets acme-energy.example employees.' }]);
  assert.equal(validateRelationship({ relationship_type: 'targets' }, entity('threat_actor', 'APT28'), victim, d3).ok, true);
});

test('Vidar/Zscaler stays rejected even though 5 blocks of the report co-mention both', () => {
  const opts = { requireEvidence: true, evidenceIndex: buildEvidenceIndex(VIDAR_DOC), publisherTokens: publisherTokens(VIDAR_REPORT, VIDAR_DOC) };
  for (const type of ['uses', 'targets', 'communicates_with', 'attributed_to']) {
    const v = validateRelationship({ relationship_type: type, evidence_block_ids: ['b019', 'b071', 'b075'] }, entity('malware', 'Vidar'), entity('organization', 'Zscaler'), opts);
    assert.equal(v.ok, false, type);
  }
});

test('publisher detection: host label vs organization name (exact, prefix, or whole word)', () => {
  const org = (n) => entity('organization', n);
  assert.deepEqual(publisherTokens({ source_url: 'https://www.ncsc.gov.uk/news/x', source_name: 'www.ncsc.gov.uk' }), ['ncsc']);
  assert.equal(isPublisherEndpoint(org('UK National Cyber Security Centre (NCSC)'), ['ncsc']), true);
  assert.equal(isPublisherEndpoint(org('Infoblox Threat Intel'), ['infoblox']), true);
  assert.equal(isPublisherEndpoint(org('Federal Bureau of Investigation (FBI)'), ['ncsc']), false);
  // PDF uploads carry no host: publisher cannot be detected (known gap, type policy still applies).
  assert.deepEqual(publisherTokens({ source_name: 'cta-nk-2026-0121.pdf' }), []);
});

// --- Predicate evidence (co-occurrence is never enough) ----------------------

test('co-occurrence without a predicate cue between the endpoints is rejected', () => {
  const opts = ev([{ id: 'b', type: 'paragraph', text: 'PivotC2 and SoftPerfect Network Scanner were both recovered from the intrusion.' }]);
  assert.equal(
    validateRelationship({ relationship_type: 'uses' }, entity('malware', 'PivotC2'), entity('tool', 'SoftPerfect Network Scanner'), opts).reason,
    RELATIONSHIP_REJECTIONS.NO_EVIDENCE
  );
});

test('production #10: page-header chrome is not evidence, and the body states the opposite direction', () => {
  const header = '9/13/26, 2:41 AM CVE-2025-25249 Exploitation Delivers PivotC2, a FortiGate Post-Exploitation RAT';
  const blocks = [];
  for (let page = 1; page <= 4; page += 1) {
    blocks.push({ id: `p${page}-h`, type: 'paragraph', page, text: header });
    blocks.push({ id: `p${page}-b`, type: 'paragraph', page, text: `Body paragraph ${page} about FortiGate appliances.` });
  }
  const pdf = { blocks };
  const subject = entity('malware', 'PivotC2');
  const object = entity('vulnerability', 'CVE-2025-25249');
  // Only the repeated header names both → header_footer zone → no evidence.
  const onlyChrome = validateRelationship({ relationship_type: 'exploits' }, subject, object, ev(pdf.blocks));
  assert.equal(onlyChrome.reason, RELATIONSHIP_REJECTIONS.NO_EVIDENCE);

  // The body names both, but the ACTOR exploits the CVE and PivotC2 is deployed afterwards.
  const body = [
    ...pdf.blocks,
    { id: 'p24-b164', type: 'paragraph', page: 5, text: 'The attack lifecycle relies on exploiting CVE-2025-25249, deploying PivotC2, establishing internal network tunnels.' },
    { id: 'p49-b341', type: 'paragraph', page: 6, text: 'PivotC2 is a Node.js remote access trojan. It is delivered after successful exploitation of CVE-2025-25249.' }
  ];
  assert.equal(validateRelationship({ relationship_type: 'exploits' }, subject, object, ev(body)).reason, RELATIONSHIP_REJECTIONS.NO_EVIDENCE);

  // A sentence that does state it is accepted.
  const stated = ev([{ id: 'x', type: 'paragraph', text: 'The PivotC2 loader exploits CVE-2025-25249 to regain access.' }]);
  assert.equal(validateRelationship({ relationship_type: 'exploits' }, subject, object, stated).ok, true);
});

test('page_edge layout blocks are chrome, not evidence', () => {
  const opts = ev([{ id: 'e', type: 'paragraph', layout: 'page_edge', text: 'Lazarus uses DTrack' }]);
  assert.equal(validateRelationship({ relationship_type: 'uses' }, entity('threat_actor', 'Lazarus'), entity('malware', 'DTrack'), opts).ok, false);
});

test('passive voice and symmetric "overlap between X and Y" are recognized', () => {
  const opts = ev([
    { id: 'a', type: 'paragraph', text: 'DTrack is a backdoor used by the Lazarus group.' },
    { id: 'b', type: 'paragraph', text: 'Previous reporting revealed occasional overlaps between PurpleBravo and PurpleDelta activity.' },
    { id: 'c', type: 'paragraph', text: 'Kaspersky Lab products detect WinPot and its modifications as Backdoor.Win32.ATMPot.gen' }
  ]);
  assert.equal(validateRelationship({ relationship_type: 'uses' }, entity('threat_actor', 'Lazarus group'), entity('malware', 'DTrack'), opts).block_id, 'a');
  assert.equal(validateRelationship({ relationship_type: 'overlaps_with' }, entity('threat_actor', 'PurpleDelta'), entity('threat_actor', 'PurpleBravo'), opts).block_id, 'b');
  assert.equal(validateRelationship({ relationship_type: 'is_detected_as' }, entity('malware', 'WinPot'), entity('malware', 'Backdoor.Win32.ATMPot.gen'), opts).block_id, 'c');
  // Wrong direction for a directional predicate: DTrack does not use Lazarus.
  assert.equal(validateRelationship({ relationship_type: 'uses' }, entity('malware', 'DTrack'), entity('threat_actor', 'Lazarus group'), opts).ok, false);
});

test('a symmetric cue outside the pair does not relate an apposition (production #19 weak sentence)', () => {
  const opts = ev([{ id: 'p2-b08', type: 'paragraph', text: 'Insikt Group distinguishes PurpleBravo (Contagious Interview) from PurpleDelta (North Korean IT workers) but has documented meaningful intersections.' }]);
  assert.equal(validateRelationship({ relationship_type: 'overlaps_with' }, entity('threat_actor', 'PurpleBravo'), entity('campaign', 'Contagious Interview'), opts).ok, false);
  // The real statement, with the PDF's U+02EE closing quote, is recognized.
  const real = ev([{ id: 'p2-b04', type: 'paragraph', text: 'PurpleBravo is a North Korean state-sponsored threat group that overlaps with the “Contagious Interviewˮ campaign first documented in November 2023.' }]);
  assert.equal(validateRelationship({ relationship_type: 'overlaps_with' }, entity('threat_actor', 'PurpleBravo'), entity('campaign', 'Contagious Interview'), real).ok, true);
});
