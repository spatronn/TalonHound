/**
 * Source-scope promotion: authoritative indicator sections vs narrative
 * provider/service usage. No vendor allowlists; fixture values stay in tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument } from './canonicalDocument.js';
import { extractCandidatesFromDocument, summarizeCandidateSet } from './candidateExtraction.js';
import { annotateDocumentZones, classifyHeadingText } from './documentZones.js';
import { SOURCE_ASSERTIONS, applyEvidencePolicy } from './evidencePolicy.js';
import { partitionCandidatesForAi } from './ai/analyze.js';
import { textToBlocksWithTables } from './extract/textTables.js';
import { htmlToCanonicalDocument } from './urlIngest.js';
import { plainTextToBlocks } from './pdfLayout.js';
import { canonicalizeIpv4Cidr, normalizeCandidateValue } from './candidateValue.js';
import {
  classifySectionRole,
  classifySourceRelation,
  discoverDocumentIndicatorScope,
  SOURCE_RELATIONS,
  SECTION_ROLES
} from './indicatorScope.js';

function doc(blocks, extra = {}) {
  return createCanonicalDocument({
    title: extra.title || 'Scope test',
    language: extra.language || 'en',
    blocks: blocks.map((b, i) => ({
      id: b.id || `b${i + 1}`,
      type: b.type || 'paragraph',
      page: b.page ?? 1,
      text: b.text,
      ...(b.layout ? { layout: b.layout } : {}),
      ...(b.table ? { table: b.table } : {})
    })),
    ...extra
  });
}

function byVal(cands, value) {
  return cands.find((c) => c.normalized_value === value);
}

test('heading roles are generic (no Appendix B/C/D hard-coding)', () => {
  assert.equal(classifySectionRole('Appendix B: C2 Servers'), SECTION_ROLES.C2_INFRASTRUCTURE);
  assert.equal(classifyHeadingText('Appendix B: C2 Servers'), 'c2_section');
  assert.equal(classifySectionRole('Appendix C: Astrill VPN Nodes'), SECTION_ROLES.OPERATIONAL_INFRASTRUCTURE);
  assert.equal(classifyHeadingText('Appendix C: Astrill VPN Nodes'), 'operational_infrastructure');
  assert.equal(
    classifySectionRole('Appendix D: IP Ranges in China Observed Administering PurpleBravo Infrastructure'),
    SECTION_ROLES.OPERATIONAL_INFRASTRUCTURE
  );
  assert.equal(classifySectionRole('Annex: Technical Indicators'), SECTION_ROLES.IOC_APPENDIX);
  assert.equal(classifySectionRole('附录 IOC'), SECTION_ROLES.IOC_APPENDIX);
  assert.equal(classifySectionRole('Göstergeler'), SECTION_ROLES.IOC_APPENDIX);
  assert.equal(classifySectionRole('IP Address Ranges in China:'), SECTION_ROLES.OPERATIONAL_INFRASTRUCTURE);
  assert.equal(classifySectionRole('Executive Summary'), null);
});

test('provider/service relation is context only — not a malicious IOC', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      {
        text: 'Actor purchased infrastructure from examplevps.com, likely to buy proxies.'
      }
    ])
  );
  const d = byVal(cands, 'examplevps.com');
  assert.ok(d);
  assert.equal(d.assessment, 'context_only');
  assert.equal(d.source_assertion, SOURCE_ASSERTIONS.PROVIDER_SERVICE);
  assert.equal(d.role, 'hosting_platform');
  assert.equal(d.ai_needed, false);
  assert.equal(d.match_state, 'context_only');
});

test('direct malicious host assertion remains promotable without an appendix', () => {
  const cands = extractCandidatesFromDocument(doc([{ text: 'Malware connects to c2.evil.example.' }]));
  const d = byVal(cands, 'c2.evil.example');
  assert.ok(d);
  assert.equal(d.source_relation, SOURCE_RELATIONS.OPERATIONAL_MALICIOUS);
  assert.equal(d.ai_needed, true, 'narrative-only report still uses semantic classification');
  assert.notEqual(d.assessment, 'context_only');
});

test('provider corporate domain stays context while customer-controlled C2 is malicious', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'p1', text: 'Actor used cloud provider examplecloud.com to host accounts.' },
      { id: 'p2', text: 'C2 was evil.customer-host.example.' }
    ])
  );
  assert.equal(byVal(cands, 'examplecloud.com')?.assessment, 'context_only');
  assert.equal(byVal(cands, 'examplecloud.com')?.source_assertion, SOURCE_ASSERTIONS.PROVIDER_SERVICE);
  const c2 = byVal(cands, 'evil.customer-host.example');
  assert.ok(c2);
  assert.equal(c2.source_relation, SOURCE_RELATIONS.OPERATIONAL_MALICIOUS);
  assert.notEqual(c2.assessment, 'context_only');
});

test('explicit C2 appendix rows promote deterministically without AI', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'h', type: 'heading', text: 'C2 Servers' },
      { id: 'r1', type: 'list_item', layout: 'observable_row', text: '203.0.113.10' },
      { id: 'r2', type: 'list_item', layout: 'observable_row', text: '198.51.100.20' },
      { id: 'r3', type: 'list_item', layout: 'observable_row', text: '192.0.2.30' }
    ])
  );
  for (const ip of ['203.0.113.10', '198.51.100.20', '192.0.2.30']) {
    const c = byVal(cands, ip);
    assert.equal(c.assessment, 'malicious', ip);
    assert.equal(c.role, 'command_and_control', ip);
    assert.equal(c.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_C2, ip);
    assert.equal(c.ai_needed, false, ip);
    assert.equal(c.decision_source, 'deterministic', ip);
  }
  assert.equal(summarizeCandidateSet(cands).ai_needed, 0);
});

test('VPN node appendix: listed IPs operational, provider corporate domain not malicious', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'h', type: 'heading', page: 1, text: 'Annex: VPN Nodes' },
      { id: 'n1', type: 'list_item', layout: 'observable_row', page: 1, text: '203.0.113.50' },
      { id: 'n2', type: 'list_item', layout: 'observable_row', page: 1, text: '198.51.100.50' },
      { id: 'n3', type: 'list_item', layout: 'observable_row', page: 1, text: '192.0.2.50' },
      { id: 'h2', type: 'heading', page: 2, text: 'Analysis' },
      { id: 'p', page: 2, text: 'The operator used the commercial VPN at astrill-example.com to administer nodes.' }
    ])
  );
  for (const ip of ['203.0.113.50', '198.51.100.50', '192.0.2.50']) {
    const c = byVal(cands, ip);
    assert.equal(c.assessment, 'malicious', ip);
    assert.equal(c.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_OPERATIONAL, ip);
    assert.equal(c.role, 'hosting_platform', ip);
    assert.equal(c.ai_needed, false, ip);
  }
  const vendor = byVal(cands, 'astrill-example.com');
  assert.ok(vendor);
  assert.equal(vendor.assessment, 'context_only');
  assert.notEqual(vendor.role, 'malicious_infrastructure');
});

test('CIDR appendix preserves prefix and does not explode hosts', () => {
  assert.equal(canonicalizeIpv4Cidr('36.35.56.0', 24), '36.35.56.0/24');
  assert.equal(normalizeCandidateValue('36.35.56.0/24', 'cidr').normalizedValue, '36.35.56.0/24');
  assert.equal(normalizeCandidateValue('36.35.56.1/24', 'cidr').normalizedValue, '36.35.56.0/24');
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'h', type: 'heading', text: 'IP Address Ranges in China:' },
      {
        id: 'p',
        text: '36.35.56.0/24 36.49.207.0/24 116.142.9.0/24'
      }
    ])
  );
  const cidrs = cands.filter((c) => c.candidate_type === 'cidr');
  assert.equal(cidrs.length, 3);
  assert.deepEqual(cidrs.map((c) => c.normalized_value).sort(), [
    '36.35.56.0/24',
    '36.49.207.0/24',
    '116.142.9.0/24'
  ].sort());
  for (const c of cidrs) {
    assert.equal(c.assessment, 'malicious');
    assert.equal(c.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_OPERATIONAL);
    assert.equal(c.parsed.prefix, 24);
    assert.equal(cands.some((x) => x.candidate_type === 'ip' && x.normalized_value === c.normalized_value.split('/')[0] && x.normalized_value.endsWith('.1')), false);
  }
  assert.equal(cands.filter((c) => c.candidate_type === 'ip').length, 0, 'no host explosion');
});

test('mixed occurrence: provider mention + explicit appendix → appendix wins', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'p', text: 'The operator purchased a VPS from dual.example.net.' },
      { id: 'h', type: 'heading', text: 'Indicators of Compromise' },
      { id: 'r', type: 'list_item', layout: 'observable_row', text: 'dual.example.net' }
    ])
  );
  const d = byVal(cands, 'dual.example.net');
  assert.equal(d.assessment, 'malicious');
  assert.equal(d.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_IOC);
  assert.equal(d.occurrences.length, 2);
});

test('occurrence window: C2 prose at the start of a long block does not taint a publisher domain at the end', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      {
        id: 'p',
        text:
          'From the persistent connection, the C2 server can issue operational commands, such as ssh_obj. ' +
          'x '.repeat(80) +
          'Insikt Group observed the operator using services such as residentialvps.example, likely to purchase infrastructure. ' +
          'Learn more at publisher-research.example.com'
      },
      { id: 'h', type: 'heading', text: 'C2 Servers' },
      { id: 'r1', type: 'list_item', layout: 'observable_row', text: '203.0.113.10' },
      { id: 'r2', type: 'list_item', layout: 'observable_row', text: '198.51.100.20' },
      { id: 'r3', type: 'list_item', layout: 'observable_row', text: '192.0.2.30' }
    ])
  );
  const vendor = byVal(cands, 'residentialvps.example');
  assert.equal(vendor.assessment, 'context_only');
  assert.equal(vendor.source_assertion, SOURCE_ASSERTIONS.PROVIDER_SERVICE);
  const pub = byVal(cands, 'publisher-research.example.com');
  assert.equal(pub.assessment, 'context_only');
  assert.notEqual(pub.source_relation, SOURCE_RELATIONS.OPERATIONAL_MALICIOUS);
  assert.equal(pub.ai_needed, false);
});

test('narrative-only report without appendix still classifies body C2 via AI path', () => {
  const cands = extractCandidatesFromDocument(
    doc([{ text: 'The backdoor connects to 203.0.113.88:8443 for command and control.' }], { title: 'Narrative only' })
  );
  const ip = byVal(cands, '203.0.113.88');
  assert.ok(ip);
  assert.equal(ip.ai_needed, true);
  assert.equal(discoverDocumentIndicatorScope(annotateDocumentZones(doc([{ text: 'no appendix here' }])).blocks).has_authoritative_indicator_scope, false);
});

test('English PDF-like multi-page appendix is not closed by a running header', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'h1', type: 'heading', page: 32, text: 'Appendix B: C2 Servers' },
      { id: 'h2', type: 'heading', page: 32, text: 'BeaverTail C2 Servers:' },
      { id: 'r1', type: 'list_item', layout: 'observable_row', page: 32, text: '14[.]37[.]47[.]13' },
      { id: 'r2', type: 'list_item', layout: 'observable_row', page: 32, text: '23[.]106[.]70[.]154' },
      { id: 'r3', type: 'list_item', layout: 'observable_row', page: 32, text: '38[.]92[.]47[.]85' },
      { id: 'f1', page: 32, text: '31 CTA-NK-2026-0121 Recorded Future® | www.recordedfuture.com' },
      { id: 'run', type: 'heading', page: 33, text: 'CYBER THREAT ANALYSIS' },
      { id: 'r4', type: 'list_item', layout: 'observable_row', page: 33, text: '216[.]126[.]229[.]166' },
      { id: 'f2', page: 33, text: '32 CTA-NK-2026-0121 Recorded Future® | www.recordedfuture.com' },
      { id: 'run2', type: 'heading', page: 34, text: 'CYBER THREAT ANALYSIS' },
      { id: 'f3', page: 34, text: '33 CTA-NK-2026-0121 Recorded Future® | www.recordedfuture.com' }
    ])
  );
  const a = byVal(cands, '14.37.47.13');
  const b = byVal(cands, '216.126.229.166');
  assert.equal(a.assessment, 'malicious');
  assert.equal(a.role, 'command_and_control');
  assert.equal(b.assessment, 'malicious');
  assert.equal(b.source_assertion, SOURCE_ASSERTIONS.EXPLICIT_C2);
  const pub = cands.find((c) => String(c.normalized_value).includes('recordedfuture.com'));
  if (pub) assert.equal(pub.assessment, 'context_only');
});

test('fragmented PDF IP list reconstructs via refang of [.] rows', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'h', type: 'heading', text: 'C2 Servers' },
      { id: 'r1', type: 'list_item', layout: 'observable_row', text: '107[.]189[.]24[.]80' },
      { id: 'r2', type: 'list_item', layout: 'observable_row', text: '144[.]172[.]95[.]226' },
      { id: 'r3', type: 'list_item', layout: 'observable_row', text: '66[.]235[.]175[.]117' }
    ])
  );
  assert.ok(byVal(cands, '107.189.24.80'));
  assert.ok(byVal(cands, '144.172.95.226'));
  assert.ok(byVal(cands, '66.235.175.117'));
});

test('Turkish plain text: Göstergeler are authoritative; body provider stays context', () => {
  const text = [
    'Analiz',
    'Aktör examplevps.com üzerinden altyapı satın aldı.',
    'Zararlı 203.0.113.9:8443 adresine bağlanır.',
    'Göstergeler',
    '203.0.113.9:8443',
    'c4ca4238a0b923820dcc509a6f75849b',
    'evil-c2.ornek.net',
    'Kaynaklar',
    '[1] https://arastirma.ornek-firma.com.tr/rapor'
  ].join('\n');
  const { blocks } = plainTextToBlocks(text, 1, 1);
  const cands = extractCandidatesFromDocument(createCanonicalDocument({ title: 'TR', language: 'tr', blocks }));
  assert.equal(byVal(cands, 'examplevps.com')?.assessment, 'context_only');
  assert.equal(byVal(cands, '203.0.113.9')?.assessment, 'malicious');
  assert.equal(byVal(cands, 'evil-c2.ornek.net')?.assessment, 'malicious');
});

test('Chinese report: 附录 IOC vs 参考链接', () => {
  const cands = extractCandidatesFromDocument(
    doc(
      [
        { id: 'h1', type: 'heading', text: '附录 IOC' },
        { id: 'b1', text: 'C2 203.0.113.44' },
        { id: 'h2', type: 'heading', text: '参考链接' },
        { id: 'b2', text: 'https://research.example.org/prior' }
      ],
      { language: 'zh' }
    )
  );
  assert.equal(byVal(cands, '203.0.113.44')?.assessment, 'malicious');
  assert.equal(cands.find((c) => String(c.normalized_value).includes('research.example.org'))?.assessment, 'context_only');
});

test('HTML IOC table is authoritative; markdown table is format-independent after canonicalization', () => {
  const html = `<html><body><h2>Indicators of Compromise</h2>
    <table><tr><th>Type</th><th>Value</th></tr>
    <tr><td>IP</td><td>203.0.113.21</td></tr>
    <tr><td>Domain</td><td>c2.badhost-example.net</td></tr>
    </table></body></html>`;
  const htmlDoc = htmlToCanonicalDocument(html, { url: 'https://vendor.example-research.com/r' });
  const htmlCands = extractCandidatesFromDocument(htmlDoc, { sourceUrl: 'https://vendor.example-research.com/r' });
  assert.equal(byVal(htmlCands, '203.0.113.21')?.assessment, 'malicious');
  assert.equal(byVal(htmlCands, 'c2.badhost-example.net')?.assessment, 'malicious');

  let n = 0;
  const mdBlocks = textToBlocksWithTables(
    ['| Type | Indicator |', '| --- | --- |', '| IP | 198.51.100.9 |', '| Domain | md-c2.badhost-example.net |'].join('\n'),
    { nextIndex: () => `t${(n += 1)}`, page: 1 }
  );
  const mdCands = extractCandidatesFromDocument(createCanonicalDocument({ title: 'md', blocks: mdBlocks }));
  assert.equal(byVal(mdCands, '198.51.100.9')?.assessment, 'malicious');
  assert.equal(byVal(mdCands, 'md-c2.badhost-example.net')?.assessment, 'malicious');
});

test('review set excludes narrative provider domains when appendices exist', () => {
  const cands = extractCandidatesFromDocument(
    doc([
      {
        id: 'p',
        text:
          'Insikt Group observed the operator using services such as proxy-seller.example, powervps.example, residentialvps.example, lunaproxy.example, and sms-activate.example, likely to purchase infrastructure.'
      },
      { id: 'h', type: 'heading', text: 'C2 Servers' },
      { id: 'r1', type: 'list_item', layout: 'observable_row', text: '203.0.113.7' },
      { id: 'r2', type: 'list_item', layout: 'observable_row', text: '198.51.100.7' },
      { id: 'r3', type: 'list_item', layout: 'observable_row', text: '192.0.2.7' }
    ])
  );
  for (const name of [
    'proxy-seller.example',
    'powervps.example',
    'residentialvps.example',
    'lunaproxy.example',
    'sms-activate.example'
  ]) {
    const c = byVal(cands, name);
    assert.ok(c, name);
    assert.equal(c.assessment, 'context_only', name);
    assert.equal(c.match_state, 'context_only', name);
  }
  assert.equal(byVal(cands, '203.0.113.7')?.assessment, 'malicious');
  const part = partitionCandidatesForAi(cands);
  assert.equal(part.toClassify.length, 0);
});

test('AI malicious guess cannot override provider-service relation', () => {
  const c = applyEvidencePolicy(
    {
      candidate_type: 'domain',
      normalized_value: 'residentialvps.example',
      is_ioc: true,
      original_value: 'residentialvps.example',
      occurrences: [
        {
          zone: 'report_body',
          form: 'standalone',
          surrounding_text: 'Actor purchased infrastructure from residentialvps.example'
        }
      ]
    },
    { assessment: 'malicious', role: 'malicious_infrastructure', confidence: 0.85 }
  );
  assert.equal(c.assessment, 'context_only');
  assert.equal(c.policy_decision, 'context_only_provider_service');
  assert.equal(c.ai_needed, false);
});

test('relation classifier: purchase vs connects-to', () => {
  assert.equal(
    classifySourceRelation('Actor purchased infrastructure from ExampleVPS.com', { value: 'examplevps.com' }),
    SOURCE_RELATIONS.PROVIDER_SERVICE
  );
  assert.equal(
    classifySourceRelation('Malware connects to c2.evil.example', { value: 'c2.evil.example' }),
    SOURCE_RELATIONS.OPERATIONAL_MALICIOUS
  );
});
