import test from 'node:test';
import assert from 'node:assert/strict';
import {
  discoverIocSourcesFromHtml,
  discoverIocSourcesFromText,
  guessTypeFromUrl
} from './discover.js';
import { validateIocSourceUrl } from './fetchSafe.js';
import { parseGitHubUrl, isEligibleIocFilePath } from './github.js';
import { transitionPatch } from './sourceState.js';
import { jsonIndicatorsToText, buildPreviewFromParses, candidatesFromDocument } from './parseContent.js';
import { plainTextToCanonicalDocument } from '../urlIngest.js';
import {
  isReportIndicatorMember,
  isUnionReportIndicatorMember,
  isLinkedOnlyIndicatorMember,
  countCandidateBuckets
} from '../indicatorMembership.js';

test('discovery finds GitHub IOC pack link and ignores nav noise', () => {
  const html = `
    <html><body><article>
      <p>See the <a href="https://github.com/gendigitalinc/ioc/tree/master/WardenStealer">complete IOC list</a> on GitHub.</p>
      <nav><a href="https://twitter.com/vendor">Twitter</a><a href="/about">About</a></nav>
      <p>Also <a href="https://vendor.example/blog/post">related research</a>.</p>
    </article></body></html>`;
  const found = discoverIocSourcesFromHtml(html, {
    reportUrl: 'https://www.gendigital.com/blog/insights/research/warden-stealer'
  });
  assert.equal(found.length, 1);
  assert.match(found[0].canonical_url, /github\.com\/gendigitalinc\/ioc/);
  assert.equal(found[0].discovery_method, 'auto');
  assert.ok(found[0].discovery_evidence.matched_cues.length);
});

test('text discovery scores IOC appendix URLs', () => {
  const text = 'Download IOCs: https://example.com/research/ioc/warden.csv for the full indicator dataset.';
  const found = discoverIocSourcesFromText(text, { reportUrl: 'https://example.com/report' });
  assert.ok(found.some((f) => f.canonical_url.includes('warden.csv')));
});

test('guessTypeFromUrl classifies github dir/file/pdf', () => {
  assert.equal(guessTypeFromUrl('https://github.com/org/ioc/tree/master/Pack'), 'github_dir');
  assert.equal(guessTypeFromUrl('https://github.com/org/ioc/blob/master/Pack/hashes.txt'), 'github_file');
  assert.equal(guessTypeFromUrl('https://cdn.example.com/iocs.pdf'), 'pdf');
});

test('blocked URLs fail validation independently', () => {
  assert.equal(validateIocSourceUrl('http://127.0.0.1/iocs.txt').ok, false);
  assert.equal(validateIocSourceUrl('http://192.168.1.1/iocs.txt').ok, false);
  assert.equal(validateIocSourceUrl('file:///etc/passwd').ok, false);
  assert.equal(validateIocSourceUrl('https://github.com/org/ioc/tree/master/X').ok, true);
});

test('github URL parse and eligible files', () => {
  const dir = parseGitHubUrl('https://github.com/gendigitalinc/ioc/tree/master/WardenStealer');
  assert.equal(dir.kind, 'dir');
  assert.equal(dir.owner, 'gendigitalinc');
  assert.equal(isEligibleIocFilePath('domains.txt'), true);
  assert.equal(isEligibleIocFilePath('README.md'), false);
  assert.equal(isEligibleIocFilePath('nested/hashes.csv'), true);
  assert.equal(isEligibleIocFilePath('samples.sha256'), true);
  assert.equal(isEligibleIocFilePath('samples.sha1'), true);
  assert.equal(isEligibleIocFilePath('samples.md5'), true);
  assert.equal(isEligibleIocFilePath('notes.docx'), false);
});

test('source state machine: dismiss and approve guards', () => {
  const discovered = { lifecycle_status: 'discovered' };
  assert.equal(transitionPatch(discovered, 'dismiss', { dismissed_by: 'u1' }).lifecycle_status, 'dismissed');
  assert.throws(() => transitionPatch({ lifecycle_status: 'extracted' }, 'dismiss'), /Cannot dismiss/);
  const inspected = { lifecycle_status: 'inspected' };
  assert.equal(transitionPatch(inspected, 'approve', { approved_by: 'u1' }).lifecycle_status, 'attached');
  assert.equal(transitionPatch({ lifecycle_status: 'attached' }, 'approve').idempotent, true);
});

test('json indicator schema extraction', () => {
  const text = jsonIndicatorsToText(JSON.stringify({
    indicators: [
      { type: 'ip', value: '203.0.113.50' },
      { domain: 'evil.example' }
    ]
  }));
  assert.ok(text.includes('203.0.113.50'));
  assert.ok(text.includes('evil.example'));
});

test('linked-source candidates do not inflate original MODE A membership', () => {
  const original = {
    candidate_type: 'ip',
    normalized_value: '203.0.113.10',
    is_ioc: true,
    assessment: 'malicious',
    review_status: 'pending',
    match_state: 'new',
    source_assertion: 'explicit_ioc',
    has_original_document_occurrence: true,
    document_has_authoritative_scope: true,
    evidence: {
      document_has_authoritative_scope: true,
      source_assertion: 'explicit_ioc',
      is_direct_source_observable: true,
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true, occurrence_kind: 'standalone_indicator_row' }]
    }
  };
  const linkedOnly = {
    candidate_type: 'domain',
    normalized_value: 'extra.example',
    is_ioc: true,
    assessment: 'malicious',
    review_status: 'pending',
    match_state: 'new',
    source_assertion: 'linked_source_ioc',
    has_original_document_occurrence: false,
    evidence: {
      source_assertion: 'linked_source_ioc',
      document_has_authoritative_scope: false,
      is_direct_source_observable: true,
      linked_sources: [{ id: 's1' }]
    },
    sources: [{ id: 's1' }]
  };
  const overlap = {
    ...original,
    sources: [{ id: 's1' }],
    evidence: { ...original.evidence, linked_sources: [{ id: 's1' }] }
  };

  assert.equal(isReportIndicatorMember(original), true);
  assert.equal(isReportIndicatorMember(linkedOnly), false);
  assert.equal(isUnionReportIndicatorMember(linkedOnly), true);
  assert.equal(isLinkedOnlyIndicatorMember(linkedOnly), true);
  assert.equal(isReportIndicatorMember(overlap), true);
  assert.equal(isLinkedOnlyIndicatorMember(overlap), false);

  const buckets = countCandidateBuckets([original, linkedOnly, overlap]);
  // overlap + original share? No - different identities: original ip, linked domain, overlap is same as original with sources
  // Wait - overlap has same identity as original in this fixture (same type/value). In a real set they'd be one row.
  // For count of three distinct rows as constructed:
  assert.equal(buckets.indicators, 2); // original + overlap
  assert.equal(buckets.linked_only, 1);
  assert.equal(buckets.total_unique, 3);
});

test('Warden-shaped: original 70 stays 70 when linked pack adds more', () => {
  const originals = Array.from({ length: 70 }, (_, i) => ({
    candidate_type: 'sha256',
    normalized_value: `${String(i).padStart(2, '0')}${'a'.repeat(62)}`,
    is_ioc: true,
    assessment: 'malicious',
    review_status: 'pending',
    match_state: 'new',
    source_assertion: 'explicit_ioc',
    has_original_document_occurrence: true,
    document_has_authoritative_scope: true,
    evidence: {
      document_has_authoritative_scope: true,
      source_assertion: 'explicit_ioc',
      is_direct_source_observable: true,
      occurrences: [{ zone: 'explicit_ioc_section', asserted: true }]
    }
  }));
  const linkedExtras = Array.from({ length: 30 }, (_, i) => ({
    candidate_type: 'domain',
    normalized_value: `extra-${i}.example`,
    is_ioc: true,
    assessment: 'malicious',
    review_status: 'pending',
    match_state: 'new',
    source_assertion: 'linked_source_ioc',
    has_original_document_occurrence: false,
    evidence: {
      source_assertion: 'linked_source_ioc',
      is_direct_source_observable: true
    },
    sources: [{ id: 'gh1' }]
  }));
  // Same hash in linked pack
  const overlapLinked = {
    ...originals[0],
    sources: [{ id: 'gh1' }]
  };
  const all = [...originals.slice(1), overlapLinked, ...linkedExtras];
  const buckets = countCandidateBuckets(all);
  assert.equal(buckets.indicators, 70);
  assert.equal(buckets.linked_only, 30);
  assert.equal(buckets.total_unique, 100);
});

test('preview overlap math for multi-source inspect', () => {
  const doc = plainTextToCanonicalDocument('203.0.113.9\n203.0.113.10\nevil.example', { title: 'pack' });
  const cands = candidatesFromDocument(doc, { sourcePublicId: 's1', filePath: 'a.txt' });
  assert.ok(cands.length >= 2);
  const preview = buildPreviewFromParses(
    [{ ok: true, candidates: cands, warnings: [] }],
    {
      originalKeys: new Set(['ip\x00203.0.113.9']),
      otherLinkedKeys: new Set(['domain\x00evil.example'])
    }
  );
  assert.equal(preview.estimated, false);
  assert.ok(preview.unique_count >= 2);
  assert.ok(preview.overlap_with_original >= 1);
});
