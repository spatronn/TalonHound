/**
 * Threat Library unit tests: SSRF URL policy, defang, candidates, AI schema, THIB integrity.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateThreatLibraryUrl, htmlToCanonicalDocument, isAllowedUrlContentType } from './urlIngest.js';
import { refangObservable, refangTextForExtraction } from './defang.js';
import { normalizeCandidateValue, extractCandidatesFromDocument } from './candidateExtraction.js';
import { createCanonicalDocument, isEffectivelyEmptyDocument } from './canonicalDocument.js';
import { validateAiAnalysis } from './ai/schema.js';
import { buildSystemPrompt } from './ai/prompts.js';
import { attachThibIntegrity, verifyThibIntegrity, computeThibContentSha256 } from './thib/integrity.js';
import { exportThibBundle, validateThibBundle } from './thib/codec.js';
import { validatePdfBuffer, sanitizePdfFileName } from './pdfIngest.js';
import { normalizeTlp, deriveMatchState, CONFIDENCE_POLICY } from './constants.js';
import { maskAiSettingsForClient } from './ai/providers.js';

test('URL policy rejects localhost and private IPs', () => {
  assert.equal(validateThreatLibraryUrl('http://127.0.0.1/x').ok, false);
  assert.equal(validateThreatLibraryUrl('http://localhost/x').ok, false);
  assert.equal(validateThreatLibraryUrl('http://10.0.0.5/x').ok, false);
  assert.equal(validateThreatLibraryUrl('http://192.168.1.1/x').ok, false);
  assert.equal(validateThreatLibraryUrl('http://169.254.169.254/latest').ok, false);
  assert.equal(validateThreatLibraryUrl('ftp://example.com/x').ok, false);
  assert.equal(validateThreatLibraryUrl('http://user:pass@example.com/x').ok, false);
  assert.equal(validateThreatLibraryUrl('https://example.com/report').ok, true);
});

test('content type allowlist', () => {
  assert.equal(isAllowedUrlContentType('text/html; charset=utf-8'), true);
  assert.equal(isAllowedUrlContentType('application/json'), false);
});

test('HTML extracts canonical blocks', () => {
  const doc = htmlToCanonicalDocument(
    `<html lang="en"><head><title>Vendor Report</title></head><body>
      <article><h1>Infrastructure</h1><p>Contact hxxp://evil[.]example/path</p>
      <p>IP 203.0.113.10 and hash aabbccddeeff00112233445566778899</p></article>
    </body></html>`,
    { url: 'https://vendor.example/r' }
  );
  assert.equal(doc.title, 'Vendor Report');
  assert.equal(doc.language, 'en');
  assert.ok(doc.blocks.length >= 2);
  const cands = extractCandidatesFromDocument(doc);
  assert.ok(cands.some((c) => c.candidate_type === 'domain' && c.normalized_value.includes('evil.example')));
  assert.ok(cands.some((c) => c.candidate_type === 'ip' && c.normalized_value === '203.0.113.10'));
});

test('defang refanging', () => {
  assert.equal(refangObservable('hxxps://evil[.]com/a'), 'https://evil.com/a');
  assert.match(refangTextForExtraction('see hxxp://a[.]b[:]8080/x'), /http:\/\/a\.b:8080\/x/);
});

test('normalizeCandidateValue reuses hash/domain rules', () => {
  const d = normalizeCandidateValue('Evil.EXAMPLE.com');
  assert.equal(d.ok, true);
  assert.equal(d.candidateType, 'domain');
  assert.equal(d.normalizedValue, 'evil.example.com');

  const h = normalizeCandidateValue('A'.repeat(64), 'sha256');
  assert.equal(h.ok, true);
  assert.equal(h.candidateType, 'sha256');

  const github = normalizeCandidateValue('github.com');
  assert.equal(github.likelyContextOnly, true);
});

test('empty document detection', () => {
  assert.equal(isEffectivelyEmptyDocument(createCanonicalDocument({ blocks: [] })), true);
  assert.equal(
    isEffectivelyEmptyDocument(
      createCanonicalDocument({ blocks: [{ id: 'b1', type: 'paragraph', text: 'Enough text content here for analysis.' }] })
    ),
    false
  );
});

test('AI schema rejects malformed and strips unknown candidates / bad blocks', () => {
  const bad = validateAiAnalysis({ summary: 'x', entities: [{ entity_type: 'nope', name: 'x' }] });
  assert.equal(bad.ok, false);

  const ok = validateAiAnalysis(
    {
      summary: 'Report about malware',
      entities: [{ entity_type: 'malware', name: 'MalX', evidence_block_ids: ['b001', 'missing'] }],
      candidate_updates: [
        {
          candidate_type: 'domain',
          normalized_value: 'evil.example',
          assessment: 'malicious',
          role: 'command_and_control',
          confidence: 0.9,
          evidence_block_ids: ['b001']
        },
        {
          candidate_type: 'domain',
          normalized_value: 'invented.example',
          assessment: 'malicious',
          role: 'unknown',
          confidence: 0.9
        }
      ],
      relationships: []
    },
    {
      knownBlockIds: new Set(['b001']),
      knownCandidateKeys: new Set(['domain\0evil.example'])
    }
  );
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.value.entities[0].evidence_block_ids, ['b001']);
  assert.equal(ok.value.candidate_updates.length, 1);
});

test('prompt injection text remains data; system prompt forbids tool use', () => {
  const sys = buildSystemPrompt();
  assert.match(sys, /UNTRUSTED DATA/i);
  assert.match(sys, /cannot redefine/i);
});

test('THIB integrity is deterministic and rejects corruption', () => {
  const base = {
    format: 'talonhound-intelligence-bundle',
    spec_version: '1.0',
    bundle_id: 'thib--11111111-1111-4111-8111-111111111111',
    created_at: '2026-01-01T00:00:00.000Z',
    generator: { name: 'TalonHound', version: '0.1.1-beta.11' },
    report: {
      id: 'report--22222222-2222-4222-8222-222222222222',
      title: 'Test',
      tlp: 'clear',
      summary: 's'
    },
    entities: [],
    indicators: [
      {
        id: 'indicator--33333333-3333-4333-8333-333333333333',
        type: 'domain',
        value: 'evil.example',
        assessment: 'malicious'
      }
    ],
    relationships: [],
    references: []
  };
  const sealed = attachThibIntegrity(base);
  assert.equal(verifyThibIntegrity(sealed).ok, true);
  const h1 = computeThibContentSha256(sealed);
  const h2 = computeThibContentSha256(sealed);
  assert.equal(h1, h2);
  const corrupted = JSON.parse(JSON.stringify(sealed));
  corrupted.integrity.content_sha256 = '0'.repeat(64);
  assert.equal(verifyThibIntegrity(corrupted).ok, false);

  const validated = validateThibBundle(sealed);
  assert.equal(validated.ok, true);

  const badSpec = attachThibIntegrity({ ...base, spec_version: '9.0' });
  assert.equal(validateThibBundle(badSpec).ok, false);
});

test('THIB export omits local DB ids', () => {
  const bundle = exportThibBundle({
    report: {
      title: 'R',
      source_type: 'url',
      tlp: 'clear',
      summary: 'sum',
      portable_id: 'report--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      bundle_id: 'thib--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
    },
    entities: [
      {
        id: 99,
        portable_id: 'entity--cccccccc-cccc-4ccc-8ccc-cccccccccccc',
        entity_type: 'malware',
        name: 'Mal',
        normalized_name: 'mal',
        description: null
      }
    ],
    candidates: [
      {
        id: 1,
        portable_id: 'indicator--dddddddd-dddd-4ddd-8ddd-dddddddddddd',
        candidate_type: 'domain',
        normalized_value: 'evil.example',
        assessment: 'malicious',
        role: 'redirector',
        confidence: 0.9,
        review_status: 'approved',
        match_state: 'new',
        matched_ioc_id: 829482,
        evidence_text: 'seen in traffic'
      }
    ],
    relationships: []
  });
  const s = JSON.stringify(bundle);
  assert.equal(/"ioc_id"\s*:/.test(s), false);
  assert.equal(/"matched_ioc_id"\s*:/.test(s), false);
  assert.equal(/829482/.test(s), false);
  assert.equal(bundle.indicators[0].value, 'evil.example');
});

test('PDF validation and filename sanitization', () => {
  assert.equal(validatePdfBuffer(Buffer.from('notpdf')).ok, false);
  const pdf = Buffer.concat([Buffer.from('%PDF-1.4\n'), Buffer.alloc(100)]);
  assert.equal(validatePdfBuffer(pdf, { fileName: '../../etc/passwd.pdf' }).ok, true);
  assert.equal(sanitizePdfFileName('../../x.pdf'), 'x.pdf');
});

test('TLP normalize and match state policy', () => {
  assert.equal(normalizeTlp('WHITE'), 'clear');
  assert.equal(normalizeTlp('TLP:AMBER+STRICT'), 'amber_strict');
  assert.equal(
    deriveMatchState({ assessment: 'context_only', confidence: 0.9, matchedIocId: null, valid: true }),
    'context_only'
  );
  assert.equal(
    deriveMatchState({
      assessment: 'unknown',
      confidence: CONFIDENCE_POLICY.REVIEW_FLOOR - 0.1,
      matchedIocId: null,
      valid: true
    }),
    'needs_review'
  );
  assert.equal(
    deriveMatchState({ assessment: 'malicious', confidence: 0.95, matchedIocId: 5, valid: true }),
    'existing'
  );
});

test('AI settings mask never returns raw key', () => {
  const masked = maskAiSettingsForClient({
    enabled: true,
    provider: 'openai',
    api_key: 'sk-secret-value-123456',
    model: 'gpt-4o',
    timeout_ms: 60000,
    max_input_chars: 10000
  });
  assert.equal(masked.api_key_configured, true);
  assert.equal(masked.api_key, undefined);
  assert.ok(!String(masked.masked_key).includes('sk-secret-value'));
});
