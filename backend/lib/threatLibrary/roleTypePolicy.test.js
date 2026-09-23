/**
 * IOC type ↔ role compatibility: a file hash is a file, never infrastructure.
 * Regression: Zscaler "Vidar Virtual Machine-Based String Obfuscation" — the
 * explicit IOC table's SHA-256 samples were persisted as command_and_control
 * because the AI role was accepted for explicit assertions without a type check.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createCanonicalDocument } from './canonicalDocument.js';
import { extractCandidatesFromDocument } from './candidateExtraction.js';
import { applyEvidencePolicy, enforceRoleTypeCompatibility } from './evidencePolicy.js';
import { mergeAiCandidateUpdates } from './pipeline.js';
import { replaceCandidates } from './store.js';

const VIDAR_V25 = '625a381981fc2d4c25c981d98b1d66bb2cf5da2dde2f590add0673a857d5b074';
const SHA1 = '2b62b690d165b9e650fa9cb9169d46ebb866b74a';
const MD5 = '3532f7012fce368f993d424fccf37cb7';

function doc(blocks) {
  return createCanonicalDocument({
    title: 'Role policy test',
    language: 'en',
    blocks: blocks.map((b, i) => ({ id: b.id || `b${i + 1}`, type: b.type || 'paragraph', page: 1, text: b.text }))
  });
}

/** An explicit IOC appendix row for `value` (the Vidar table shape). */
function explicitCandidate(value) {
  const cands = extractCandidatesFromDocument(
    doc([
      { id: 'h', type: 'heading', text: 'Indicators Of Compromise (IOCs)' },
      { id: 'r', type: 'list_item', text: value }
    ])
  );
  const c = cands.find((x) => x.normalized_value === value.toLowerCase());
  assert.ok(c, `candidate for ${value}`);
  return c;
}

test('Vidar regression: SHA-256 in an explicit IOC table + AI command_and_control → malware_sample', () => {
  const c = explicitCandidate(VIDAR_V25);
  assert.equal(c.candidate_type, 'sha256');
  applyEvidencePolicy(c, { assessment: 'malicious', role: 'command_and_control', confidence: 0.95 });
  assert.equal(c.assessment, 'malicious');
  assert.equal(c.role, 'malware_sample');
  // The model's claim stays visible as a suggestion, it just never becomes the role.
  assert.equal(c.ai_role_suggestion, 'command_and_control');
});

test('SHA-1 and MD5 hold the same invariant for every infrastructure role', () => {
  for (const value of [SHA1, MD5]) {
    for (const role of ['command_and_control', 'redirector', 'payload_hosting', 'malware_download', 'hosting_platform', 'malicious_infrastructure']) {
      const c = explicitCandidate(value);
      applyEvidencePolicy(c, { assessment: 'malicious', role, confidence: 0.9 });
      assert.equal(c.role, 'malware_sample', `${c.candidate_type} ${role}`);
    }
  }
});

test('the full AI merge path (mergeAiCandidateUpdates) cannot put an infrastructure role on a hash', () => {
  const c = explicitCandidate(VIDAR_V25);
  const [merged] = mergeAiCandidateUpdates([c], {
    candidate_updates: [{ candidate_type: 'sha256', normalized_value: VIDAR_V25, assessment: 'malicious', role: 'command_and_control', confidence: 0.95 }]
  });
  assert.equal(merged.role, 'malware_sample');
});

test('unknown / empty role on an explicit hash still falls back to malware_sample', () => {
  for (const role of [undefined, null, '', 'unknown']) {
    const c = explicitCandidate(VIDAR_V25);
    c.role = role;
    applyEvidencePolicy(c);
    assert.equal(c.role, 'malware_sample', String(role));
  }
});

test('valid file roles on hashes are kept (malware_sample, security_tool, reference)', () => {
  for (const role of ['malware_sample', 'security_tool', 'reference', 'unknown']) {
    const c = enforceRoleTypeCompatibility({ candidate_type: 'sha256', role, assessment: 'context_only' });
    assert.equal(c.role, role);
  }
});

test('non-malicious hash with a network role becomes reference, not malware_sample', () => {
  const c = enforceRoleTypeCompatibility({ candidate_type: 'md5', role: 'hosting_platform', assessment: 'context_only' });
  assert.equal(c.role, 'reference');
  const s = enforceRoleTypeCompatibility({ candidate_type: 'md5', role: 'legitimate_service', assessment: 'suspicious' });
  assert.equal(s.role, 'malware_sample');
});

test('IP / domain / URL keep their infrastructure roles (unchanged behaviour)', () => {
  const cases = [
    ['http://203.0.113.5/drop/x.bin', 'payload_hosting'],
    ['198.51.100.44', 'command_and_control'],
    ['evil-c2.example.net', 'redirector']
  ];
  for (const [value, role] of cases) {
    const c = explicitCandidate(value);
    applyEvidencePolicy(c, { assessment: 'malicious', role, confidence: 0.95 });
    assert.equal(c.role, role, value);
  }
  for (const type of ['ip', 'domain', 'url']) {
    const c = enforceRoleTypeCompatibility({ candidate_type: type, role: 'command_and_control', assessment: 'malicious' });
    assert.equal(c.role, 'command_and_control');
  }
});

test('replaceCandidates enforces the invariant for every persistence path (e.g. THIB import)', async () => {
  const inserted = [];
  const pool = {
    async query(sql, params) {
      if (/INSERT INTO threat_report_candidates/.test(sql)) {
        inserted.push({ candidate_type: params[2], role: params[6] });
        return { rows: [{ id: inserted.length, role: params[6] }] };
      }
      return { rows: [] };
    }
  };
  const input = [
    { candidate_type: 'sha256', original_value: VIDAR_V25, normalized_value: VIDAR_V25, assessment: 'malicious', role: 'command_and_control' },
    { candidate_type: 'domain', original_value: 'c2.example.net', normalized_value: 'c2.example.net', assessment: 'malicious', role: 'command_and_control' }
  ];
  await replaceCandidates(pool, 1, input);
  assert.deepEqual(inserted, [
    { candidate_type: 'sha256', role: 'malware_sample' },
    { candidate_type: 'domain', role: 'command_and_control' }
  ]);
  // Caller's objects are not mutated.
  assert.equal(input[0].role, 'command_and_control');
});
