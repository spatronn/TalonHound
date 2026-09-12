/**
 * AI extract / normalize / validate pipeline tests (includes BengalSEO failure shape).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { extractJsonObject } from './extract.js';
import { normalizeConfidence, normalizeAiAnalysisInput } from './normalize.js';
import { processAiResponseText, validateAiAnalysis } from './schema.js';
import { THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION } from './contract.js';
import { analyzeThreatDocument } from './analyze.js';
import { AI_FAILURE_CODES } from './timeouts.js';
import { createCanonicalDocument } from '../canonicalDocument.js';

test('markdown fenced JSON extracts successfully', () => {
  const r = extractJsonObject('```json\n{"summary":"ok","entities":[],"candidate_updates":[],"relationships":[]}\n```');
  assert.equal(r.ok, true);
  assert.equal(r.method, 'fence');
  assert.equal(r.value.summary, 'ok');
});

test('leading explanation + one JSON object extracts when wrapper is known', () => {
  const r = extractJsonObject('Here is the JSON:\n{"summary":"x","entities":[],"candidate_updates":[],"relationships":[]}');
  assert.equal(r.ok, true);
  assert.equal(r.value.summary, 'x');
});

test('random prose is rejected', () => {
  const r = extractJsonObject('I cannot help with that request.');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'ai_output_parse_error');
});

test('confidence high string normalizes to documented numeric mapping', () => {
  assert.equal(normalizeConfidence('high').value, 0.85);
  assert.equal(normalizeConfidence('95%').value, 0.95);
  assert.equal(normalizeConfidence(95).value, 0.95);
  assert.equal(normalizeConfidence(0.93).value, 0.93);
});

test('BengalSEO failure shape: confidence "high" becomes valid after normalize', () => {
  const raw = {
    summary: 'Introduction to The DFIR Report...',
    report_type: 'threat_report',
    language: 'en-us',
    tlp: 'green',
    confidence: 'high',
    entities: [],
    candidate_updates: [],
    relationships: []
  };
  const before = validateAiAnalysis(
    { ...raw },
    { knownBlockIds: new Set(['b001']), knownCandidateKeys: new Set() }
  );
  // validateAiAnalysis now includes normalize — should succeed
  assert.equal(before.ok, true);
  assert.equal(before.value.confidence, 0.85);
  assert.equal(before.value.language, 'en');
  assert.equal(before.value.tlp, 'GREEN');
});

test('enum aliases normalize', () => {
  const n = normalizeAiAnalysisInput({
    summary: 's',
    entities: [{ entity_type: 'Threat Actor', name: 'APT' }],
    candidate_updates: [
      {
        candidate_type: 'domain',
        normalized_value: 'evil.example',
        assessment: 'context only',
        role: 'C2',
        confidence: 'high'
      }
    ],
    relationships: []
  });
  assert.equal(n.ok, true);
  assert.equal(n.value.entities[0].entity_type, 'threat_actor');
  assert.equal(n.value.candidate_updates[0].assessment, 'context_only');
  assert.equal(n.value.candidate_updates[0].role, 'command_and_control');
});

test('missing empty arrays default safely', () => {
  const n = normalizeAiAnalysisInput({ summary: 'only summary', confidence: 0.5 });
  assert.equal(n.ok, true);
  assert.deepEqual(n.value.entities, []);
  assert.deepEqual(n.value.candidate_updates, []);
  assert.deepEqual(n.value.relationships, []);
});

test('unknown enum is not silently invented', () => {
  const r = processAiResponseText(
    JSON.stringify({
      summary: 's',
      entities: [{ entity_type: 'spaceship', name: 'x' }],
      candidate_updates: [],
      relationships: []
    })
  );
  assert.equal(r.ok, false);
  assert.equal(r.code, 'ai_output_schema_error');
});

test('hallucinated block id is stripped and recorded', () => {
  const r = validateAiAnalysis(
    {
      summary: 's',
      entities: [{ entity_type: 'malware', name: 'M', evidence_block_ids: ['b001', 'page-99'] }],
      candidate_updates: [],
      relationships: []
    },
    { knownBlockIds: new Set(['b001']), knownCandidateKeys: new Set() }
  );
  assert.equal(r.ok, true);
  assert.deepEqual(r.value.entities[0].evidence_block_ids, ['b001']);
  assert.ok((r.rejected || []).some((x) => x.code === 'unknown_block_id'));
});

test('hallucinated candidate is rejected from updates', () => {
  const r = validateAiAnalysis(
    {
      summary: 's',
      entities: [],
      candidate_updates: [
        {
          candidate_type: 'domain',
          normalized_value: 'nope.example',
          assessment: 'malicious',
          role: 'unknown',
          confidence: 0.9
        }
      ],
      relationships: []
    },
    { knownCandidateKeys: new Set(['domain\0real.example']) }
  );
  assert.equal(r.ok, true);
  assert.equal(r.value.candidate_updates.length, 0);
});

test('partial invalid relationship is dropped, assessments kept', () => {
  const r = validateAiAnalysis(
    {
      summary: 's',
      entities: [{ entity_type: 'malware', name: 'MalX' }],
      candidate_updates: [
        {
          candidate_type: 'domain',
          normalized_value: 'evil.example',
          assessment: 'malicious',
          role: 'redirector',
          confidence: 0.9
        }
      ],
      relationships: [
        {
          subject_kind: 'entity',
          subject_ref: 'MalX',
          relationship_type: 'uses',
          object_kind: 'entity',
          object_ref: 'MissingActor'
        }
      ]
    },
    { knownCandidateKeys: new Set(['domain\0evil.example']) }
  );
  assert.equal(r.ok, true);
  assert.equal(r.value.candidate_updates.length, 1);
  assert.equal(r.value.relationships.length, 0);
  assert.ok((r.rejected || []).length >= 1);
});

test('thinking wrappers are stripped before parse', () => {
  const r = extractJsonObject(
    '<think>secret chain</think>\n{"summary":"ok","entities":[],"candidate_updates":[],"relationships":[]}'
  );
  assert.equal(r.ok, true);
  assert.equal(r.value.summary, 'ok');
});

test('schema version constant is stable contract id', () => {
  assert.match(THREAT_LIBRARY_SEMANTIC_SCHEMA_VERSION, /^threat-library-semantic-v/);
});

test('repair path: invalid then valid via callProvider mock', async () => {
  const document = createCanonicalDocument({
    title: 't',
    blocks: [{ id: 'b001', type: 'paragraph', text: 'Malware Foo used evil.example for C2.' }]
  });
  let calls = 0;
  const out = await analyzeThreatDocument(
    {
      enabled: true,
      provider: 'ollama',
      model: 'qwen3.5:9b',
      base_url: 'http://127.0.0.1:11434',
      max_input_chars: 20000
    },
    {
      document,
      candidates: [
        {
          candidate_type: 'domain',
          normalized_value: 'evil.example',
          original_value: 'evil.example',
          block_id: 'b001'
        }
      ]
    },
    {
      callProvider: async () => {
        calls += 1;
        if (calls === 1) {
          return {
            text: JSON.stringify({
              summary: 'first',
              confidence: 'high',
              entities: [{ entity_type: 'malware', name: 'Foo' }],
              candidate_updates: [
                {
                  candidate_id: 'cand-001',
                  assessment: 'malicious',
                  role: 'C2',
                  confidence: 'high'
                }
              ],
              relationships: []
            })
          };
        }
        // Should not need repair for this case after normalize — but if called, return valid
        return {
          text: JSON.stringify({
            summary: 'repaired',
            confidence: 0.9,
            entities: [],
            candidate_updates: [],
            relationships: []
          })
        };
      }
    }
  );
  assert.equal(out.ok, true);
  assert.equal(out.value.confidence, 0.85);
  assert.equal(calls, 1, 'deterministic normalize should avoid AI repair');
});

test('incompatible checkpoint schema_version is not reused', async () => {
  const document = createCanonicalDocument({
    title: 't',
    blocks: [{ id: 'b001', type: 'paragraph', text: 'x'.repeat(100) }]
  });
  let providerCalls = 0;
  await analyzeThreatDocument(
    {
      enabled: true,
      provider: 'ollama',
      model: 'm',
      base_url: 'http://127.0.0.1:11434'
    },
    { document, candidates: [] },
    {
      loadCompletedChunk: async () => ({
        ok: true,
        value: {
          summary: 'old',
          entities: [],
          candidate_updates: [],
          relationships: [],
          confidence: 0.5
        },
        schema_version: 'threat-library-semantic-v1'
      }),
      callProvider: async () => {
        providerCalls += 1;
        return {
          text: JSON.stringify({
            summary: 'new',
            confidence: 0.7,
            entities: [],
            candidate_updates: [],
            relationships: []
          })
        };
      }
    }
  );
  assert.equal(providerCalls, 1);
});

test('truncated JSON fails without partial persist path', () => {
  const r = processAiResponseText('{"summary":"broken","entities":[');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'ai_output_parse_error');
});
