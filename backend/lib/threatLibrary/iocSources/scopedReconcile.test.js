import test from 'node:test';
import assert from 'node:assert/strict';
import { changedCandidateColumns, candidateColumns } from '../store.js';

test('candidateColumns defaults original occurrence true; linked-only can be false', () => {
  const orig = candidateColumns({
    candidate_type: 'ip',
    original_value: '1.2.3.4',
    normalized_value: '1.2.3.4',
    assessment: 'malicious',
    source_assertion: 'explicit_ioc'
  });
  assert.equal(orig.has_original_document_occurrence, true);

  const linked = candidateColumns({
    candidate_type: 'ip',
    original_value: '1.2.3.4',
    normalized_value: '1.2.3.4',
    assessment: 'malicious',
    source_assertion: 'linked_source_ioc',
    has_original_document_occurrence: false
  });
  assert.equal(linked.has_original_document_occurrence, false);
});

test('changedCandidateColumns ignores identical evidence', () => {
  const col = candidateColumns({
    candidate_type: 'domain',
    original_value: 'a.example',
    normalized_value: 'a.example',
    assessment: 'malicious',
    source_assertion: 'explicit_ioc',
    evidence: { source_assertion: 'explicit_ioc' }
  });
  const prior = { ...col, id: 1 };
  assert.deepEqual(changedCandidateColumns(prior, col), []);
});
