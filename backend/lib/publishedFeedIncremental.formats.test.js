import test from 'node:test';
import assert from 'node:assert/strict';
import { feedNeedsStructuredSerializerInput } from './publishedFeedIncremental.js';

const COMBOS = [
  { formats: ['txt'], structured: false, label: 'TXT only' },
  { formats: ['json'], structured: true, label: 'JSON only' },
  { formats: ['stix'], structured: true, label: 'STIX only' },
  { formats: ['txt', 'json'], structured: true, label: 'TXT + JSON' },
  { formats: ['txt', 'stix'], structured: true, label: 'TXT + STIX' },
  { formats: ['json', 'stix'], structured: true, label: 'JSON + STIX' },
  { formats: ['txt', 'json', 'stix'], structured: true, label: 'TXT + JSON + STIX' }
];

for (const combo of COMBOS) {
  test(`${combo.label} serializer input ${combo.structured ? 'includes' : 'skips'} item_json`, () => {
    assert.equal(
      feedNeedsStructuredSerializerInput({ formats: combo.formats }),
      combo.structured
    );
  });
}
