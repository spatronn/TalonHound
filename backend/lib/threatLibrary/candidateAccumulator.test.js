/**
 * The extraction passes in isolation: a token becomes one candidate per identity,
 * a rejected token leaves a recorded reason, and each pass reads only its blocks.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCandidateAccumulator } from './candidateAccumulator.js';
import { readDocumentText } from './candidateTextPass.js';
import { readTypedTables } from './candidateTablePass.js';
import { extractCandidatesWithDiagnostics } from './candidateExtraction.js';

function makeAcc() {
  const rejected = [];
  const typeDiag = { syntactic_occurrences: 0, rejected_values: {}, examples: [] };
  const acc = createCandidateAccumulator({
    tableOrdinals: new Map(),
    listLeadIns: new Map(),
    valueLineLeadIns: new Map(),
    codeListNames: new Map(),
    sourceHost: 'publisher.example',
    normalizedSourceUrl: 'https://publisher.example/report',
    typeDiag,
    explicitTableAssertions: { assertion_keys: new Set(), row_keys: new Set() },
    referenceColumnValues: new Map(),
    noteRejectedToken: (raw, type, block, reason) => rejected.push({ raw, type, reason }),
    extractionVersion: 'test'
  });
  return { acc, rejected, typeDiag };
}

const block = (id, text, zone = 'report_body') => ({ id, type: 'paragraph', text, zone, section_path: ['Body'] });

test('two occurrences of one identity accumulate on one candidate', () => {
  const { acc } = makeAcc();
  const a = acc.add('203.0.113.7', 'ip', block('b1', 'seen at 203.0.113.7'));
  const b = acc.add('203.0.113.7', 'ip', block('b2', 'again 203.0.113.7'));
  assert.ok(a);
  assert.equal(a, b);
  assert.equal(acc.byKey.size, 1);
  assert.equal(a.occurrences.length, 2);
});

test('a token that does not normalize is rejected with a recorded reason', () => {
  const { acc, rejected, typeDiag } = makeAcc();
  assert.equal(acc.add('not an ip at all', 'ip', block('b1', 'not an ip at all')), null);
  assert.equal(acc.byKey.size, 0);
  assert.equal(rejected.length, 1);
  assert.equal(rejected[0].reason, acc.lastRejection());
  assert.equal(typeDiag.rejected_values[acc.lastRejection()], 1);
});

test('a hex run labelled as a credential is not a file digest', () => {
  const { acc, rejected } = makeAcc();
  const hex = 'a'.repeat(31) + 'b';
  assert.equal(acc.add(hex, 'md5', block('b1', `API key: ${hex}`)), null);
  assert.equal(rejected[0].reason, 'credential_labeled_hex');
});

test('the text pass skips blocks already read as typed tables', () => {
  const { acc } = makeAcc();
  const blocks = [block('b1', 'beacon to 203.0.113.9 observed'), block('b2', 'and 203.0.113.10 observed')];
  readDocumentText(blocks, acc, {
    typeDiag: { syntactic_occurrences: 0, rejected_values: {}, examples: [] },
    tableHandled: new Set(['b2']),
    networkEndpoints: [],
    scanText: (b) => b.text,
    isObservableRow: () => false,
    noteRejectedToken: () => {}
  });
  const values = [...acc.byKey.values()].map((e) => e.value ?? e.normalized_value);
  assert.deepEqual(values, ['203.0.113.9']);
});

test('the passes compose: one typed row plus one sentence, through the orchestrator', () => {
  const doc = {
    blocks: [
      { id: 'h', type: 'heading', level: 2, text: 'Indicators of Compromise' },
      { id: 't', type: 'table', text: 'Type IP\nip 198.51.100.4', table: { headers: ['Type', 'Value'], rows: [['ip', '198.51.100.4']] } },
      { id: 'h2', type: 'heading', level: 2, text: 'Analysis' },
      { id: 'p', type: 'paragraph', text: 'The loader beacons to 198.51.100.5 every hour.' }
    ],
    meta: {}
  };
  const { candidates } = extractCandidatesWithDiagnostics(doc, { sourceUrl: 'https://publisher.example/r' });
  const byValue = new Map(candidates.map((c) => [c.normalizedValue ?? c.normalized_value, c]));
  assert.ok(byValue.has('198.51.100.4'));
  assert.ok(byValue.has('198.51.100.5'));
  assert.equal(byValue.get('198.51.100.4').evidence.occurrences[0].form, 'table_row');
});

test('readTypedTables ignores blocks that are not tables', () => {
  const { acc } = makeAcc();
  const handled = new Set();
  readTypedTables([block('b1', 'nothing tabular here')], acc, {
    diagnostics: { explicit_tables: { tables_seen: 0, ioc_tables: 0, explicit_tables: 0, rows_seen: 0, rows_valid: 0, rows_rejected: 0, rejected_reasons: {}, candidates_from_tables: 0, table_block_ids: [] } },
    explicitTableAssertions: {},
    tableHandled: handled,
    referenceColumnValues: new Map(),
    networkEndpoints: [],
    slashDateOrder: null,
    observationNotAfter: null,
    noteRejectedToken: () => {}
  });
  assert.equal(handled.size, 0);
  assert.equal(acc.byKey.size, 0);
});
