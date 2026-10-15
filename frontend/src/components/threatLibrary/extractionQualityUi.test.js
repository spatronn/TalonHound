import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  QUALITY_CODE_COPY,
  QUALITY_DISCLAIMER,
  describeExtractionQuality,
  describeQualityChip,
  splitIdentity
} from './extractionQualityUi.js';

const here = path.dirname(fileURLToPath(import.meta.url));

const QUALITY = {
  version: 'tl-quality-v1',
  mode: 'A',
  status: 'high',
  counts: { high: 1, warning: 1, info: 1 },
  warnings_total: 3,
  warnings: [
    {
      code: 'authoritative_section_empty',
      severity: 'info',
      explanation: 'internal text',
      candidates: [],
      candidate_count: 0,
      block_ids: ['b9'],
      section: { heading: 'IOCs', zone: 'explicit_ioc_section', opened_by: 'b9' },
      extractor_version: { quality: 'tl-quality-v1', zones: 'tl-zones-v9' }
    },
    {
      code: 'indicator_rows_adjacent_to_authoritative_scope',
      severity: 'warning',
      explanation: '4 row-shaped IOC values … MODE A …',
      candidates: ['md5:aaaa', 'md5:bbbb', 'md5:cccc', 'md5:dddd', 'md5:eeee', 'md5:ffff', 'md5:0000'],
      candidate_count: 9,
      block_ids: ['b7', 'b8'],
      section: { heading: 'Loaders', zone: 'report_body', adjacent_authoritative_block: 'b5', adjacent_authoritative_heading: 'C2 servers' },
      evidence: [{ block_id: 'b7', text: 'loader.exe aaaa' }],
      extractor_version: { quality: 'tl-quality-v1' }
    },
    {
      code: 'appendix_without_hash_indicators',
      severity: 'high',
      candidates: ['md5:aaaa', 'url:http://198.51.100.1:8080/x'],
      candidate_count: 2,
      section: { heading: 'Indicators of compromise', zone: 'explicit_ioc_section' }
    }
  ]
};

test('every backend reason code has analyst wording', () => {
  const backend = fs.readFileSync(path.join(here, '..', '..', '..', '..', 'backend', 'lib', 'threatLibrary', 'extractionQuality.js'), 'utf8');
  const block = backend.slice(backend.indexOf('export const QUALITY_CODES'), backend.indexOf('});', backend.indexOf('export const QUALITY_CODES')));
  const codes = [...block.matchAll(/:\s*'([a-z_]+)'/g)].map((m) => m[1]);
  assert.ok(codes.length >= 15, 'parsed the backend code list');
  for (const code of codes) assert.ok(QUALITY_CODE_COPY[code], `missing UI copy for ${code}`);
});

test('quality model: sorted by severity, status label, headline counts attention vs notes', () => {
  const m = describeExtractionQuality(QUALITY);
  assert.equal(m.assessed, true);
  assert.equal(m.statusLabel, 'Likely incomplete');
  assert.equal(m.tone, 'danger');
  assert.deepEqual(m.items.map((i) => i.severity), ['high', 'warning', 'info']);
  assert.equal(m.attention, 2);
  assert.equal(m.headline, '2 checks need review · 1 note');
  assert.equal(m.disclaimer, QUALITY_DISCLAIMER);
  assert.match(m.disclaimer, /not confirmed errors/);
});

test('warning item: analyst wording, section context, bounded values, no parser internals', () => {
  const item = describeExtractionQuality(QUALITY).items.find((i) => i.code === 'indicator_rows_adjacent_to_authoritative_scope');
  assert.equal(item.title, 'Indicator-like rows just outside the IOC section');
  assert.match(item.why, /sub-heading may have ended the IOC section/);
  assert.equal(item.context, 'Under “Loaders”, next to “C2 servers”.');
  assert.equal(item.values.length, 5);
  assert.equal(item.moreValues, 4, 'candidate_count 9 − 5 shown');
  assert.deepEqual(item.values[0], { type: 'md5', value: 'aaaa', typeLabel: 'MD5' });
  const text = JSON.stringify(describeExtractionQuality(QUALITY));
  for (const internal of ['block_ids', 'b7', 'explicit_ioc_section', 'report_body', 'tl-zones', 'MODE A', 'extractor_version', 'internal text']) {
    assert.equal(text.includes(internal), false, `exposes ${internal}`);
  }
});

test('identities split on the first colon (URLs keep their own colons)', () => {
  assert.deepEqual(splitIdentity('url:http://198.51.100.1:8080/x'), { type: 'url', value: 'http://198.51.100.1:8080/x' });
  assert.deepEqual(splitIdentity('plain'), { type: '', value: 'plain' });
});

test('not yet assessed and clean reports', () => {
  const none = describeExtractionQuality(null);
  assert.equal(none.assessed, false);
  assert.equal(none.statusLabel, 'Not checked yet');
  assert.equal(describeQualityChip(null), null);
  const clean = describeExtractionQuality({ version: 'tl-quality-v1', status: 'clean', counts: { high: 0, warning: 0, info: 0 }, warnings: [] });
  assert.equal(clean.statusLabel, 'No issues found');
  assert.equal(clean.headline, 'No issues found by the automatic checks.');
  assert.equal(describeQualityChip({ status: 'info', warnings: [{ code: 'authoritative_section_empty', severity: 'info' }] }), null, 'notes alone get no header chip');
});

test('header chip only when something needs review, and says it is a signal', () => {
  const chip = describeQualityChip(QUALITY);
  assert.equal(chip.label, 'Extraction check · 2');
  assert.equal(chip.tone, 'danger');
  assert.match(chip.title, /not a confirmed error/);
});

test('unknown codes degrade to a generic, internal-free item', () => {
  const m = describeExtractionQuality({ status: 'warning', warnings: [{ code: 'future_check', severity: 'warning', explanation: 'zone=foo' }] });
  assert.equal(m.items[0].title, 'Extraction check');
  assert.equal(JSON.stringify(m).includes('zone=foo'), false);
});
