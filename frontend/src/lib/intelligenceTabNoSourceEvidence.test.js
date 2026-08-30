import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const intelligenceTabSrc = readFileSync(join(here, '..', 'intelligenceTab.jsx'), 'utf8');

test('Intelligence tab does not render Source Evidence section', () => {
  assert.equal(intelligenceTabSrc.includes('Source Evidence'), false);
  assert.equal(intelligenceTabSrc.includes('SourceEvidenceSection'), false);
  assert.equal(intelligenceTabSrc.includes('groupFileArtifactObservations'), false);
  assert.equal(intelligenceTabSrc.includes('Additional Known Hashes'), false);
  assert.equal(intelligenceTabSrc.includes('Observed As'), false);
});

test('Intelligence tab still renders File Information for hash IOCs', () => {
  assert.match(intelligenceTabSrc, /File Information/);
  assert.match(intelligenceTabSrc, /FileArtifactInformationCard/);
  assert.match(intelligenceTabSrc, /Known Hashes/);
  assert.match(intelligenceTabSrc, /Primary Identifier/);
});
