import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const intelligenceTabSrc = readFileSync(join(here, '..', 'intelligenceTab.jsx'), 'utf8');

// Index of a section's render marker within IntelligenceTabPanel's output.
// Each `<Component` open-tag / title marker appears exactly once in the render
// path, so a plain indexOf reflects its top-to-bottom position on the page.
function markerIndex(marker) {
  const idx = intelligenceTabSrc.indexOf(marker);
  assert.ok(idx >= 0, `expected render marker ${marker} to be present`);
  // Uniqueness guard: a duplicate marker would make ordering assertions lie.
  assert.equal(
    intelligenceTabSrc.indexOf(marker, idx + 1),
    -1,
    `render marker ${marker} must appear exactly once`
  );
  return idx;
}

test('Analyst Intelligence renders after every other intelligence section', () => {
  const analyst = markerIndex('<AnalystIntelligenceSection');
  const summary = markerIndex('<IntelligenceSummarySection');
  const automated = markerIndex('>Automated Intelligence<');
  const derived = markerIndex('<DerivedInfrastructureSection');
  const fileInfo = markerIndex('<FileArtifactInformationCard');

  assert.ok(summary < analyst, 'Intelligence Summary must be above Analyst Intelligence');
  assert.ok(automated < analyst, 'Automated Intelligence must be above Analyst Intelligence');
  assert.ok(derived < analyst, 'Derived Infrastructure must be above Analyst Intelligence');
  assert.ok(fileInfo < analyst, 'File Information must be above Analyst Intelligence');
});

test('hash: Automated Intelligence -> File Information order in render', () => {
  const automated = markerIndex('>Automated Intelligence<');
  const fileInfo = markerIndex('<FileArtifactInformationCard');
  assert.ok(automated < fileInfo, 'Automated Intelligence must render above File Information');
});

test('URL: Automated Intelligence -> Derived Infrastructure order in render', () => {
  const automated = markerIndex('>Automated Intelligence<');
  const derived = markerIndex('<DerivedInfrastructureSection');
  assert.ok(automated < derived, 'Automated Intelligence must render above Derived Infrastructure');
});

test('section layout is driven by the shared ordering helper (not hard-coded)', () => {
  assert.match(intelligenceTabSrc, /buildIntelligenceSectionOrder/);
  assert.match(intelligenceTabSrc, /sectionOrder\.map/);
});
