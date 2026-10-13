/**
 * Metamorphic layout regression: the same publisher IOC set rendered in
 * structurally equivalent layouts (heading hierarchies, bold labels, tables,
 * <pre> inventories, filename/hash pairs, level-less PDF headings, mixed C2 /
 * loader subsections) must yield the same report Indicators.
 *
 * Expectations are strict for every variant. Known failures (knownFailures.js)
 * run as `todo` so they stay visible without blocking; the ratchet test fails
 * once a known failure passes, so its registry entry and the baseline are
 * retired together with the fix.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildLayoutVariant, layoutVariantGroundTruth, listLayoutVariantIds } from './layoutVariants.js';
import { groundTruthIdentity, scoreBenchmarkCase } from './benchmarkMetrics.js';
import { extractReportCandidates } from '../extractionStages.js';
import { KNOWN_BENCHMARK_FAILURES, KNOWN_FAILURE_CAUSES, knownFailureFor } from './knownFailures.js';

const GROUND_TRUTH = layoutVariantGroundTruth();
const EXPECTED = [...new Set(GROUND_TRUTH.indicators.map(groundTruthIdentity))].sort();

function score(variantId) {
  const v = buildLayoutVariant(variantId);
  const extracted = extractReportCandidates({ source_type: v.format === 'pdf' ? 'pdf' : 'url', source_url: v.sourceUrl }, v.document);
  return scoreBenchmarkCase({ groundTruth: GROUND_TRUTH, candidates: extracted.candidates, blocks: extracted.annotated.blocks });
}

const VARIANTS = listLayoutVariantIds();

test('variant grid covers every required layout family', () => {
  const structures = new Set(VARIANTS.map((v) => v.split('/')[0]));
  for (const s of [
    'html_typed_subsections', 'html_c2_then_loaders', 'html_c2_then_nested_plugins',
    'html_bold_subsections', 'html_bold_appendix', 'pdf_typed_subsections', 'pdf_c2_then_loaders'
  ]) assert.ok(structures.has(s), s);
  const reprs = new Set(VARIANTS.map((v) => v.split('/')[1]));
  for (const r of ['table', 'hash_lines', 'hash_filename_lines', 'filename_hash_lines']) assert.ok(reprs.has(r), r);
  assert.equal(EXPECTED.length, 6);
});

for (const variantId of VARIANTS) {
  const known = knownFailureFor(`layout/${variantId}`);
  test(
    `layout ${variantId}: all publisher IOCs are report Indicators with an explicit assertion`,
    known ? { todo: `known failure (${known.cause}): ${known.summary}` } : {},
    () => {
      const m = score(variantId);
      assert.deepEqual(m.members, EXPECTED, `Indicator membership for ${variantId}`);
      assert.equal(m.indicators.fn_not_extracted, 0, 'every value is extracted as a candidate');
      assert.equal(m.assertions.correct, m.assertions.checked, 'every Indicator carries an explicit publisher assertion');
    }
  );
}

test('known-failure registry is current: every listed case still fails, and for a recorded reason', () => {
  const stale = [];
  for (const [caseId, cause] of Object.entries(KNOWN_BENCHMARK_FAILURES)) {
    assert.ok(KNOWN_FAILURE_CAUSES[cause], `${caseId}: unknown cause ${cause}`);
    const variantId = caseId.replace(/^layout\//, '');
    assert.ok(VARIANTS.includes(variantId), `${caseId} is not a generated variant`);
    const m = score(variantId);
    if (m.indicators.fn === 0 && m.indicators.fp === 0) stale.push(caseId);
    // A known failure is a membership failure: candidate extraction is intact.
    else assert.equal(m.indicators.fn_not_extracted, 0, `${caseId}: extraction regressed, not only membership`);
  }
  assert.deepEqual(
    stale,
    [],
    'these known failures now pass — remove them from knownFailures.js and run `npm run benchmark:threat-library -- --write-baseline`'
  );
});

test('metamorphic invariance: every passing layout yields one identical Indicator set', () => {
  const sets = new Map();
  for (const variantId of VARIANTS) {
    if (knownFailureFor(`layout/${variantId}`)) continue;
    sets.set(variantId, score(variantId).members.join(','));
  }
  assert.deepEqual([...new Set(sets.values())], [EXPECTED.join(',')]);
});
