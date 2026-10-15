/**
 * Known extraction failures of the benchmark (recorded, NOT accepted).
 *
 * Every entry is a case whose ground truth is still strict: the expectation is
 * never weakened to make the case pass. Tests run these cases as `todo` (the
 * failure stays visible) and fail when a listed case starts passing, so a fix
 * must also retire its entry here and refresh the baseline.
 *
 * P1 gate: pdfVariant fixtures now emit pdf_v5-shaped blocks (inferred heading
 * levels + filename/hash observable rows). The five prior PDF layout todos
 * pass under that contract and are retired. Remaining PDF risk is real scanned
 * / low-quality geometry that still merges lines before pdfLayout sees them —
 * not covered by the constructed metamorphic fixtures.
 */

export const KNOWN_FAILURE_CAUSES = Object.freeze({});

/** case id → cause (keys of KNOWN_FAILURE_CAUSES). */
export const KNOWN_BENCHMARK_FAILURES = Object.freeze({});

/**
 * @param {string} caseId
 * @returns {{ cause: string, summary: string, detail: string }|null}
 */
export function knownFailureFor(caseId) {
  const cause = KNOWN_BENCHMARK_FAILURES[caseId];
  return cause ? { cause, ...KNOWN_FAILURE_CAUSES[cause] } : null;
}
