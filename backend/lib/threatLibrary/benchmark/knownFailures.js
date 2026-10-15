/**
 * Known extraction failures of the benchmark (recorded, NOT accepted).
 *
 * Every entry is a case whose ground truth is still strict: the expectation is
 * never weakened to make the case pass. Tests run these cases as `todo` (the
 * failure stays visible) and fail when a listed case starts passing, so a fix
 * must also retire its entry here and refresh the baseline.
 *
 * P1 release gate:
 * - Current `pdf_*` metamorphic variants emit pdf_v5-shaped blocks and PASS
 *   (parser contract improvement).
 * - `pdf_legacy_*` variants deliberately reproduce pre-v5 residual geometry
 *   (level-less headings; filename/hash lines merged into one paragraph). Those
 *   remain known failures: membership is lost because the source blocks lack
 *   recoverable structure, not because ground truth was relaxed.
 */

export const KNOWN_FAILURE_CAUSES = Object.freeze({
  levelless_pdf_sibling_heading: {
    summary: 'A level-less PDF sub-heading over a Filename|MD5 table closes the IOC appendix',
    detail:
      'When headings carry no level (degraded residual geometry), hierarchy continuation never applies; a structured ' +
      'table is not an indicator row block for the subgroup rule, and a file-hash inventory outside authoritative ' +
      'scope is not self-proving (tl-table-v7). Production pdf_v5 emits inferred levels; these legacy fixtures keep ' +
      'the residual shape so the failure remains visible.'
  },
  pdf_merged_filename_hash_lines: {
    summary: 'PDF "filename hash" lines merge into one paragraph that reads as narrative',
    detail:
      'When consecutive filename/hash inventory lines were already merged into one paragraph before zoning, the ' +
      'block is narrative (relation marker none) → never an assertion. Production pdf_v5 keeps each line as an ' +
      'observable_row via isFilenameHashRowLine; legacy fixtures retain the merged paragraph as unsupported input.'
  }
});

/** case id → cause (keys of KNOWN_FAILURE_CAUSES). */
export const KNOWN_BENCHMARK_FAILURES = Object.freeze({
  'layout/pdf_legacy_typed_subsections/table': 'levelless_pdf_sibling_heading',
  'layout/pdf_legacy_c2_then_loaders/table': 'levelless_pdf_sibling_heading',
  'layout/pdf_legacy_flat/filename_hash_lines': 'pdf_merged_filename_hash_lines',
  'layout/pdf_legacy_typed_subsections/filename_hash_lines': 'pdf_merged_filename_hash_lines',
  'layout/pdf_legacy_c2_then_loaders/filename_hash_lines': 'pdf_merged_filename_hash_lines'
});

/**
 * @param {string} caseId
 * @returns {{ cause: string, summary: string, detail: string }|null}
 */
export function knownFailureFor(caseId) {
  const cause = KNOWN_BENCHMARK_FAILURES[caseId];
  return cause ? { cause, ...KNOWN_FAILURE_CAUSES[cause] } : null;
}
