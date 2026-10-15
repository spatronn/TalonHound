/**
 * Known extraction failures of the benchmark (recorded, NOT accepted).
 *
 * Every entry is a case whose ground truth is still strict: the expectation is
 * never weakened to make the case pass. Tests run these cases as `todo` (the
 * failure stays visible) and fail when a listed case starts passing, so a fix
 * must also retire its entry here and refresh the baseline.
 *
 * Causes were diagnosed on main 7757c5d (tl-zones-v9 / tl-candidates-v25).
 * P1 (tl-zones-v10 / tl-candidates-v26) retired the five HTML filename-first
 * row-scope failures via isAnnotatedIndicatorRowLine alignment.
 */

export const KNOWN_FAILURE_CAUSES = Object.freeze({
  levelless_pdf_sibling_heading: {
    summary: 'A level-less PDF sub-heading over a Filename|MD5 table closes the IOC appendix',
    detail:
      'pdfLayout emits headings without a level, so hierarchy continuation never applies; a structured table is not ' +
      'an indicator row block for the subgroup rule, and a file-hash inventory outside authoritative scope is not ' +
      'self-proving (tl-table-v6). The table rows become body_mention. P1 adds inferPdfHeadingLevel; remaining ' +
      'failures need measured confirmation that font/numbering ranks match publisher nesting on these fixtures.'
  },
  pdf_merged_filename_hash_lines: {
    summary: 'PDF "filename hash" lines merge into one paragraph that reads as narrative',
    detail:
      'pdfLayout.linesToBlocks merges consecutive non-observable-only lines into one paragraph; inside the appendix ' +
      'the paragraph is narrative (relation marker none) → ai_needed_authoritative_narrative, never an assertion. ' +
      'P1 emits isFilenameHashRowLine as observable_row; remaining failures are fixture geometry that still merges.'
  }
});

/** case id → cause (keys of KNOWN_FAILURE_CAUSES). */
export const KNOWN_BENCHMARK_FAILURES = Object.freeze({
  'layout/pdf_typed_subsections/table': 'levelless_pdf_sibling_heading',
  'layout/pdf_c2_then_loaders/table': 'levelless_pdf_sibling_heading',
  'layout/pdf_flat/filename_hash_lines': 'pdf_merged_filename_hash_lines',
  'layout/pdf_typed_subsections/filename_hash_lines': 'pdf_merged_filename_hash_lines',
  'layout/pdf_c2_then_loaders/filename_hash_lines': 'pdf_merged_filename_hash_lines'
});

/**
 * @param {string} caseId
 * @returns {{ cause: string, summary: string, detail: string }|null}
 */
export function knownFailureFor(caseId) {
  const cause = KNOWN_BENCHMARK_FAILURES[caseId];
  return cause ? { cause, ...KNOWN_FAILURE_CAUSES[cause] } : null;
}
