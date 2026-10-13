/**
 * Known extraction failures of the benchmark (recorded, NOT accepted).
 *
 * Every entry is a case whose ground truth is still strict: the expectation is
 * never weakened to make the case pass. Tests run these cases as `todo` (the
 * failure stays visible) and fail when a listed case starts passing, so a fix
 * must also retire its entry here and refresh the baseline.
 *
 * Causes were diagnosed on main 7757c5d (tl-zones-v9 / tl-candidates-v25).
 */

export const KNOWN_FAILURE_CAUSES = Object.freeze({
  filename_hash_row_not_scope_content: {
    summary: 'A "<filename> <hash>" line (filename first) is not indicator content for scope continuation',
    detail:
      'documentZones.isIndicatorRowBlock rejects "loader.exe <md5>" lines while indicatorScope.isIndicatorRowShape ' +
      'accepts them, so a sibling sub-heading over such lines closes the IOC appendix and the hashes fall to ' +
      'body_mention (ai_needed_prose_sample_hash). Inside an already-open appendix the same lines are asserted rows.'
  },
  levelless_pdf_sibling_heading: {
    summary: 'A level-less PDF sub-heading over a Filename|MD5 table closes the IOC appendix',
    detail:
      'pdfLayout emits headings without a level, so hierarchy continuation never applies; a structured table is not ' +
      'an indicator row block for the subgroup rule, and a file-hash inventory outside authoritative scope is not ' +
      'self-proving (tl-table-v6). The table rows become body_mention.'
  },
  pdf_merged_filename_hash_lines: {
    summary: 'PDF "filename hash" lines merge into one paragraph that reads as narrative',
    detail:
      'pdfLayout.linesToBlocks merges consecutive non-observable-only lines into one paragraph; inside the appendix ' +
      'the paragraph is narrative (relation marker none) → ai_needed_authoritative_narrative, never an assertion.'
  }
});

/** case id → cause (keys of KNOWN_FAILURE_CAUSES). */
export const KNOWN_BENCHMARK_FAILURES = Object.freeze({
  'layout/html_family_sibling/filename_hash_lines': 'filename_hash_row_not_scope_content',
  'layout/html_c2_then_loaders/filename_hash_lines': 'filename_hash_row_not_scope_content',
  'layout/html_c2_then_nested_plugins/filename_hash_lines': 'filename_hash_row_not_scope_content',
  'layout/html_bold_subsections/filename_hash_lines': 'filename_hash_row_not_scope_content',
  'layout/html_bold_appendix/filename_hash_lines': 'filename_hash_row_not_scope_content',
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
