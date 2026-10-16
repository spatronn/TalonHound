/**
 * Known extraction failures of the benchmark (recorded, NOT accepted).
 *
 * Every entry is a case whose ground truth is still strict: the expectation is
 * never weakened to make the case pass. Tests run these cases as `todo` (the
 * failure stays visible) and fail when a listed case starts passing, so a fix
 * must also retire its entry here and refresh the baseline.
 *
 * Retired in P1.1 (tl-zones-v11 / tl-candidates-v28 / threat_library_pdf_v6):
 * - `levelless_pdf_sibling_heading` (pdf_legacy_typed_subsections/table,
 *   pdf_legacy_c2_then_loaders/table): an indicator-group sub-label over a
 *   Filename|MD5 table now keeps the open IOC section exactly as it does over
 *   indicator rows. The same defect occurred in pdf_v5 output whenever the
 *   appendix heading and its sub-headings inferred the same level (bold-only
 *   headings without numbering or a size step).
 * - `pdf_merged_filename_hash_lines` (pdf_legacy_{flat,typed_subsections,
 *   c2_then_loaders}/filename_hash_lines): a block that is exclusively
 *   filename/hash pairs is read as an observable row with one pair per line.
 *   pdf_v5 produced the same narrative paragraph for any visual line holding
 *   three or more pairs; pdf_v6 emits those lines as rows.
 *
 * Remaining ambiguity is pinned by layoutAmbiguity.test.js, not listed here:
 * with equal or unknown heading levels, a sub-heading whose label names no
 * indicator group ("Plugins") after a C2 child section closes scope — the
 * hierarchy is not recoverable from the blocks and the conservative reading
 * is kept.
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
