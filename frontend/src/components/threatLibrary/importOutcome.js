/**
 * URL / PDF import response -> modal outcome. A duplicate is an expected
 * no-op (HTTP 200, `already_imported: true`, `duplicate_reason`) shown as
 * information with a link to the existing report — never as an import error.
 * Branches on the machine-readable fields only, never on message text.
 */

export const IMPORT_DUPLICATE_COPY = Object.freeze({
  url: 'This report has already been imported.',
  sha256: 'This PDF has already been imported.'
});

/**
 * @param {object|null|undefined} data response body of POST /threat-library/import/{url,pdf}
 * @returns {{ kind: 'duplicate', message: string, reportId: string, title: string, importedAt: string|null }
 *   | { kind: 'created', report: object|null }}
 */
export function describeImportOutcome(data) {
  if (data?.already_imported === true && data.report?.id) {
    const reason = data.duplicate_reason === 'sha256' ? 'sha256' : 'url';
    return {
      kind: 'duplicate',
      message: IMPORT_DUPLICATE_COPY[reason],
      reportId: String(data.report.id),
      title: data.report.title || 'Untitled report',
      importedAt: data.report.created_at || null
    };
  }
  return { kind: 'created', report: data?.report || null };
}
