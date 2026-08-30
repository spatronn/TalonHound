// Classify a raw worker/DB export failure into a safe, user-facing reason.
//
// The Action Center shows `failure_reason` verbatim, so raw PostgreSQL text must never be
// stored there: it can contain shared-memory object names ("/PostgreSQL.NNNN"), SQL
// fragments, file paths, or connection details. The worker persists ONLY the returned
// `publicMessage` as the row's failure_reason and keeps the full technical error in the
// server-side audit log / container logs, correlated by export id.
//
// Only the shared-memory class maps to a specific, actionable message (and only when it is
// actually detected). Everything else falls back to a single safe generic message.

export const EXPORT_FAILURE_CODES = Object.freeze({
  INSUFFICIENT_SHARED_MEMORY: 'insufficient_shared_memory',
  UNEXPECTED: 'unexpected_error'
});

const PUBLIC_MESSAGES = Object.freeze({
  [EXPORT_FAILURE_CODES.INSUFFICIENT_SHARED_MEMORY]:
    'Export failed due to insufficient database shared memory. Check server resources and retry.',
  [EXPORT_FAILURE_CODES.UNEXPECTED]:
    'Export failed due to an unexpected server error. Please retry; if it keeps failing, contact an administrator.'
});

export function exportFailurePublicMessage(code) {
  return PUBLIC_MESSAGES[code] || PUBLIC_MESSAGES[EXPORT_FAILURE_CODES.UNEXPECTED];
}

/**
 * @param {unknown} err  Raw error thrown by the worker/pg driver.
 * @returns {{ code: string, publicMessage: string }}
 */
export function classifyExportFailure(err) {
  const message = err && (err.message || (typeof err === 'string' ? err : '')) ? String(err.message || err) : '';
  const text = message.toLowerCase();
  const sqlstate = err && err.code ? String(err.code) : '';

  // PostgreSQL failed to size a dynamic shared-memory (DSM) segment for a parallel plan.
  // Typical text: `could not resize shared memory segment "/PostgreSQL.123" to 33554432
  // bytes: No space left on device`. Match the shared-memory wording specifically so a
  // plain disk-full ("No space left on device") on temp files is NOT mislabeled as this.
  const isSharedMemory =
    /shared memory segment/.test(text) ||
    /could not resize shared memory/.test(text) ||
    /dynamic shared memory/.test(text) ||
    /out of shared memory/.test(text);

  if (isSharedMemory) {
    return {
      code: EXPORT_FAILURE_CODES.INSUFFICIENT_SHARED_MEMORY,
      publicMessage: PUBLIC_MESSAGES[EXPORT_FAILURE_CODES.INSUFFICIENT_SHARED_MEMORY]
    };
  }

  // Reserved for future explicit sqlstate handling; unused today but keeps the shape clear.
  void sqlstate;

  return {
    code: EXPORT_FAILURE_CODES.UNEXPECTED,
    publicMessage: PUBLIC_MESSAGES[EXPORT_FAILURE_CODES.UNEXPECTED]
  };
}
