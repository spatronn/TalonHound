export const VT_PROVIDER = 'virustotal';

export const VT_NOT_INDEXED_MESSAGE =
  'VirusTotal has no report for this URL yet. The URL may not have been submitted or indexed.';

/** @param {number} httpStatus */
export function isVtResourceNotFound(httpStatus) {
  return Number(httpStatus) === 404;
}

export function buildVtNotIndexedResponse(overrides = {}) {
  return {
    status: 'not_found',
    provider: VT_PROVIDER,
    message: VT_NOT_INDEXED_MESSAGE,
    is_error: false,
    ...overrides
  };
}

/**
 * Map VT HTTP status to user-facing error message (fatal/integration errors only).
 * @param {number} httpStatus
 */
export function vtHttpErrorMessage(httpStatus) {
  const code = Number(httpStatus);
  if (code === 401 || code === 403) return 'Invalid VirusTotal API key.';
  if (code === 429) return 'VirusTotal rate limit reached. Try again later.';
  return 'VirusTotal enrichment failed.';
}
