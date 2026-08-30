import { ensureRequestId } from './apiRequestId.js';

export const API_ERROR_CODE = Object.freeze({
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_IOC_TYPE: 'INVALID_IOC_TYPE',
  INVALID_IOC_VALUE: 'INVALID_IOC_VALUE',
  IOC_NOT_FOUND: 'IOC_NOT_FOUND',
  INVALID_API_KEY: 'INVALID_API_KEY',
  API_KEY_DISABLED: 'API_KEY_DISABLED',
  INSUFFICIENT_SCOPE: 'INSUFFICIENT_SCOPE',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  QUERY_TOO_EXPENSIVE: 'QUERY_TOO_EXPENSIVE',
  INTERNAL_ERROR: 'INTERNAL_ERROR'
});

/**
 * Send the canonical /api/v1 error envelope.
 * @param {import('express').Response} res
 * @param {number} status
 * @param {string} code
 * @param {string} message
 * @param {import('express').Request} [req]
 * @param {{ details?: unknown }} [opts]
 */
export function sendApiError(res, status, code, message, req, opts = {}) {
  const requestId = req ? ensureRequestId(req, res) : (res.getHeader?.('x-request-id') || null);
  const body = {
    error: {
      code: String(code || API_ERROR_CODE.INTERNAL_ERROR),
      message: String(message || 'An error occurred'),
      request_id: requestId || undefined
    }
  };
  if (opts.details != null) {
    body.error.details = opts.details;
  }
  res.set('Cache-Control', 'no-store');
  return res.status(status).json(body);
}
