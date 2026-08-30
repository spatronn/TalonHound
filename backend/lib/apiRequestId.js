import crypto from 'node:crypto';

const HDR_REQUEST_ID = 'x-request-id';
const HDR_CORRELATION_ID = 'x-correlation-id';

/**
 * Reuse client-supplied request/correlation id when present; otherwise generate one.
 * Attaches `req.requestId` and response header `X-Request-Id`.
 */
export function ensureRequestId(req, res) {
  if (req.requestId) {
    if (res && !res.getHeader(HDR_REQUEST_ID)) {
      res.setHeader(HDR_REQUEST_ID, req.requestId);
    }
    return req.requestId;
  }
  const incoming = req?.headers?.[HDR_REQUEST_ID] || req?.headers?.[HDR_CORRELATION_ID];
  const id = incoming
    ? String(incoming).trim().slice(0, 128)
    : `req_${crypto.randomBytes(12).toString('hex')}`;
  req.requestId = id;
  if (res) res.setHeader(HDR_REQUEST_ID, id);
  return id;
}
