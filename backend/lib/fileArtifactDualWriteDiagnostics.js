/**
 * Safe diagnostics for best-effort file-artifact dual-write.
 *
 * Dual-write is a secondary write after the primary operation (custom feed
 * import, manual IOC create, VirusTotal enrichment). It must never fail the
 * primary operation and must never fail silently. It fails in two ways: a
 * thrown error (module load, uncontrolled DB error) or a controlled
 * `{ ok: false }` result. Both are described the same way here, with raw
 * observables / hashes and caller-supplied secrets removed from the message.
 *
 * Kept outside lib/fileArtifacts/ on purpose: callers import this statically,
 * while the dual-write module itself stays a lazy import that may fail.
 */

const MESSAGE_MAX = 300;
// md5 / sha1 / sha256 / sha512 shaped hex runs.
const HEX_HASH = /\b(?:[a-f0-9]{128}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi;
// Credential-shaped fragments an error string may echo (headers, key=value, URLs).
const BEARER = /\b(bearer|basic)\s+[^\s,;'"]+/gi;
const SECRET_ASSIGNMENT = /\b(authorization|x-apikey|api[-_]?key|token|secret|password)(\s*[:=]\s*)[^\s,;'"]+/gi;
const CONNECTION_URL = /\b(postgres(?:ql)?|redis|https?):\/\/[^\s'"]+/gi;

export const FILE_ARTIFACT_DUAL_WRITE_OPERATION = 'file_artifact_dual_write';

/** A dual-write result that reports a controlled failure without throwing. */
export function isFileArtifactDualWriteFailureResult(result) {
  return Boolean(result) && result.ok === false;
}

/**
 * @param {any} failure - thrown error, or a dual-write `{ ok: false }` result
 * @param {{ redactValues?: Array<string|null|undefined>, redact?: (msg: string) => string }} [opts]
 * @returns {{ error_code: string, error_class: string, error_message: string }}
 */
export function describeFileArtifactDualWriteFailure(failure, { redactValues = [], redact = null } = {}) {
  const isError = failure instanceof Error;
  let msg = String((isError ? failure.message : (failure?.error ?? failure)) || '');
  for (const value of redactValues) {
    const v = value == null ? '' : String(value);
    if (v) msg = msg.replace(new RegExp(v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '<observable>');
  }
  msg = msg
    .replace(CONNECTION_URL, '$1://[REDACTED]')
    .replace(BEARER, '$1 [REDACTED]')
    .replace(SECRET_ASSIGNMENT, '$1$2[REDACTED]')
    .replace(HEX_HASH, '<hash>');
  if (typeof redact === 'function') msg = redact(msg) || '';
  return {
    error_code: String(failure?.code || failure?.name || 'unknown'),
    error_class: isError ? failure.constructor.name : 'DualWriteResult',
    error_message: msg.replace(/\s+/g, ' ').trim().slice(0, MESSAGE_MAX)
  };
}

/**
 * Request-level (one IOC per call) best-effort dual-write: never throws, logs
 * one structured warning per failed call, nothing on success or skip.
 *
 * @param {{
 *   run: () => Promise<any>,
 *   logger: { warn: (message: string, fields: object) => void },
 *   fields: Record<string, unknown>,
 *   redactValues?: Array<string|null|undefined>
 * }} input
 * @returns {Promise<{ ok: boolean, result?: any }>}
 */
export async function runBestEffortFileArtifactDualWrite({ run, logger, fields, redactValues = [] }) {
  let failure;
  try {
    const result = await run();
    if (!isFileArtifactDualWriteFailureResult(result)) return { ok: true, result };
    failure = result;
  } catch (err) {
    failure = err;
  }
  logger.warn('file-artifact dual-write failed; primary operation continues', {
    ...fields,
    operation: FILE_ARTIFACT_DUAL_WRITE_OPERATION,
    result: 'failed',
    ...describeFileArtifactDualWriteFailure(failure, { redactValues })
  });
  return { ok: false };
}
