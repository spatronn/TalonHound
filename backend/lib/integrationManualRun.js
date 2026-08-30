import { normalizeUsomRunMode } from './usomReconciliation.js';

/** True when the client sent a non-blank run_mode value. */
export function hasExplicitRunMode(value) {
  return value != null && String(value).trim() !== '';
}

/**
 * Resolve manual /run-now run_mode in a feed-aware way.
 * - Non-USOM: absent / null / blank are ignored; any explicit value is rejected.
 * - USOM: normalize via normalizeUsomRunMode (blank defaults to incremental).
 */
export function resolveManualIntegrationRunMode(key, requestedModeRaw) {
  if (key !== 'usom-trcert') {
    if (hasExplicitRunMode(requestedModeRaw)) {
      return {
        ok: false,
        status: 400,
        message: 'run_mode is supported only for usom-trcert'
      };
    }
    return { ok: true, runMode: null };
  }

  const runMode = normalizeUsomRunMode(requestedModeRaw);
  if (!runMode) {
    return {
      ok: false,
      status: 400,
      message: 'Invalid run_mode. Expected incremental or full_reconciliation.'
    };
  }
  return { ok: true, runMode };
}
