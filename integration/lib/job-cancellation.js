import { FAILURE_MESSAGES, FAILURE_TYPES } from './integrationQueueConfig.js';

export class IntegrationJobAbortedError extends Error {
  constructor(message = FAILURE_MESSAGES.aborted, failureType = FAILURE_TYPES.ABORTED) {
    super(message);
    this.name = 'IntegrationJobAbortedError';
    this.failureType = failureType;
  }
}

function resolveAbortFailureType(signal) {
  const reason = signal?.reason;
  if (reason === FAILURE_TYPES.TIMEOUT) return FAILURE_TYPES.TIMEOUT;
  if (reason === FAILURE_TYPES.WORKER_SHUTDOWN) return FAILURE_TYPES.WORKER_SHUTDOWN;
  if (reason === FAILURE_TYPES.STALE) return FAILURE_TYPES.STALE;
  return FAILURE_TYPES.ABORTED;
}

function resolveAbortMessage(failureType) {
  if (failureType === FAILURE_TYPES.TIMEOUT) return FAILURE_MESSAGES.timeout;
  if (failureType === FAILURE_TYPES.WORKER_SHUTDOWN) return FAILURE_MESSAGES.worker_shutdown;
  if (failureType === FAILURE_TYPES.STALE) return FAILURE_MESSAGES.stale;
  return FAILURE_MESSAGES.aborted;
}

export function throwIfAborted(signal) {
  if (!signal?.aborted) return;
  const failureType = resolveAbortFailureType(signal);
  throw new IntegrationJobAbortedError(resolveAbortMessage(failureType), failureType);
}

export function isJobAbortedError(err) {
  return err?.name === 'IntegrationJobAbortedError' || err?.name === 'AbortError';
}

export function resolveJobFailureType(err) {
  if (err?.failureType) return err.failureType;
  if (isJobAbortedError(err)) return err.failureType || FAILURE_TYPES.ABORTED;
  return null;
}

/** Merge fetch init with an optional AbortSignal (native fetch cancellation). */
export function fetchWithSignal(url, init = {}, signal) {
  throwIfAborted(signal);
  const merged = { ...init };
  if (signal) merged.signal = signal;
  return fetch(url, merged);
}

/**
 * Run import under AbortController; abort propagates to signal and import settles before return.
 */
export async function runCancellableImport(runFn, { signal, onAbort } = {}) {
  throwIfAborted(signal);
  try {
    return await runFn({ signal });
  } catch (err) {
    if (isJobAbortedError(err) && typeof onAbort === 'function') {
      await onAbort(err).catch(() => {});
    }
    throw err;
  }
}
