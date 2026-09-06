/** IOC Details header copy-button success feedback (UI only). */

export const IOC_COPY_FEEDBACK_MS = 2000;

/** Soft success green used elsewhere in IOC details dark UI (e.g. status accents). */
export const IOC_COPY_SUCCESS_COLOR = '#86efac';

export function getIocCopyControlLabels(copied) {
  return copied
    ? { ariaLabel: 'Copied', title: 'Copied' }
    : { ariaLabel: 'Copy IOC', title: 'Copy IOC' };
}

/**
 * Copy text via Clipboard API. Success feedback must only run when `{ ok: true }`.
 * @param {string} value
 * @param {{ writeText?: (text: string) => Promise<void> } | null | undefined} [clipboard]
 */
export async function copyTextToClipboard(value, clipboard = globalThis.navigator?.clipboard) {
  const text = String(value ?? '').trim();
  if (!text || text === '-') return { ok: false, reason: 'empty' };
  if (!clipboard?.writeText) return { ok: false, reason: 'unsupported' };
  try {
    await clipboard.writeText(text);
    return { ok: true };
  } catch {
    return { ok: false, reason: 'failed' };
  }
}

/**
 * @returns {{ copied: true, feedbackEpoch: number }}
 * Callers should apply both fields so a re-click while already in the success
 * state still restarts the feedback window (epoch change retriggers the effect).
 */
export function beginCopiedFeedback(feedbackEpoch) {
  return {
    copied: true,
    feedbackEpoch: Number(feedbackEpoch || 0) + 1
  };
}

/**
 * Schedule / restart temporary "copied" UI state using explicit global timers.
 * Prefer the React effect pattern in IocHeader; this helper remains for unit tests.
 * @param {{ current: ReturnType<typeof setTimeout> | null }} timerRef
 * @param {(copied: boolean) => void} setCopied
 * @param {number} [delayMs]
 * @param {{ setTimeout: typeof setTimeout, clearTimeout: typeof clearTimeout }} [timers]
 */
export function scheduleCopiedFeedbackReset(
  timerRef,
  setCopied,
  delayMs = IOC_COPY_FEEDBACK_MS,
  timers = {
    setTimeout: (...args) => globalThis.setTimeout(...args),
    clearTimeout: (id) => globalThis.clearTimeout(id)
  }
) {
  if (timerRef.current != null) timers.clearTimeout(timerRef.current);
  setCopied(true);
  timerRef.current = timers.setTimeout(() => {
    setCopied(false);
    timerRef.current = null;
  }, delayMs);
}

/** Clear pending feedback timeout (e.g. on unmount). */
export function clearCopiedFeedbackTimer(
  timerRef,
  timers = { clearTimeout: (id) => globalThis.clearTimeout(id) }
) {
  if (timerRef.current != null) {
    timers.clearTimeout(timerRef.current);
    timerRef.current = null;
  }
}
