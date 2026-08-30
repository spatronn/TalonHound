/**
 * IOC Stats recalculation UI helpers (IOC List page).
 * Pure helpers so confirm / busy / 409 handling can be unit-tested without mounting the page.
 */

export const IOC_STATS_RECALCULATE_LABEL = 'Recalculate stats';
export const IOC_STATS_RECALCULATING_LABEL = 'Recalculating...';
export const IOC_STATS_RECALCULATION_IN_PROGRESS = 'ioc_stats_recalculation_in_progress';

export const IOC_STATS_RECALCULATE_SUCCESS_TOAST = 'IOC statistics recalculated successfully.';
export const IOC_STATS_RECALCULATE_ALREADY_RUNNING_TOAST =
  'IOC statistics recalculation is already in progress.';

export function iocStatsRecalculateConfirmOptions() {
  return {
    title: 'Recalculate IOC statistics?',
    description:
      'This will recalculate IOC statistics in the background. The process may take a few minutes.',
    confirmLabel: 'Recalculate',
    cancelLabel: 'Cancel',
    variant: 'primary'
  };
}

export function iocStatsRecalculateButtonLabel({ busy = false, refreshInProgress = false } = {}) {
  return busy || refreshInProgress
    ? IOC_STATS_RECALCULATING_LABEL
    : IOC_STATS_RECALCULATE_LABEL;
}

export function shouldDisableIocStatsRecalculateButton({
  canWrite = false,
  busy = false,
  refreshInProgress = false
} = {}) {
  return !canWrite || busy || refreshInProgress;
}

/**
 * @param {unknown} err
 */
export function isIocStatsRecalculationInProgressError(err) {
  const status = err?.response?.status;
  const data = err?.response?.data || {};
  const code = String(data.error || data.code || '');
  return status === 409 && code === IOC_STATS_RECALCULATION_IN_PROGRESS;
}

/**
 * Drive the confirm → POST → busy-state flow. API is injected for tests.
 *
 * Uses AppConfirm Mode B (`onConfirm`) so Recalculate shows Working… and is
 * disabled for the POST round-trip (blocks Enter / double-click). Hard failures
 * rethrow so the modal stays open with the error; already-in-progress does not.
 *
 * @param {object} deps
 * @param {(opts: object) => Promise<boolean>} deps.requestConfirm
 * @param {boolean} deps.canWrite
 * @param {() => boolean} deps.isBlocked  true when already busy / in progress
 * @param {() => Promise<{ data?: object }>} deps.postRefresh
 * @param {(busy: boolean) => void} deps.setBusy
 * @param {(kind: 'started'|'already_running'|'error'|'cancelled'|'blocked', payload?: unknown) => void} [deps.onOutcome]
 */
export async function runIocStatsRecalculateRequest(deps) {
  const {
    requestConfirm,
    canWrite,
    isBlocked,
    postRefresh,
    setBusy,
    onOutcome = () => {}
  } = deps;

  if (!canWrite || isBlocked()) {
    onOutcome('blocked');
    return { started: false, reason: 'blocked' };
  }

  let outcome = { started: false, reason: 'cancelled' };

  const ok = await requestConfirm({
    ...iocStatsRecalculateConfirmOptions(),
    onConfirm: async () => {
      if (isBlocked()) {
        outcome = { started: false, reason: 'blocked' };
        return;
      }
      setBusy(true);
      try {
        const { data } = await postRefresh();
        outcome = { started: true, reason: 'started', data };
        onOutcome('started', data);
      } catch (err) {
        if (isIocStatsRecalculationInProgressError(err)) {
          outcome = { started: false, reason: 'already_running', error: err };
          onOutcome('already_running', err);
          return;
        }
        setBusy(false);
        outcome = { started: false, reason: 'error', error: err };
        onOutcome('error', err);
        throw err;
      }
    }
  });

  if (!ok && outcome.reason === 'cancelled') {
    onOutcome('cancelled');
  }
  return outcome;
}
