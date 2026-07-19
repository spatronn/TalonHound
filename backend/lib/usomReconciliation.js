export const USOM_INCREMENTAL_MODE = 'incremental';
export const USOM_FULL_RECONCILIATION_MODE = 'full_reconciliation';
export const USOM_RUN_MODE_VALUES = Object.freeze([
  USOM_INCREMENTAL_MODE,
  USOM_FULL_RECONCILIATION_MODE
]);

export function normalizeUsomRunMode(value, { defaultMode = USOM_INCREMENTAL_MODE } = {}) {
  const mode = String(value || '').trim().toLowerCase();
  if (!mode) return defaultMode;
  return USOM_RUN_MODE_VALUES.includes(mode) ? mode : null;
}

export function inferUsomRunMode(row) {
  const explicit = row?.run_mode ?? row?.run_details?.run_mode;
  const normalized = normalizeUsomRunMode(explicit, { defaultMode: null });
  if (normalized) return normalized;
  const trigger = String(row?.triggered_by || row?.triggeredBy || '').toLowerCase();
  return trigger.includes(USOM_FULL_RECONCILIATION_MODE)
    ? USOM_FULL_RECONCILIATION_MODE
    : USOM_INCREMENTAL_MODE;
}

export function isScheduledRepeatIteration(job) {
  return Boolean(
    job?.repeatJobKey
    || job?.opts?.repeat
    || String(job?.id || '').startsWith('repeat:')
  );
}

export function decideUsomEnqueue(requestedMode, activeRows = []) {
  const mode = normalizeUsomRunMode(requestedMode);
  if (!mode) return { action: 'reject', reason: 'invalid_mode' };
  const rows = (activeRows || []).map((row) => ({ ...row, run_mode: inferUsomRunMode(row) }));
  const same = rows.find((row) => row.run_mode === mode);
  if (same) return { action: 'coalesce', reason: 'same_mode_active', existing: same };
  const full = rows.find((row) => row.run_mode === USOM_FULL_RECONCILIATION_MODE);
  if (mode === USOM_INCREMENTAL_MODE && full) {
    return { action: 'suppress', reason: 'full_reconciliation_active', existing: full };
  }
  return {
    action: 'enqueue',
    reason: mode === USOM_FULL_RECONCILIATION_MODE && rows.length
      ? 'retain_after_incremental'
      : 'ready'
  };
}

function runAt(run) {
  return run?.finished_at || run?.started_at || null;
}

export function buildUsomReconciliationHealth({
  latestFullRun = null,
  lastSuccessfulFullRun = null,
  now = new Date(),
  warningDays = 8,
  degradedDays = 14
} = {}) {
  const successAt = runAt(lastSuccessfulFullRun);
  const successMs = successAt ? Date.parse(successAt) : NaN;
  const ageDays = Number.isFinite(successMs)
    ? Math.max(0, (now.getTime() - successMs) / 86_400_000)
    : null;
  const latestStatus = String(latestFullRun?.status || '').toLowerCase();

  let state = 'healthy';
  let warning = null;
  if (latestStatus === 'failed' || latestStatus === 'fail') {
    state = 'degraded';
    warning = 'Latest full reconciliation failed.';
  } else if (ageDays == null) {
    state = 'degraded';
    warning = 'No successful full reconciliation has been recorded.';
  } else if (ageDays > degradedDays) {
    state = 'degraded';
    warning = `Full reconciliation is ${Math.floor(ageDays)} days old.`;
  } else if (ageDays > warningDays) {
    state = 'warning';
    warning = `Full reconciliation is ${Math.floor(ageDays)} days old.`;
  }

  return {
    state,
    age_days: ageDays == null ? null : Number(ageDays.toFixed(2)),
    warning,
    latest_status: latestStatus || 'never'
  };
}
