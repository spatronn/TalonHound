/**
 * Job Queue Status — Result column and details presentation.
 * Shares metric wording with Feeds Last Result (without "Completed ·" prefix).
 */

function n(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : 0;
}

function fmt(value) {
  return n(value).toLocaleString();
}

/**
 * Compact result cell text for a queue job row.
 * @param {object} job
 * @returns {{ text: string, title: string, tone: 'neutral'|'success'|'danger'|'warning' }}
 */
export function presentQueueJobResult(job) {
  const state = String(job?.state || job?.status || '').toLowerCase();
  const result = job?.result;
  const available = result?.available === true
    || Boolean(job?.result_code)
    || Boolean(job?.result_summary)
    || Boolean(job?.result_details);

  if (state === 'queued' || state === 'running') {
    return { text: '—', title: 'Job has not finished yet', tone: 'neutral' };
  }

  if (!available) {
    // Legacy rows without snapshot: fall back for failed/skipped reason only
    if (state === 'failed' || state === 'fail') {
      return { text: 'Failed', title: job?.failed_reason || 'Failed', tone: 'danger' };
    }
    return { text: 'Result unavailable', title: 'This job completed before result snapshots were stored', tone: 'neutral' };
  }

  const summary = String(job?.result_summary || result?.result_summary || '').trim();
  const code = String(job?.result_code || result?.result_code || '').toUpperCase();

  if (summary) {
    let tone = 'success';
    if (code === 'FAILED' || state === 'failed') tone = 'danger';
    else if (code === 'COMPLETED_WITH_WARNINGS') tone = 'warning';
    else if (code.startsWith('SKIPPED')) tone = 'neutral';
    return { text: summary, title: summary, tone };
  }

  if (code === 'FAILED' || state === 'failed') {
    return { text: 'Failed', title: job?.failed_reason || 'Failed', tone: 'danger' };
  }

  return { text: 'Result unavailable', title: 'Snapshot present but summary missing', tone: 'neutral' };
}

/**
 * Reason column: failure/skip only — never generic success text.
 * @param {object} job
 * @param {{ formatDurationMs?: (ms: number) => string, formatUserDateTime?: (v: any) => string }} helpers
 */
export function presentQueueJobReason(job, helpers = {}) {
  const state = String(job?.state || job?.status || '').toLowerCase();
  const formatDurationMs = helpers.formatDurationMs || ((ms) => `${ms}ms`);
  const formatUserDateTime = helpers.formatUserDateTime || ((v) => String(v || ''));

  if (state === 'queued' && job?.queue_hint) return job.queue_hint;
  if (state === 'success') return '—';
  if (state === 'running') {
    const parts = [];
    if (job?.running_for_ms != null) parts.push(`running for ${formatDurationMs(job.running_for_ms)}`);
    if (job?.started_at) parts.push(`started ${formatUserDateTime(job.started_at)}`);
    if (job?.possibly_stuck) parts.push('Possibly stuck / stale');
    return parts.length ? parts.join(' · ') : '—';
  }
  if (state === 'skipped') {
    const reason = job?.failed_reason || '';
    return reason || '—';
  }
  if (job?.failed_reason) {
    if (job?.failure_type) return `[${job.failure_type}] ${job.failed_reason}`;
    return job.failed_reason;
  }
  return '—';
}

/**
 * Detail metrics for expandable row — hide null/unsupported; keep meaningful zeros.
 * @param {object} job
 */
export function buildQueueJobDetailMetrics(job) {
  const details = job?.result_details || job?.result?.result_details || null;
  const rows = [];

  function push(label, value, { hideNull = true, hideZero = false } = {}) {
    if (value == null) {
      if (hideNull) return;
      rows.push({ label, value: '—' });
      return;
    }
    const num = Number(value);
    if (Number.isFinite(num)) {
      if (hideZero && num === 0) return;
      rows.push({ label, value: fmt(num) });
      return;
    }
    rows.push({ label, value: String(value) });
  }

  if (details && typeof details === 'object') {
    push('Checked', details.checked, { hideNull: true });
    push('New', details.new, { hideNull: true });
    push('Updated', details.updated, { hideNull: true });
    push('Unchanged', details.unchanged, { hideNull: true });
    push('Expired', details.expired, { hideZero: true });
    push('Filtered / skipped', details.filtered, { hideZero: true });
    push('Rejected', details.rejected, { hideZero: true });
    push('Failed', details.failed, { hideZero: true });
    push('Suppressed', details.suppressed, { hideZero: true });
    push('Reactivated', details.reactivated, { hideZero: true });
    push('Fetched', details.fetched, { hideNull: true, hideZero: false });
    push('Parsed', details.parsed, { hideNull: true, hideZero: false });
  } else if (job?.records_processed != null || job?.records_inserted != null) {
    // Legacy counters without snapshot
    push('Processed', job.records_processed);
    push('New', job.records_inserted);
    push('Updated', job.records_updated);
    push('Unchanged', job.records_unchanged ?? job.records_duplicate);
  }

  return rows;
}

/**
 * Format run mode / trigger for details.
 */
export function formatQueueTrigger(triggeredBy) {
  const t = String(triggeredBy || '').trim().toLowerCase();
  if (!t) return '—';
  if (t === 'scheduler' || t === 'scheduled' || t === 'repeatable') return 'scheduled';
  if (t.includes('manual')) return 'manual';
  if (t.startsWith('scheduler:') || t.startsWith('scheduled:')) return 'scheduled';
  return triggeredBy;
}

export function formatQueueRunMode(mode) {
  if (mode === 'full_reconciliation') return 'Full reconciliation';
  if (mode === 'incremental') return 'Incremental';
  return mode || '—';
}
