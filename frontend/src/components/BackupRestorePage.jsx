import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../lib/api.js';
import {
  formatUserDateTime,
  getUserTimezone,
  utcIsoTooltip,
  TIMEZONE_CHANGED_EVENT
} from '../lib/formatDate.js';
import './BackupRestorePage.css';

const PAGE_SIZE_OPTIONS = [10, 25, 50];

function formatBytes(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) return '—';
  if (v < 1024) return `${v} B`;
  if (v < 1024 ** 2) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 ** 3) return `${(v / 1024 ** 2).toFixed(1)} MB`;
  return `${(v / 1024 ** 3).toFixed(2)} GB`;
}

function formatDuration(ms) {
  const v = Number(ms);
  if (!Number.isFinite(v) || v < 0) return '—';
  if (v < 1000) return `${v} ms`;
  if (v < 60_000) return `${(v / 1000).toFixed(1)} s`;
  return `${Math.floor(v / 60_000)}m ${Math.round((v % 60_000) / 1000)}s`;
}

function truncateId(id, head = 22, tail = 6) {
  const s = String(id || '');
  if (s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

function statusTone(status) {
  const s = String(status || '').toLowerCase();
  if (['completed', 'passed', 'ready', 'ok'].includes(s)) return 'ok';
  if (['failed', 'interrupted'].includes(s)) return 'bad';
  if (['running', 'verifying', 'queued', 'pending'].includes(s)) return 'run';
  if (['disabled', 'warn', 'warning'].includes(s)) return 'warn';
  return 'muted';
}

function Svg({ children, size = 16, className = '' }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

const Icons = {
  create: (
    <Svg size={18}>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="M7 10 12 15 17 10" />
      <path d="M12 15V3" />
    </Svg>
  ),
  warn: (
    <Svg size={18}>
      <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
    </Svg>
  ),
  shield: (
    <Svg size={18}>
      <path d="M12 3 4 6v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V6l-8-3Z" />
    </Svg>
  ),
  calendarCheck: (
    <Svg size={18}>
      <rect x="3" y="5" width="18" height="16" rx="2" />
      <path d="M8 3v4" />
      <path d="M16 3v4" />
      <path d="M3 11h18" />
      <path d="m9 16 2 2 4-4" />
    </Svg>
  ),
  calendar: (
    <Svg size={18}>
      <rect x="3" y="5" width="18" height="16" rx="2" />
      <path d="M8 3v4" />
      <path d="M16 3v4" />
      <path d="M3 11h18" />
    </Svg>
  ),
  database: (
    <Svg size={18}>
      <ellipse cx="12" cy="6" rx="7" ry="3" />
      <path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6" />
      <path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" />
    </Svg>
  ),
  chart: (
    <Svg size={18}>
      <path d="M21.2 8.4A9 9 0 1 0 12 21" />
      <path d="M12 3v9l7 4" />
    </Svg>
  ),
  history: (
    <Svg size={18}>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
      <path d="M14 2v6h6" />
      <path d="M8 13h8" />
      <path d="M8 17h6" />
    </Svg>
  ),
  copy: (
    <Svg size={14}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </Svg>
  ),
  download: (
    <Svg size={14}>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="M7 10 12 15 17 10" />
      <path d="M12 15V3" />
    </Svg>
  ),
  verify: (
    <Svg size={14}>
      <path d="M12 3 4 6v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V6l-8-3Z" />
      <path d="m9 12 2 2 4-4" />
    </Svg>
  ),
  check: (
    <Svg size={12}>
      <path d="M20 6 9 17l-5-5" />
    </Svg>
  ),
  chevronLeft: (
    <Svg size={16}>
      <path d="m15 18-6-6 6-6" />
    </Svg>
  ),
  chevronRight: (
    <Svg size={16}>
      <path d="m9 18 6-6-6-6" />
    </Svg>
  )
};

function StatusBadge({ status, label, withCheck = false }) {
  const tone = statusTone(status);
  const text = label ?? status ?? '—';
  return (
    <span className={`br-badge br-badge-${tone}`}>
      {withCheck && tone === 'ok' ? (
        <span className="br-badge-icon">{Icons.check}</span>
      ) : (
        <span className="br-badge-dot" />
      )}
      {text}
    </span>
  );
}

function DateCell({ value, timezone }) {
  if (!value) return <span className="br-muted">—</span>;
  return (
    <span title={utcIsoTooltip(value) || undefined}>
      {formatUserDateTime(value, timezone)}
    </span>
  );
}

function MetricCard({ tone, icon, label, value, sub }) {
  return (
    <div className={`br-card br-card-${tone}`}>
      <div className="br-card-top">
        <div className="br-card-label">{label}</div>
        <div className={`br-card-icon br-card-icon-${tone}`}>{icon}</div>
      </div>
      <div className="br-card-value">{value}</div>
      <div className="br-card-sub">{sub}</div>
    </div>
  );
}

function RowActionsMenu({
  row,
  busy,
  onDetails,
  onRestore,
  onDelete,
  canRestore,
  canDelete
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    function onDoc(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  return (
    <div className="br-menu" ref={ref}>
      <button
        type="button"
        className="br-btn br-btn-ghost br-btn-icon"
        disabled={busy}
        aria-label="More actions"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        ⋯
      </button>
      {open ? (
        <div className="br-menu-panel" role="menu">
          <button type="button" role="menuitem" className="br-menu-item" onClick={() => { setOpen(false); onDetails(row); }}>
            Details
          </button>
          <button
            type="button"
            role="menuitem"
            className="br-menu-item br-menu-caution"
            disabled={!canRestore}
            onClick={() => { setOpen(false); onRestore(row); }}
          >
            Restore…
          </button>
          <button
            type="button"
            role="menuitem"
            className="br-menu-item br-menu-danger"
            disabled={!canDelete}
            onClick={() => { setOpen(false); onDelete(row); }}
          >
            Delete…
          </button>
        </div>
      ) : null}
    </div>
  );
}

export default function BackupRestorePage({ AppShell, useSession }) {
  const { isAdmin } = useSession();
  const [timezone, setTimezone] = useState(() => getUserTimezone());
  const [status, setStatus] = useState(null);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [detailsTarget, setDetailsTarget] = useState(null);
  const [restoreTarget, setRestoreTarget] = useState(null);
  const [restoreConfirm, setRestoreConfirm] = useState('');
  const [restoreResult, setRestoreResult] = useState(null);
  const [restorePhase, setRestorePhase] = useState('idle');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const infoTimer = useRef(null);

  useEffect(() => {
    function syncTz() {
      setTimezone(getUserTimezone());
    }
    window.addEventListener(TIMEZONE_CHANGED_EVENT, syncTz);
    window.addEventListener('storage', syncTz);
    return () => {
      window.removeEventListener(TIMEZONE_CHANGED_EVENT, syncTz);
      window.removeEventListener('storage', syncTz);
    };
  }, []);

  useEffect(() => () => {
    if (infoTimer.current) clearTimeout(infoTimer.current);
  }, []);

  function flashInfo(message) {
    setInfo(message);
    if (infoTimer.current) clearTimeout(infoTimer.current);
    infoTimer.current = setTimeout(() => setInfo(''), 4000);
  }

  const load = useCallback(async () => {
    const [st, list] = await Promise.all([
      api.get('/backups/status'),
      api.get('/backups', { params: { limit: 100 } })
    ]);
    setStatus(st.data);
    setItems(list.data?.items || []);
  }, []);

  const refresh = useCallback(async () => {
    try {
      await load();
      setError('');
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to load backups');
    } finally {
      setLoading(false);
    }
  }, [load]);

  useEffect(() => {
    if (!isAdmin) return undefined;
    refresh();
    return undefined;
  }, [isAdmin, refresh]);

  const hasActive = useMemo(
    () => Boolean(status?.backup_running) || items.some((r) => ['queued', 'running', 'verifying'].includes(r.status)),
    [status, items]
  );

  useEffect(() => {
    if (!isAdmin || !hasActive) return undefined;
    const t = setInterval(() => {
      refresh().catch(() => {});
    }, 3000);
    return () => clearInterval(t);
  }, [isAdmin, hasActive, refresh]);

  const totalPages = Math.max(1, Math.ceil(items.length / pageSize) || 1);
  const safePage = Math.min(page, totalPages);
  const pageItems = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return items.slice(start, start + pageSize);
  }, [items, safePage, pageSize]);

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const rangeStart = items.length === 0 ? 0 : (safePage - 1) * pageSize + 1;
  const rangeEnd = Math.min(safePage * pageSize, items.length);

  async function onCreate() {
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post('/backups');
      flashInfo(`Backup queued: ${data.backup_id}`);
      await refresh();
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to start backup');
    } finally {
      setBusy(false);
    }
  }

  async function onVerify(row) {
    setBusy(true);
    setError('');
    try {
      await api.post(`/backups/${row.id}/verify`);
      flashInfo(`Verified ${row.backup_id}`);
      await refresh();
    } catch (err) {
      setError(err?.response?.data?.message || 'Verification failed');
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  function onDownload(row) {
    setError('');
    const a = document.createElement('a');
    a.href = `/api/backups/${row.id}/download`;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    flashInfo(`Download started for ${row.backup_id}`);
  }

  async function copyBackupId(id) {
    try {
      await navigator.clipboard.writeText(id);
      flashInfo('Backup ID copied');
    } catch {
      flashInfo(id);
    }
  }

  async function onDeleteConfirm() {
    if (!deleteTarget) return;
    setBusy(true);
    setError('');
    try {
      await api.delete(`/backups/${deleteTarget.id}`);
      flashInfo(`Deleted ${deleteTarget.backup_id}`);
      setDeleteTarget(null);
      await refresh();
    } catch (err) {
      setError(err?.response?.data?.message || 'Delete failed');
    } finally {
      setBusy(false);
    }
  }

  async function onRestorePrepare() {
    if (!restoreTarget) return;
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post(`/backups/${restoreTarget.id}/restore/prepare`);
      setRestoreResult(data);
      setRestorePhase('prepared');
      flashInfo('Restore prepared. Confirm after the safety backup completes.');
      await refresh();
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to prepare restore');
    } finally {
      setBusy(false);
    }
  }

  async function onRestoreConfirm() {
    if (!restoreTarget || !restoreResult?.restore?.id) return;
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post(`/backups/${restoreTarget.id}/restore/confirm`, {
        restore_id: restoreResult.restore.id,
        confirmation: restoreConfirm
      });
      setRestoreResult((prev) => ({ ...prev, ...data, restore: data.restore }));
      setRestorePhase('ready');
    } catch (err) {
      setError(err?.response?.data?.message || 'Confirmation failed');
    } finally {
      setBusy(false);
    }
  }

  function openRestore(row) {
    setRestoreTarget(row);
    setRestoreConfirm('');
    setRestoreResult(null);
    setRestorePhase('idle');
  }

  if (!isAdmin) {
    return (
      <AppShell>
        <div className="br-page">
          <h1 className="br-title">Backup &amp; Restore</h1>
          <p className="br-subtitle">Administrator access required.</p>
        </div>
      </AppShell>
    );
  }

  const encryptionOn = Boolean(status?.encryption_enabled);
  const scheduleSummary = status?.schedule_summary || '—';
  const scheduleTz = status?.timezone || 'UTC';
  const storageLabel = status?.storage_provider === 'local' || !status?.storage_provider
    ? 'Local persistent volume'
    : String(status.storage_provider);
  const historySub = [
    `${status?.total_stored ?? items.length} backup${(status?.total_stored ?? items.length) === 1 ? '' : 's'} stored`,
    status?.last_verification?.status ? `verification ${status.last_verification.status}` : null
  ].filter(Boolean).join(' · ');

  return (
    <AppShell>
      <div className="br-page">
        <div className="br-header">
          <div className="br-header-text">
            <h1 className="br-title">Backup &amp; Restore</h1>
            <p className="br-subtitle">
              Secure PostgreSQL backups with checksum verification. Restores are executed via the host CLI.
            </p>
          </div>
          <button
            type="button"
            className="br-btn br-btn-primary br-btn-lg"
            disabled={busy || hasActive}
            onClick={onCreate}
            title={hasActive ? 'A backup is already running' : 'Create backup'}
          >
            <span className="br-btn-leading">{Icons.create}</span>
            {hasActive ? 'Backup running…' : 'Create Backup'}
          </button>
        </div>

        {!encryptionOn && status ? (
          <div className="br-banner br-banner-warn" role="status">
            <span className="br-banner-icon">{Icons.warn}</span>
            <div>
              <strong>Backup encryption is disabled.</strong>
              {' '}
              Backup archives may contain API keys and other sensitive configuration.
              Enable <code>BACKUP_ENCRYPTION_ENABLED</code> and configure <code>BACKUP_ENCRYPTION_KEY_FILE</code>.
            </div>
          </div>
        ) : null}

        {error ? <div className="br-banner br-banner-error">{error}</div> : null}
        {info ? <div className="br-banner br-banner-info br-toast">{info}</div> : null}

        <section className="br-panel">
          <div className="br-panel-head">
            <h2 className="br-panel-title">
              <span className="br-panel-icon">{Icons.shield}</span>
              Backup Policy
            </h2>
            {status?.last_verification ? (
              <span className={`br-verify-pill br-verify-${statusTone(status.last_verification.status)}`}>
                Last verification: {status.last_verification.status || '—'}
                {status.last_verification.at ? (
                  <> · <DateCell value={status.last_verification.at} timezone={timezone} /></>
                ) : null}
              </span>
            ) : null}
          </div>
          <div className="br-policy-grid">
            <div className="br-policy-item">
              <div className="br-policy-label">Schedule</div>
              <div className="br-policy-value">{scheduleSummary}</div>
            </div>
            <div className="br-policy-item">
              <div className="br-policy-label">Timezone</div>
              <div className="br-policy-value">{scheduleTz}</div>
            </div>
            <div className="br-policy-item">
              <div className="br-policy-label">Retention</div>
              <div className="br-policy-value">{status?.retention_days ?? '—'} days</div>
            </div>
            <div className="br-policy-item">
              <div className="br-policy-label">Encryption</div>
              <div className="br-policy-value">
                <StatusBadge
                  status={encryptionOn ? 'passed' : 'warn'}
                  label={encryptionOn ? 'Enabled' : 'Disabled'}
                />
              </div>
            </div>
            <div className="br-policy-item">
              <div className="br-policy-label">Storage</div>
              <div className="br-policy-value">{storageLabel}</div>
            </div>
          </div>
        </section>

        <div className="br-cards">
          <MetricCard
            tone="green"
            icon={Icons.calendarCheck}
            label="Last Successful Backup"
            value={status?.last_successful
              ? <DateCell value={status.last_successful.completed_at} timezone={timezone} />
              : 'None yet'}
            sub={(
              <span className="br-mono" title={status?.last_successful?.backup_id || undefined}>
                {status?.last_successful ? truncateId(status.last_successful.backup_id) : '—'}
              </span>
            )}
          />
          <MetricCard
            tone="blue"
            icon={Icons.calendar}
            label="Next Scheduled Backup"
            value={status?.enabled
              ? <DateCell value={status.next_scheduled_at} timezone={timezone} />
              : 'Disabled'}
            sub={scheduleSummary}
          />
          <MetricCard
            tone="purple"
            icon={Icons.database}
            label="Stored Backups"
            value={status?.total_stored ?? '—'}
            sub={`Retention ${status?.retention_days ?? '—'} days`}
          />
          <MetricCard
            tone="teal"
            icon={Icons.chart}
            label="Storage Used"
            value={formatBytes(status?.storage_used_bytes)}
            sub={storageLabel}
          />
        </div>

        <section className="br-panel br-history">
          <div className="br-panel-head">
            <div>
              <h2 className="br-panel-title">
                <span className="br-panel-icon">{Icons.history}</span>
                Backup History
              </h2>
              <p className="br-muted">{historySub}</p>
            </div>
          </div>

          <div className="br-table-wrap">
            {loading ? (
              <p className="br-empty">Loading…</p>
            ) : items.length === 0 ? (
              <div className="br-empty">
                <p>No backups yet.</p>
                <p className="br-muted">Create a backup to protect PostgreSQL data.</p>
              </div>
            ) : (
              <table className="br-table">
                <thead>
                  <tr>
                    <th>Created</th>
                    <th>Backup ID</th>
                    <th>Trigger</th>
                    <th>Status</th>
                    <th>Size</th>
                    <th>Encryption</th>
                    <th>Verification</th>
                    <th>Duration</th>
                    <th>Created By</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {pageItems.map((row) => {
                    const completed = row.status === 'completed';
                    const canDownload = completed;
                    const canRestore = completed && row.verify_status !== 'failed';
                    const canDelete = !['queued', 'running', 'verifying'].includes(row.status);
                    return (
                      <tr key={row.id}>
                        <td className="br-nowrap"><DateCell value={row.created_at} timezone={timezone} /></td>
                        <td>
                          <div className="br-id-cell">
                            <code className="br-id-chip" title={row.backup_id}>{truncateId(row.backup_id)}</code>
                            <button
                              type="button"
                              className="br-btn br-btn-ghost br-btn-icon br-btn-xs"
                              onClick={() => copyBackupId(row.backup_id)}
                              title="Copy ID"
                              aria-label="Copy backup ID"
                            >
                              {Icons.copy}
                            </button>
                          </div>
                        </td>
                        <td>{row.trigger_type}</td>
                        <td><StatusBadge status={row.status} /></td>
                        <td className="br-nowrap">{formatBytes(row.archive_size_bytes)}</td>
                        <td>
                          <StatusBadge
                            status={row.encrypted ? 'passed' : 'muted'}
                            label={row.encrypted ? 'Encrypted' : 'Plain'}
                          />
                        </td>
                        <td>
                          <StatusBadge
                            status={row.verify_status}
                            label={row.verify_status || '—'}
                            withCheck
                          />
                        </td>
                        <td className="br-nowrap">{formatDuration(row.duration_ms)}</td>
                        <td>{row.created_by_email || '—'}</td>
                        <td>
                          <div className="br-actions">
                            <button
                              type="button"
                              className="br-btn br-btn-outline"
                              disabled={busy || !canDownload}
                              onClick={() => onDownload(row)}
                            >
                              <span className="br-btn-leading">{Icons.download}</span>
                              Download
                            </button>
                            <button
                              type="button"
                              className="br-btn br-btn-outline"
                              disabled={busy || !completed}
                              onClick={() => onVerify(row)}
                            >
                              <span className="br-btn-leading">{Icons.verify}</span>
                              Verify
                            </button>
                            <RowActionsMenu
                              row={row}
                              busy={busy}
                              canRestore={canRestore}
                              canDelete={canDelete}
                              onDetails={setDetailsTarget}
                              onRestore={openRestore}
                              onDelete={setDeleteTarget}
                            />
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          {!loading && items.length > 0 ? (
            <div className="br-pager">
              <label className="br-pager-size">
                Rows per page:
                <select
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value));
                    setPage(1);
                  }}
                >
                  {PAGE_SIZE_OPTIONS.map((n) => (
                    <option key={n} value={n}>{n}</option>
                  ))}
                </select>
              </label>
              <div className="br-pager-range">
                {rangeStart}-{rangeEnd} of {items.length}
              </div>
              <div className="br-pager-nav">
                <button
                  type="button"
                  className="br-btn br-btn-ghost br-btn-icon"
                  disabled={safePage <= 1}
                  aria-label="Previous page"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  {Icons.chevronLeft}
                </button>
                <button
                  type="button"
                  className="br-btn br-btn-ghost br-btn-icon"
                  disabled={safePage >= totalPages}
                  aria-label="Next page"
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                >
                  {Icons.chevronRight}
                </button>
              </div>
            </div>
          ) : null}
        </section>
      </div>

      {deleteTarget ? (
        <div className="br-modal-backdrop" role="presentation" onClick={() => !busy && setDeleteTarget(null)}>
          <div className="br-modal" role="dialog" onClick={(e) => e.stopPropagation()}>
            <h2>Delete backup?</h2>
            <p>Delete <span className="br-mono">{deleteTarget.backup_id}</span>? This removes the archive from storage.</p>
            <div className="br-modal-actions">
              <button type="button" className="br-btn br-btn-ghost" disabled={busy} onClick={() => setDeleteTarget(null)}>Cancel</button>
              <button type="button" className="br-btn br-btn-danger" disabled={busy} onClick={onDeleteConfirm}>Delete</button>
            </div>
          </div>
        </div>
      ) : null}

      {detailsTarget ? (
        <div className="br-modal-backdrop" role="presentation" onClick={() => setDetailsTarget(null)}>
          <div className="br-modal br-modal-wide" role="dialog" onClick={(e) => e.stopPropagation()}>
            <h2>Backup details</h2>
            <div className="br-detail-groups">
              <section>
                <h3>General</h3>
                <dl className="br-dl">
                  <dt>Backup ID</dt><dd className="br-mono">{detailsTarget.backup_id}</dd>
                  <dt>Status</dt><dd><StatusBadge status={detailsTarget.status} /></dd>
                  <dt>Trigger</dt><dd>{detailsTarget.trigger_type}</dd>
                  <dt>Created</dt><dd><DateCell value={detailsTarget.created_at} timezone={timezone} /></dd>
                  <dt>Started</dt><dd><DateCell value={detailsTarget.started_at} timezone={timezone} /></dd>
                  <dt>Completed</dt><dd><DateCell value={detailsTarget.completed_at} timezone={timezone} /></dd>
                  <dt>Created by</dt><dd>{detailsTarget.created_by_email || '—'}</dd>
                  <dt>Duration</dt><dd>{formatDuration(detailsTarget.duration_ms)}</dd>
                </dl>
              </section>
              <section>
                <h3>Archive</h3>
                <dl className="br-dl">
                  <dt>Filename</dt><dd className="br-mono">{detailsTarget.archive_filename || '—'}</dd>
                  <dt>Size</dt><dd>{formatBytes(detailsTarget.archive_size_bytes)}</dd>
                  <dt>Database size</dt><dd>{formatBytes(detailsTarget.database_size_bytes)}</dd>
                  <dt>Encryption</dt><dd>{detailsTarget.encrypted ? 'Enabled' : 'Disabled'}</dd>
                  <dt>Checksum</dt><dd className="br-mono br-wrap">{detailsTarget.checksum_sha256 || '—'}</dd>
                </dl>
              </section>
              <section>
                <h3>Verification</h3>
                <dl className="br-dl">
                  <dt>Status</dt><dd><StatusBadge status={detailsTarget.verify_status} withCheck /></dd>
                  <dt>Verified at</dt><dd><DateCell value={detailsTarget.verified_at} timezone={timezone} /></dd>
                  {detailsTarget.verify_error ? (
                    <><dt>Error</dt><dd>{detailsTarget.verify_error}</dd></>
                  ) : null}
                </dl>
              </section>
              {detailsTarget.error_message ? (
                <section>
                  <h3>Error details</h3>
                  <dl className="br-dl">
                    <dt>Code</dt><dd>{detailsTarget.error_code || '—'}</dd>
                    <dt>Message</dt><dd>{detailsTarget.error_message}</dd>
                  </dl>
                </section>
              ) : null}
            </div>
            <div className="br-modal-actions">
              <button type="button" className="br-btn br-btn-primary" onClick={() => setDetailsTarget(null)}>Close</button>
            </div>
          </div>
        </div>
      ) : null}

      {restoreTarget ? (
        <div className="br-modal-backdrop" role="presentation">
          <div className="br-modal br-modal-wide" role="dialog">
            <h2>Restore from backup</h2>
            <p className="br-warn">
              This overwrites the live PostgreSQL database. The web app does <strong>not</strong> run{' '}
              <code>pg_restore</code> — after confirmation you must run the host CLI command.
            </p>
            <dl className="br-dl">
              <dt>Backup ID</dt><dd className="br-mono">{restoreTarget.backup_id}</dd>
              <dt>Created</dt><dd><DateCell value={restoreTarget.created_at || restoreTarget.completed_at} timezone={timezone} /></dd>
              <dt>Size</dt><dd>{formatBytes(restoreTarget.archive_size_bytes)}</dd>
              <dt>Verification</dt>
              <dd><StatusBadge status={restoreTarget.verify_status} withCheck /></dd>
            </dl>
            <ul className="br-impact-list">
              <li>A safety backup of the current database will be taken first.</li>
              <li>Writer services will be stopped temporarily during restore.</li>
              <li>Expect application downtime until services restart.</li>
              <li>Redis queues are not restored; reconcile after restore if needed.</li>
            </ul>

            {restorePhase === 'idle' ? (
              <div className="br-modal-actions">
                <button type="button" className="br-btn br-btn-ghost" disabled={busy} onClick={() => setRestoreTarget(null)}>Cancel</button>
                <button type="button" className="br-btn br-btn-danger" disabled={busy} onClick={onRestorePrepare}>
                  Prepare restore (starts safety backup)
                </button>
              </div>
            ) : null}

            {restorePhase === 'prepared' || restorePhase === 'ready' ? (
              <>
                <p className="br-muted">
                  Safety backup:{' '}
                  <span className="br-mono">
                    {restoreResult?.safety_backup?.backup_id || restoreResult?.restore?.safety_backup_id}
                  </span>
                  {' '}({restoreResult?.safety_backup?.status || 'queued'})
                </p>
                <label className="br-label">
                  Type <code>RESTORE</code> or the backup ID to confirm
                  <input
                    className="br-input"
                    value={restoreConfirm}
                    onChange={(e) => setRestoreConfirm(e.target.value)}
                    disabled={busy || restorePhase === 'ready'}
                    autoComplete="off"
                  />
                </label>
                {restorePhase === 'prepared' ? (
                  <div className="br-modal-actions">
                    <button type="button" className="br-btn br-btn-ghost" disabled={busy} onClick={() => setRestoreTarget(null)}>Close</button>
                    <button type="button" className="br-btn br-btn-danger" disabled={busy || !restoreConfirm} onClick={onRestoreConfirm}>
                      Confirm restore request
                    </button>
                  </div>
                ) : null}
                {restorePhase === 'ready' ? (
                  <div className="br-cli-box">
                    <div className="br-card-label">Run on the Docker Compose host</div>
                    <pre className="br-mono">{restoreResult?.restore?.cli_command || restoreResult?.next_step}</pre>
                    <div className="br-modal-actions">
                      <button type="button" className="br-btn br-btn-primary" onClick={() => setRestoreTarget(null)}>Done</button>
                    </div>
                  </div>
                ) : null}
              </>
            ) : null}
          </div>
        </div>
      ) : null}
    </AppShell>
  );
}
