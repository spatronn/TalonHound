import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { api } from '../lib/api.js';
import {
  formatUserDateTime,
  formatUserDateParts,
  getUserTimezone,
  utcIsoTooltip,
  TIMEZONE_CHANGED_EVENT
} from '../lib/formatDate.js';
import { computeOverflowMenuPosition } from '../lib/backupMenuPosition.js';
import './BackupRestorePage.css';

const PAGE_SIZE_OPTIONS = [10, 25, 50];
const ROW_MENU_EVENT = 'br-backup-row-menu';

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

function StackedDateCell({ value, timezone }) {
  const parts = formatUserDateParts(value, timezone);
  if (!parts) return <span className="br-muted">—</span>;
  return (
    <span className="br-date-stack" title={utcIsoTooltip(value) || undefined}>
      <span className="br-date-day">{parts.date}</span>
      <span className="br-date-time">{parts.time}</span>
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
  onDelete,
  canDelete
}) {
  const [open, setOpen] = useState(false);
  const [coords, setCoords] = useState({ top: 0, left: 0, width: 168 });
  const triggerRef = useRef(null);
  const menuRef = useRef(null);

  const updatePosition = useCallback(() => {
    const el = triggerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const menuRect = menuRef.current?.getBoundingClientRect();
    const pos = computeOverflowMenuPosition({
      trigger: rect,
      menuWidth: menuRect?.width || 168,
      menuHeight: menuRect?.height || 132,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight
    });
    setCoords({ top: pos.top, left: pos.left, width: pos.width });
  }, []);

  useLayoutEffect(() => {
    if (!open) return undefined;
    updatePosition();
    const onReposition = () => updatePosition();
    window.addEventListener('resize', onReposition);
    window.addEventListener('scroll', onReposition, true);
    return () => {
      window.removeEventListener('resize', onReposition);
      window.removeEventListener('scroll', onReposition, true);
    };
  }, [open, updatePosition]);

  useEffect(() => {
    if (!open) return undefined;

    function onDoc(e) {
      const t = e.target;
      if (triggerRef.current?.contains(t)) return;
      if (menuRef.current?.contains(t)) return;
      setOpen(false);
    }

    function onKey(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        setOpen(false);
        triggerRef.current?.focus();
      }
    }

    function onOtherMenu(e) {
      if (e.detail !== row.id) setOpen(false);
    }

    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    window.addEventListener(ROW_MENU_EVENT, onOtherMenu);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener(ROW_MENU_EVENT, onOtherMenu);
    };
  }, [open, row.id]);

  useEffect(() => {
    if (!open) return undefined;
    const id = requestAnimationFrame(() => {
      const first = menuRef.current?.querySelector('[role="menuitem"]:not([disabled])')
        || menuRef.current?.querySelector('[role="menuitem"]');
      first?.focus();
    });
    return () => cancelAnimationFrame(id);
  }, [open]);

  function toggleMenu() {
    setOpen((wasOpen) => {
      const next = !wasOpen;
      if (next) {
        window.dispatchEvent(new CustomEvent(ROW_MENU_EVENT, { detail: row.id }));
      }
      return next;
    });
  }

  function pick(action) {
    setOpen(false);
    triggerRef.current?.focus();
    action();
  }

  return (
    <div className="br-menu">
      <button
        type="button"
        ref={triggerRef}
        className="br-btn br-btn-ghost br-overflow-btn"
        disabled={busy}
        aria-label="More actions"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={toggleMenu}
      >
        ⋯
      </button>
      {open && typeof document !== 'undefined'
        ? createPortal(
          <div
            ref={menuRef}
            className="br-menu-panel br-menu-panel-portal"
            role="menu"
            style={{ top: coords.top, left: coords.left, minWidth: coords.width }}
          >
            <button
              type="button"
              role="menuitem"
              className="br-menu-item"
              onClick={() => pick(() => onDetails(row))}
            >
              Details
            </button>
            <button
              type="button"
              role="menuitem"
              className="br-menu-item br-menu-danger"
              disabled={!canDelete}
              onClick={() => {
                if (!canDelete) return;
                pick(() => onDelete(row));
              }}
            >
              Delete…
            </button>
          </div>,
          document.body
        )
        : null}
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

  const orphanQueuedMs = (status?.orphan_queued_minutes ?? 5) * 60_000;

  const isStaleQueuedRow = useCallback((row) => {
    if (!row || row.status !== 'queued') return false;
    const t = new Date(row.created_at || row.updated_at).getTime();
    return Number.isFinite(t) && Date.now() - t >= orphanQueuedMs;
  }, [orphanQueuedMs]);

  const hasRunning = useMemo(
    () => Boolean(status?.backup_running)
      || items.some((r) => ['running', 'verifying'].includes(r.status)),
    [status, items]
  );

  const hasFreshQueued = useMemo(
    () => items.some((r) => r.status === 'queued' && !isStaleQueuedRow(r)),
    [items, isStaleQueuedRow]
  );

  const hasStaleQueued = useMemo(
    () => Boolean(status?.backup_stale_queued) || items.some((r) => isStaleQueuedRow(r)),
    [status, items, isStaleQueuedRow]
  );

  /** Poll while any in-flight row exists (including stale queued until reconcile). */
  const hasActive = useMemo(
    () => hasRunning || hasFreshQueued || items.some((r) => r.status === 'queued'),
    [hasRunning, hasFreshQueued, items]
  );

  /** Create allowed when only stale orphans remain (API also ignores them as blockers). */
  const createBlocked = busy || hasRunning || hasFreshQueued;

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
  const scheduleLocalHint = useMemo(() => {
    if (!status?.next_scheduled_at || scheduleTz === timezone) return null;
    return `Next in your timezone (${timezone}): ${formatUserDateTime(status.next_scheduled_at, timezone)}`;
  }, [status?.next_scheduled_at, scheduleTz, timezone]);
  const storageLabel = status?.storage_provider === 'local' || !status?.storage_provider
    ? 'Local persistent volume'
    : String(status.storage_provider);
  const historySub = [
    `${status?.total_stored ?? items.length} backup${(status?.total_stored ?? items.length) === 1 ? '' : 's'} stored`,
    status?.last_verification?.status ? `verification ${status.last_verification.status}` : null
  ].filter(Boolean).join(' · ');

  const createButtonLabel = hasRunning
    ? 'Backup running…'
    : hasFreshQueued
      ? 'Backup queued…'
      : 'Create Backup';

  return (
    <AppShell>
      <div className="br-page">
        <div className="br-header">
          <div className="br-header-text">
            <h1 className="br-title">Backup &amp; Restore</h1>
            <p className="br-subtitle">
              Restore operations are performed through the host CLI.
            </p>
          </div>
          <button
            type="button"
            className="br-btn br-btn-primary br-btn-lg"
            disabled={createBlocked}
            onClick={onCreate}
            title={createBlocked
              ? (hasRunning ? 'A backup is already running' : 'A backup is already queued')
              : 'Create backup'}
          >
            <span className="br-btn-leading">{Icons.create}</span>
            {createButtonLabel}
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

        {hasStaleQueued ? (
          <div className="br-banner br-banner-warn" role="status">
            <span className="br-banner-icon">{Icons.warn}</span>
            <div>
              <strong>Backup is queued but has not been picked up by the worker.</strong>
              {' '}
              Create Backup is available again; the stale row will be marked failed by the worker reconciler
              (or ask an operator to clear it). Check <code>backup-worker</code> logs for <code>ENQUEUE_FAILED</code>.
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
              {scheduleLocalHint ? <div className="br-muted" style={{ marginTop: 4, fontSize: 12 }}>{scheduleLocalHint}</div> : null}
            </div>
            <div className="br-policy-item">
              <div className="br-policy-label">Timezone</div>
              <div className="br-policy-value">{scheduleTz}</div>
              <div className="br-muted" style={{ marginTop: 4, fontSize: 12 }}>
                Cron wall-clock in this zone (default Sunday 00:00 UTC ≈ 03:00 Europe/Istanbul in summer).
              </div>
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

          <div className="br-table-wrap" role="table" aria-label="Backup history">
            {loading ? (
              <p className="br-empty">Loading…</p>
            ) : items.length === 0 ? (
              <div className="br-empty">
                <p>No backups yet.</p>
                <p className="br-muted">Create a backup to protect PostgreSQL data.</p>
              </div>
            ) : (
              <>
                <div className="br-history-grid-head" role="row">
                  <div role="columnheader">Created</div>
                  <div role="columnheader">Backup ID</div>
                  <div role="columnheader">Status</div>
                  <div role="columnheader">Size</div>
                  <div role="columnheader">Verification</div>
                  <div role="columnheader">Created By</div>
                  <div role="columnheader" className="br-th-actions">Actions</div>
                </div>
                {pageItems.map((row) => {
                  const completed = row.status === 'completed';
                  const canDownload = completed;
                  const canDelete = !['queued', 'running', 'verifying'].includes(row.status);
                  return (
                    <div className="br-history-grid-row" role="row" key={row.id}>
                      <div role="cell" className="br-cell-created">
                        <StackedDateCell value={row.created_at} timezone={timezone} />
                      </div>
                      <div role="cell">
                        <div className="br-id-cell">
                          <code className="br-id-text" title={row.backup_id}>{row.backup_id}</code>
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
                      </div>
                      <div role="cell"><StatusBadge status={row.status} /></div>
                      <div role="cell">{formatBytes(row.archive_size_bytes)}</div>
                      <div role="cell">
                        <StatusBadge
                          status={row.verify_status}
                          label={row.verify_status || '—'}
                          withCheck
                        />
                      </div>
                      <div role="cell">
                        <span className="br-cell-clip" title={row.created_by_email || undefined}>
                          {row.created_by_email || '—'}
                        </span>
                      </div>
                      <div role="cell" className="br-cell-actions">
                        <div className="br-actions">
                          <button
                            type="button"
                            className="br-btn br-btn-outline br-action-btn"
                            disabled={busy || !canDownload}
                            onClick={() => onDownload(row)}
                            title="Download"
                          >
                            <span className="br-btn-leading">{Icons.download}</span>
                            <span className="br-action-label">Download</span>
                          </button>
                          <button
                            type="button"
                            className="br-btn br-btn-outline br-action-btn"
                            disabled={busy || !completed}
                            onClick={() => onVerify(row)}
                            title="Verify"
                          >
                            <span className="br-btn-leading">{Icons.verify}</span>
                            <span className="br-action-label">Verify</span>
                          </button>
                          <RowActionsMenu
                            row={row}
                            busy={busy}
                            canDelete={canDelete}
                            onDetails={setDetailsTarget}
                            onDelete={setDeleteTarget}
                          />
                        </div>
                      </div>
                    </div>
                  );
                })}
              </>
            )}
          </div>

          {!loading && items.length > 0 ? (
            <footer className="br-history-footer">
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
            </footer>
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
    </AppShell>
  );
}
