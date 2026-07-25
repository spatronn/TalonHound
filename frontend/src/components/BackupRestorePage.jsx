import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../lib/api.js';
import {
  formatUserDateTime,
  getUserTimezone,
  utcIsoTooltip,
  TIMEZONE_CHANGED_EVENT
} from '../lib/formatDate.js';
import './BackupRestorePage.css';

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

function truncateId(id, head = 18, tail = 6) {
  const s = String(id || '');
  if (s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

function statusBadgeClass(status) {
  const s = String(status || '').toLowerCase();
  if (['completed', 'passed', 'ready'].includes(s)) return 'br-badge br-badge-ok';
  if (['failed', 'interrupted'].includes(s)) return 'br-badge br-badge-bad';
  if (['running', 'verifying', 'queued', 'pending'].includes(s)) return 'br-badge br-badge-run';
  return 'br-badge br-badge-muted';
}

function DateCell({ value, timezone }) {
  if (!value) return <span className="br-muted">—</span>;
  return (
    <span title={utcIsoTooltip(value) || undefined}>
      {formatUserDateTime(value, timezone)}
    </span>
  );
}

function RowActionsMenu({
  row,
  busy,
  onDetails,
  onRestore,
  onDelete,
  canDownload,
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
      api.get('/backups', { params: { limit: 50 } })
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

  return (
    <AppShell>
      <div className="br-page">
        <div className="br-header">
          <div className="br-header-text">
            <h1 className="br-title">Backup &amp; Restore</h1>
            <p className="br-subtitle">Secure PostgreSQL backups with checksum verification.</p>
            <p className="br-note">Restores are prepared in the UI and executed safely through the host CLI.</p>
          </div>
          <button
            type="button"
            className="br-btn br-btn-primary br-btn-lg"
            disabled={busy || hasActive}
            onClick={onCreate}
            title={hasActive ? 'A backup is already running' : 'Create backup'}
          >
            {hasActive ? 'Backup running…' : 'Create Backup'}
          </button>
        </div>

        {!encryptionOn && status ? (
          <div className="br-banner br-banner-warn" role="status">
            <strong>Backup encryption is disabled.</strong>
            {' '}
            Backup archives may contain API keys and other sensitive configuration.
            Enable <code>BACKUP_ENCRYPTION_ENABLED</code> and configure <code>BACKUP_ENCRYPTION_KEY_FILE</code>.
          </div>
        ) : null}

        {error ? <div className="br-banner br-banner-error">{error}</div> : null}
        {info ? <div className="br-banner br-banner-info br-toast">{info}</div> : null}

        <section className="br-panel">
          <div className="br-panel-head">
            <h2 className="br-panel-title">Backup Policy</h2>
            {status?.last_verification ? (
              <span className={statusBadgeClass(status.last_verification.status)}>
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
                <span className={encryptionOn ? 'br-badge br-badge-ok' : 'br-badge br-badge-warn'}>
                  {encryptionOn ? 'Enabled' : 'Disabled'}
                </span>
              </div>
            </div>
            <div className="br-policy-item">
              <div className="br-policy-label">Storage</div>
              <div className="br-policy-value">
                {status?.storage_provider === 'local' || !status?.storage_provider
                  ? 'Local persistent volume'
                  : String(status.storage_provider)}
              </div>
            </div>
          </div>
        </section>

        <div className="br-cards">
          <div className="br-card">
            <div className="br-card-label">Last Successful Backup</div>
            <div className="br-card-value">
              {status?.last_successful
                ? <DateCell value={status.last_successful.completed_at} timezone={timezone} />
                : 'None yet'}
            </div>
            <div className="br-card-sub br-mono" title={status?.last_successful?.backup_id || undefined}>
              {status?.last_successful ? truncateId(status.last_successful.backup_id) : '—'}
            </div>
          </div>
          <div className="br-card">
            <div className="br-card-label">Next Scheduled Backup</div>
            <div className="br-card-value">
              {status?.enabled
                ? <DateCell value={status.next_scheduled_at} timezone={timezone} />
                : 'Disabled'}
            </div>
            <div className="br-card-sub">{scheduleSummary}</div>
          </div>
          <div className="br-card">
            <div className="br-card-label">Stored Backups</div>
            <div className="br-card-value">{status?.total_stored ?? '—'}</div>
            <div className="br-card-sub">Retention {status?.retention_days ?? '—'} days</div>
          </div>
          <div className="br-card">
            <div className="br-card-label">Storage Used</div>
            <div className="br-card-value">{formatBytes(status?.storage_used_bytes)}</div>
            <div className="br-card-sub">Local volume</div>
          </div>
        </div>

        <section className="br-panel">
          <div className="br-panel-head">
            <div>
              <h2 className="br-panel-title">Backup History</h2>
              <p className="br-muted">
                {items.length} shown
                {status?.last_verification?.status
                  ? ` · Last verification ${status.last_verification.status}`
                  : ''}
              </p>
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
                  {items.map((row) => {
                    const completed = row.status === 'completed';
                    const canDownload = completed;
                    const canRestore = completed && row.verify_status !== 'failed';
                    const canDelete = !['queued', 'running', 'verifying'].includes(row.status);
                    return (
                      <tr key={row.id}>
                        <td><DateCell value={row.created_at} timezone={timezone} /></td>
                        <td>
                          <div className="br-id-cell">
                            <code className="br-mono" title={row.backup_id}>{truncateId(row.backup_id)}</code>
                            <button type="button" className="br-btn br-btn-ghost br-btn-xs" onClick={() => copyBackupId(row.backup_id)} title="Copy ID">Copy</button>
                          </div>
                        </td>
                        <td>{row.trigger_type}</td>
                        <td><span className={statusBadgeClass(row.status)}>{row.status}</span></td>
                        <td>{formatBytes(row.archive_size_bytes)}</td>
                        <td>
                          <span className={row.encrypted ? 'br-badge br-badge-ok' : 'br-badge br-badge-muted'}>
                            {row.encrypted ? 'Encrypted' : 'Plain'}
                          </span>
                        </td>
                        <td><span className={statusBadgeClass(row.verify_status)}>{row.verify_status || '—'}</span></td>
                        <td>{formatDuration(row.duration_ms)}</td>
                        <td>{row.created_by_email || '—'}</td>
                        <td>
                          <div className="br-actions">
                            <button type="button" className="br-btn br-btn-ghost" disabled={busy || !canDownload} onClick={() => onDownload(row)}>Download</button>
                            <button type="button" className="br-btn br-btn-ghost" disabled={busy || !completed} onClick={() => onVerify(row)}>Verify</button>
                            <RowActionsMenu
                              row={row}
                              busy={busy}
                              canDownload={canDownload}
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
                  <dt>Status</dt><dd><span className={statusBadgeClass(detailsTarget.status)}>{detailsTarget.status}</span></dd>
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
                  <dt>Status</dt><dd><span className={statusBadgeClass(detailsTarget.verify_status)}>{detailsTarget.verify_status || '—'}</span></dd>
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
              <dd><span className={statusBadgeClass(restoreTarget.verify_status)}>{restoreTarget.verify_status || '—'}</span></dd>
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
