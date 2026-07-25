import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api.js';
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

function formatWhen(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  } catch {
    return String(iso);
  }
}

function statusClass(status) {
  const s = String(status || '');
  if (s === 'completed' || s === 'passed' || s === 'ready') return 'br-status br-status-ok';
  if (s === 'failed' || s === 'interrupted') return 'br-status br-status-bad';
  if (s === 'running' || s === 'verifying' || s === 'queued') return 'br-status br-status-run';
  return 'br-status';
}

export default function BackupRestorePage({ AppShell, useSession }) {
  const { isAdmin } = useSession();
  const [status, setStatus] = useState(null);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [expanded, setExpanded] = useState(() => new Set());
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [restoreTarget, setRestoreTarget] = useState(null);
  const [restoreConfirm, setRestoreConfirm] = useState('');
  const [restoreResult, setRestoreResult] = useState(null);
  const [restorePhase, setRestorePhase] = useState('idle'); // idle | prepared | ready

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
    setInfo('');
    setError('');
    try {
      const { data } = await api.post('/backups');
      setInfo(`Backup queued: ${data.backup_id}`);
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
      setInfo(`Verified ${row.backup_id}`);
      await refresh();
    } catch (err) {
      setError(err?.response?.data?.message || 'Verification failed');
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function onDownload(row) {
    setError('');
    // Stream via browser download manager — do NOT axios-blob (~hundreds of MB).
    const href = `/api/backups/${row.id}/download`;
    const a = document.createElement('a');
    a.href = href;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setInfo(`Download started for ${row.backup_id}`);
  }

  async function onDeleteConfirm() {
    if (!deleteTarget) return;
    setBusy(true);
    setError('');
    try {
      await api.delete(`/backups/${deleteTarget.id}`);
      setInfo(`Deleted ${deleteTarget.backup_id}`);
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
      setInfo('Restore prepared. A safety backup was queued. Confirm after it completes.');
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
      setInfo('Restore confirmed. Run the CLI command on the host to apply.');
    } catch (err) {
      setError(err?.response?.data?.message || 'Confirmation failed');
    } finally {
      setBusy(false);
    }
  }

  function toggleExpand(id) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  if (!isAdmin) {
    return (
      <AppShell>
        <div className="br-page">
          <h1>Backup &amp; Restore</h1>
          <p className="br-muted">Administrator access required.</p>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <div className="br-page">
        <div className="br-header">
          <div>
            <h1>Backup &amp; Restore</h1>
            <p className="br-muted">
              PostgreSQL backups with checksum verification. Destructive restore runs via host CLI only.
            </p>
          </div>
          <button
            type="button"
            className="br-btn br-btn-primary"
            disabled={busy || hasActive}
            onClick={onCreate}
            title={hasActive ? 'A backup is already running' : 'Create backup'}
          >
            Create Backup
          </button>
        </div>

        {error ? <div className="br-banner br-banner-error">{error}</div> : null}
        {info ? <div className="br-banner br-banner-info">{info}</div> : null}

        <div className="br-cards">
          <div className="br-card">
            <div className="br-card-label">Last successful backup</div>
            <div className="br-card-value">
              {status?.last_successful
                ? formatWhen(status.last_successful.completed_at)
                : 'None yet'}
            </div>
            <div className="br-card-sub">
              {status?.last_successful?.backup_id || '—'}
            </div>
          </div>
          <div className="br-card">
            <div className="br-card-label">Next scheduled backup</div>
            <div className="br-card-value">
              {status?.enabled ? formatWhen(status.next_scheduled_at) : 'Disabled'}
            </div>
            <div className="br-card-sub">{status?.cron || '—'}</div>
          </div>
          <div className="br-card">
            <div className="br-card-label">Total stored backups</div>
            <div className="br-card-value">{status?.total_stored ?? '—'}</div>
            <div className="br-card-sub">Retention {status?.retention_days ?? '—'} days</div>
          </div>
          <div className="br-card">
            <div className="br-card-label">Storage used</div>
            <div className="br-card-value">{formatBytes(status?.storage_used_bytes)}</div>
            <div className="br-card-sub">
              Encryption {status?.encryption_enabled ? 'on' : 'off'}
            </div>
          </div>
          <div className="br-card">
            <div className="br-card-label">Last verification</div>
            <div className="br-card-value">
              <span className={statusClass(status?.last_verification?.status)}>
                {status?.last_verification?.status || '—'}
              </span>
            </div>
            <div className="br-card-sub">{formatWhen(status?.last_verification?.at)}</div>
          </div>
        </div>

        <div className="br-table-wrap">
          {loading ? (
            <p className="br-muted">Loading…</p>
          ) : (
            <table className="br-table">
              <thead>
                <tr>
                  <th>Created</th>
                  <th>Backup ID</th>
                  <th>Trigger</th>
                  <th>Status</th>
                  <th>Size</th>
                  <th>Encrypted</th>
                  <th>Verified</th>
                  <th>Duration</th>
                  <th>Created by</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="br-muted">No backups yet.</td>
                  </tr>
                ) : (
                  items.map((row) => (
                    <React.Fragment key={row.id}>
                      <tr>
                        <td>{formatWhen(row.created_at)}</td>
                        <td className="br-mono">{row.backup_id}</td>
                        <td>{row.trigger_type}</td>
                        <td><span className={statusClass(row.status)}>{row.status}</span></td>
                        <td>{formatBytes(row.archive_size_bytes)}</td>
                        <td>{row.encrypted ? 'yes' : 'no'}</td>
                        <td><span className={statusClass(row.verify_status)}>{row.verify_status || '—'}</span></td>
                        <td>{formatDuration(row.duration_ms)}</td>
                        <td>{row.created_by_email || '—'}</td>
                        <td className="br-actions">
                          <button type="button" className="br-btn br-btn-ghost" disabled={busy || row.status !== 'completed'} onClick={() => onVerify(row)}>Verify</button>
                          <button type="button" className="br-btn br-btn-ghost" disabled={busy || row.status !== 'completed'} onClick={() => onDownload(row)}>Download</button>
                          <button type="button" className="br-btn br-btn-ghost" disabled={busy || ['queued', 'running', 'verifying'].includes(row.status)} onClick={() => setDeleteTarget(row)}>Delete</button>
                          <button
                            type="button"
                            className="br-btn br-btn-danger"
                            disabled={busy || row.status !== 'completed'}
                            onClick={() => {
                              setRestoreTarget(row);
                              setRestoreConfirm('');
                              setRestoreResult(null);
                              setRestorePhase('idle');
                            }}
                          >
                            Restore
                          </button>
                          <button type="button" className="br-btn br-btn-ghost" onClick={() => toggleExpand(row.id)}>
                            {expanded.has(row.id) ? 'Hide' : 'Details'}
                          </button>
                        </td>
                      </tr>
                      {expanded.has(row.id) ? (
                        <tr className="br-detail-row">
                          <td colSpan={10}>
                            <div className="br-detail">
                              <div>Checksum: <span className="br-mono">{row.checksum_sha256 || '—'}</span></div>
                              {row.error_message ? <div>Error: {row.error_message}</div> : null}
                              {row.verify_error ? <div>Verify error: {row.verify_error}</div> : null}
                              <div>DB size: {formatBytes(row.database_size_bytes)}</div>
                            </div>
                          </td>
                        </tr>
                      ) : null}
                    </React.Fragment>
                  ))
                )}
              </tbody>
            </table>
          )}
        </div>
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

      {restoreTarget ? (
        <div className="br-modal-backdrop" role="presentation">
          <div className="br-modal br-modal-wide" role="dialog">
            <h2>Restore from backup</h2>
            <p className="br-warn">
              This will overwrite the live PostgreSQL database. Writer services must be stopped.
              The web app does <strong>not</strong> run <code>pg_restore</code> itself — after confirmation
              you must run the host CLI command.
            </p>
            <p>Target: <span className="br-mono">{restoreTarget.backup_id}</span></p>

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
                  Safety backup: <span className="br-mono">{restoreResult?.safety_backup?.backup_id || restoreResult?.restore?.safety_backup_id}</span>
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
