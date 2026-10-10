/**
 * Threat Library report — Additional IOC Sources tab.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../../lib/api.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import { ui } from './styles.js';

function statusTone(status) {
  const s = String(status || '').toLowerCase();
  if (s === 'extracted' || s === 'inspected' || s === 'succeeded') return 'ok';
  if (s === 'failed' || s === 'blocked' || s === 'unsupported') return 'danger';
  if (s === 'dismissed') return 'muted';
  if (s === 'inspecting' || s === 'extracting' || s === 'attached') return 'warn';
  return 'neutral';
}

function PreviewBlock({ preview }) {
  if (!preview || typeof preview !== 'object') return null;
  const estimated = preview.estimated === true;
  const label = estimated ? 'Estimated' : 'Inspected';
  return (
    <dl className="th-ioc-source-preview">
      <div><dt>{label} raw</dt><dd>{preview.raw_count ?? '—'}</dd></div>
      <div><dt>{label} unique</dt><dd>{preview.unique_count ?? '—'}</dd></div>
      <div><dt>Overlap (original)</dt><dd>{preview.overlap_with_original ?? '—'}</dd></div>
      <div><dt>New identities</dt><dd>{preview.new_identities ?? '—'}</dd></div>
    </dl>
  );
}

export default function IocSourcesPanel({
  reportId,
  canWrite,
  summary: initialSummary,
  onChanged
}) {
  const [items, setItems] = useState([]);
  const [summary, setSummary] = useState(initialSummary || null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [addUrl, setAddUrl] = useState('');
  const [selected, setSelected] = useState(null);
  const [selectedPaths, setSelectedPaths] = useState(() => new Set());

  const load = useCallback(async () => {
    if (!reportId) return;
    setLoading(true);
    setError('');
    try {
      const res = await api.get(`/threat-library/reports/${reportId}/ioc-sources`);
      setItems(res.data?.items || []);
      setSummary(res.data?.summary || null);
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to load IOC sources');
    } finally {
      setLoading(false);
    }
  }, [reportId]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!selected) return;
    const fresh = items.find((i) => i.id === selected.id);
    if (fresh) setSelected(fresh);
  }, [items, selected?.id]);

  useEffect(() => {
    if (!selected?.files) {
      setSelectedPaths(new Set());
      return;
    }
    setSelectedPaths(new Set(selected.files.filter((f) => f.selected !== false).map((f) => f.path)));
  }, [selected?.id, selected?.files]);

  async function runAction(key, fn) {
    setBusy(key);
    setError('');
    try {
      await fn();
      await load();
      if (typeof onChanged === 'function') onChanged();
    } catch (err) {
      setError(err?.response?.data?.message || err.message || 'Action failed');
    } finally {
      setBusy('');
    }
  }

  async function addSource(e) {
    e.preventDefault();
    const url = addUrl.trim();
    if (!url) return;
    await runAction('add', async () => {
      await api.post(`/threat-library/reports/${reportId}/ioc-sources`, { url });
      setAddUrl('');
    });
  }

  const discovered = items.filter((s) => s.lifecycle_status === 'discovered' || s.lifecycle_status === 'inspected' || s.lifecycle_status === 'failed' || s.lifecycle_status === 'blocked' || s.lifecycle_status === 'unsupported');
  const attached = items.filter((s) => ['attached', 'extracting', 'extracted', 'stale'].includes(s.lifecycle_status));

  return (
    <section className="th-ioc-sources" aria-label="IOC Sources">
      <header className="th-ioc-sources__header">
        <div>
          <h2 style={{ margin: 0, fontSize: '1.1rem' }}>IOC Sources</h2>
          <p style={{ margin: '0.35rem 0 0', color: 'var(--th-muted, #64748b)', fontSize: '0.9rem' }}>
            External IOC datasets linked to this report. Approving a source authorizes extraction;
            it does not approve IOCs into inventory.
          </p>
        </div>
        <ul className="th-ioc-sources__counts" aria-label="Source counts">
          <li><strong>{summary?.total ?? items.length}</strong> total</li>
          <li><strong>{summary?.discovered_pending ?? 0}</strong> need review</li>
          <li><strong>{summary?.attached ?? 0}</strong> attached</li>
          <li><strong>{summary?.extracted ?? 0}</strong> extracted</li>
          <li><strong>{summary?.failed ?? 0}</strong> failed</li>
        </ul>
      </header>

      {canWrite ? (
        <form className="th-ioc-sources__add" onSubmit={addSource}>
          <label htmlFor="th-ioc-source-url">Add source URL</label>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <input
              id="th-ioc-source-url"
              type="url"
              value={addUrl}
              onChange={(e) => setAddUrl(e.target.value)}
              placeholder="https://github.com/org/ioc/…"
              style={{ flex: '1 1 16rem', minWidth: 0 }}
              disabled={Boolean(busy)}
            />
            <button type="submit" className="btn btn-primary" disabled={Boolean(busy) || !addUrl.trim()}>
              {busy === 'add' ? 'Adding…' : 'Add Source'}
            </button>
          </div>
        </form>
      ) : null}

      {error ? <p role="alert" style={{ color: 'var(--th-danger, #b91c1c)' }}>{error}</p> : null}
      {loading ? <p>Loading sources…</p> : null}

      {!loading && !items.length ? (
        <p style={{ color: 'var(--th-muted, #64748b)' }}>
          No additional IOC sources discovered or added yet.
        </p>
      ) : null}

      <div className="th-ioc-sources__layout">
        <div className="th-ioc-sources__list">
          {discovered.length ? (
            <div>
              <h3 style={{ fontSize: '0.95rem' }}>Discovered / pending</h3>
              <ul className="th-ioc-source-cards">
                {discovered.map((s) => (
                  <li key={s.id}>
                    <button
                      type="button"
                      className={`th-ioc-source-card${selected?.id === s.id ? ' is-selected' : ''}`}
                      onClick={() => setSelected(s)}
                    >
                      <span className={`th-ioc-source-status is-${statusTone(s.lifecycle_status)}`}>
                        {s.lifecycle_status}
                      </span>
                      <span className="th-ioc-source-card__url">{s.original_url}</span>
                      <span className="th-ioc-source-card__meta">
                        {s.source_type} · {s.discovery_method}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {attached.length ? (
            <div>
              <h3 style={{ fontSize: '0.95rem' }}>Attached</h3>
              <ul className="th-ioc-source-cards">
                {attached.map((s) => (
                  <li key={s.id}>
                    <button
                      type="button"
                      className={`th-ioc-source-card${selected?.id === s.id ? ' is-selected' : ''}`}
                      onClick={() => setSelected(s)}
                    >
                      <span className={`th-ioc-source-status is-${statusTone(s.lifecycle_status)}`}>
                        {s.lifecycle_status}
                      </span>
                      <span className="th-ioc-source-card__url">{s.original_url}</span>
                      <span className="th-ioc-source-card__meta">
                        extract: {s.extraction_status}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>

        {selected ? (
          <aside className="th-ioc-source-drawer" aria-label="Source detail">
            <header>
              <h3 style={{ marginTop: 0, fontSize: '1rem', wordBreak: 'break-all' }}>{selected.original_url}</h3>
              <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--th-muted, #64748b)' }}>
                Canonical: {selected.canonical_url}
              </p>
            </header>

            <dl className="th-ioc-source-meta">
              <div><dt>Status</dt><dd>{selected.lifecycle_status}</dd></div>
              <div><dt>Type</dt><dd>{selected.source_type}</dd></div>
              <div><dt>Discovery</dt><dd>{selected.discovery_method}</dd></div>
              <div><dt>Inspection</dt><dd>{selected.inspection_status}</dd></div>
              <div><dt>Extraction</dt><dd>{selected.extraction_status}</dd></div>
              {selected.last_fetched_at ? (
                <div><dt>Last fetch</dt><dd>{formatUserDateTime(selected.last_fetched_at)}</dd></div>
              ) : null}
              {selected.approved_at ? (
                <div><dt>Approved</dt><dd>{formatUserDateTime(selected.approved_at)}</dd></div>
              ) : null}
            </dl>

            {selected.discovery_evidence?.link_text || selected.discovery_evidence?.surrounding_text ? (
              <div>
                <h4 style={{ fontSize: '0.9rem' }}>Discovery evidence</h4>
                {selected.discovery_evidence.link_text ? (
                  <p style={{ fontSize: '0.9rem' }}>Link text: {selected.discovery_evidence.link_text}</p>
                ) : null}
                {selected.discovery_evidence.surrounding_text ? (
                  <p style={{ fontSize: '0.85rem', color: 'var(--th-muted, #64748b)' }}>
                    {selected.discovery_evidence.surrounding_text}
                  </p>
                ) : null}
              </div>
            ) : null}

            <PreviewBlock preview={selected.preview} />

            {selected.error_detail ? (
              <p role="alert" style={{ color: 'var(--th-danger, #b91c1c)', fontSize: '0.9rem' }}>
                {selected.error_code ? `${selected.error_code}: ` : ''}{selected.error_detail}
              </p>
            ) : null}

            {Array.isArray(selected.files) && selected.files.length ? (
              <div>
                <h4 style={{ fontSize: '0.9rem' }}>Files</h4>
                <ul className="th-ioc-source-files">
                  {selected.files.map((f) => (
                    <li key={f.path}>
                      <label style={{ display: 'flex', gap: '0.4rem', alignItems: 'flex-start' }}>
                        <input
                          type="checkbox"
                          checked={selectedPaths.has(f.path)}
                          disabled={!canWrite || selected.lifecycle_status === 'extracted'}
                          onChange={() => {
                            setSelectedPaths((prev) => {
                              const next = new Set(prev);
                              if (next.has(f.path)) next.delete(f.path);
                              else next.add(f.path);
                              return next;
                            });
                          }}
                        />
                        <span>
                          <code style={{ wordBreak: 'break-all' }}>{f.path}</code>
                          <br />
                          <span style={{ fontSize: '0.8rem', color: 'var(--th-muted, #64748b)' }}>
                            {f.parse_status}
                            {f.estimated_unique_count != null ? ` · ~${f.estimated_unique_count} unique` : ''}
                          </span>
                        </span>
                      </label>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {canWrite ? (
              <div className="th-ioc-source-actions" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '1rem' }}>
                {['discovered', 'inspected', 'failed', 'blocked', 'unsupported', 'attached', 'extracted', 'stale'].includes(selected.lifecycle_status) ? (
                  <button
                    type="button"
                    className="btn"
                    disabled={Boolean(busy)}
                    onClick={() => runAction('inspect', () => api.post(`/threat-library/ioc-sources/${selected.id}/retry-inspect`))}
                  >
                    {busy === 'inspect' ? 'Queuing…' : 'Retry inspection'}
                  </button>
                ) : null}
                {['inspected', 'failed', 'stale'].includes(selected.lifecycle_status) ? (
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={Boolean(busy)}
                    onClick={() => runAction('approve', () => api.post(`/threat-library/ioc-sources/${selected.id}/approve`, {
                      selected_paths: [...selectedPaths]
                    }))}
                  >
                    {busy === 'approve' ? 'Attaching…' : 'Approve & Attach'}
                  </button>
                ) : null}
                {['attached', 'extracted', 'failed', 'stale'].includes(selected.lifecycle_status) ? (
                  <button
                    type="button"
                    className="btn"
                    disabled={Boolean(busy)}
                    onClick={() => runAction('extract', () => api.post(`/threat-library/ioc-sources/${selected.id}/retry-extract`))}
                  >
                    {busy === 'extract' ? 'Queuing…' : 'Retry extraction'}
                  </button>
                ) : null}
                {['discovered', 'inspected', 'failed', 'blocked', 'unsupported', 'stale'].includes(selected.lifecycle_status) ? (
                  <button
                    type="button"
                    className="btn"
                    disabled={Boolean(busy)}
                    onClick={() => runAction('dismiss', () => api.post(`/threat-library/ioc-sources/${selected.id}/dismiss`))}
                  >
                    Dismiss
                  </button>
                ) : null}
              </div>
            ) : null}
          </aside>
        ) : null}
      </div>

      <style>{`
        .th-ioc-sources__header { display: flex; flex-wrap: wrap; gap: 1rem; justify-content: space-between; margin-bottom: 1rem; }
        .th-ioc-sources__counts { display: flex; flex-wrap: wrap; gap: 0.75rem; list-style: none; margin: 0; padding: 0; font-size: 0.85rem; }
        .th-ioc-sources__add { margin-bottom: 1.25rem; }
        .th-ioc-sources__add label { display: block; font-size: 0.85rem; margin-bottom: 0.35rem; }
        .th-ioc-sources__layout { display: grid; grid-template-columns: minmax(0, 1fr); gap: 1rem; }
        @media (min-width: 900px) {
          .th-ioc-sources__layout { grid-template-columns: minmax(0, 1fr) minmax(18rem, 22rem); }
        }
        .th-ioc-source-cards { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.5rem; }
        .th-ioc-source-card {
          width: 100%; text-align: left; border: 1px solid var(--th-border, #e2e8f0);
          background: var(--th-surface, #fff); padding: 0.75rem; border-radius: 6px; cursor: pointer;
        }
        .th-ioc-source-card.is-selected { border-color: var(--th-accent, #0f766e); box-shadow: inset 0 0 0 1px var(--th-accent, #0f766e); }
        .th-ioc-source-card__url { display: block; font-size: 0.9rem; word-break: break-all; margin: 0.35rem 0; }
        .th-ioc-source-card__meta { font-size: 0.8rem; color: var(--th-muted, #64748b); }
        .th-ioc-source-status { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.03em; }
        .th-ioc-source-status.is-ok { color: #047857; }
        .th-ioc-source-status.is-danger { color: #b91c1c; }
        .th-ioc-source-status.is-warn { color: #b45309; }
        .th-ioc-source-status.is-muted { color: #64748b; }
        .th-ioc-source-drawer { border: 1px solid var(--th-border, #e2e8f0); border-radius: 6px; padding: 1rem; background: var(--th-surface, #fff); }
        .th-ioc-source-meta, .th-ioc-source-preview { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem 1rem; font-size: 0.85rem; }
        .th-ioc-source-meta dt, .th-ioc-source-preview dt { color: var(--th-muted, #64748b); font-weight: 500; }
        .th-ioc-source-meta dd, .th-ioc-source-preview dd { margin: 0.1rem 0 0; }
        .th-ioc-source-files { list-style: none; margin: 0; padding: 0; display: grid; gap: 0.4rem; max-height: 14rem; overflow: auto; }
      `}</style>
    </section>
  );
}
