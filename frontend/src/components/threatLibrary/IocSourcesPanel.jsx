/**
 * Threat Library report — Additional IOC Sources tab.
 * Visual system matches Threat Library reportPage.css / styles.js (dark surfaces).
 */

import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../../lib/api.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import { badgeStyle, ui } from './styles.js';
import {
  isAttachedLifecycle,
  isPendingLifecycle,
  lifecycleBadge,
  shortSourceTitle,
  sourceCardMeta,
  sourceTypeLabel
} from './iocSourcesUi.js';

function PreviewBlock({ preview }) {
  if (!preview || typeof preview !== 'object') return null;
  const estimated = preview.estimated === true;
  const label = estimated ? 'Estimated' : 'Inspected';
  return (
    <dl className="tl-ioc-source-preview">
      <div>
        <dt>{label} raw</dt>
        <dd>{preview.raw_count ?? '—'}</dd>
      </div>
      <div>
        <dt>{label} unique</dt>
        <dd>{preview.unique_count ?? '—'}</dd>
      </div>
      <div>
        <dt>Overlap (original)</dt>
        <dd>{preview.overlap_with_original ?? '—'}</dd>
      </div>
      <div>
        <dt>New identities</dt>
        <dd>{preview.new_identities ?? '—'}</dd>
      </div>
      {preview.repo_ref ? (
        <div>
          <dt>Branch / ref</dt>
          <dd>{preview.repo_ref}</dd>
        </div>
      ) : null}
    </dl>
  );
}

function SourceCard({ source, selected, onSelect }) {
  const badge = lifecycleBadge(source.lifecycle_status);
  const title = shortSourceTitle(source);
  const meta = sourceCardMeta(source);
  const url = source.original_url || source.canonical_url || '';
  return (
    <button
      type="button"
      className={`tl-ioc-source-card${selected ? ' is-selected' : ''}`}
      onClick={() => onSelect(source)}
      aria-pressed={selected}
      data-testid="ioc-source-card"
      data-lifecycle={source.lifecycle_status || ''}
    >
      <div className="tl-ioc-source-card__head">
        <span className="tl-ioc-source-card__type">{sourceTypeLabel(source.source_type)}</span>
        <span className="tl-badge" style={badgeStyle(badge)} data-testid="ioc-source-status">
          {badge.label}
        </span>
      </div>
      <div className="tl-ioc-source-card__title">{title}</div>
      {url ? (
        <div className="tl-ioc-source-card__url" title={url}>
          {url}
        </div>
      ) : null}
      {meta ? <div className="tl-ioc-source-card__meta">{meta}</div> : null}
    </button>
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

  const discovered = items.filter((s) => isPendingLifecycle(s.lifecycle_status));
  const attached = items.filter((s) => isAttachedLifecycle(s.lifecycle_status));
  const selectedBadge = selected ? lifecycleBadge(selected.lifecycle_status) : null;

  return (
    <section className="tl-ioc-sources" aria-label="IOC Sources" data-testid="ioc-sources-panel">
      <header className="tl-ioc-sources__header">
        <div className="tl-ioc-sources__intro">
          <h2 className="tl-ioc-sources__title">IOC Sources</h2>
          <p className="tl-ioc-sources__lede">
            External IOC datasets linked to this report. Approving a source authorizes extraction;
            it does not approve IOCs into inventory.
          </p>
        </div>
        <ul className="tl-ioc-sources__counts" aria-label="Source counts">
          <li><strong>{summary?.total ?? items.length}</strong> total</li>
          <li><strong>{summary?.discovered_pending ?? 0}</strong> need review</li>
          <li><strong>{summary?.attached ?? 0}</strong> attached</li>
          <li><strong>{summary?.extracted ?? 0}</strong> extracted</li>
          <li><strong>{summary?.failed ?? 0}</strong> failed</li>
        </ul>
      </header>

      {canWrite ? (
        <form className="tl-ioc-sources__add" onSubmit={addSource}>
          <label htmlFor="tl-ioc-source-url" style={ui.label}>Add source URL</label>
          <div className="tl-ioc-sources__add-row">
            <input
              id="tl-ioc-source-url"
              type="url"
              value={addUrl}
              onChange={(e) => setAddUrl(e.target.value)}
              placeholder="https://github.com/org/ioc/…"
              style={{ ...ui.input, flex: '1 1 16rem', minWidth: 0 }}
              disabled={Boolean(busy)}
            />
            <button
              type="submit"
              style={ui.btnPrimary}
              disabled={Boolean(busy) || !addUrl.trim()}
            >
              {busy === 'add' ? 'Adding…' : 'Add Source'}
            </button>
          </div>
        </form>
      ) : null}

      {error ? <p role="alert" style={ui.error}>{error}</p> : null}
      {loading ? <p style={ui.muted}>Loading sources…</p> : null}

      {!loading && !items.length ? (
        <p style={ui.muted}>
          No additional IOC sources discovered or added yet.
        </p>
      ) : null}

      <div className="tl-ioc-sources__layout">
        <div className="tl-ioc-sources__list">
          {discovered.length ? (
            <section className="tl-ioc-sources__group" aria-label="Discovered or pending sources">
              <h3 className="tl-ioc-sources__group-title">Discovered / pending</h3>
              <ul className="tl-ioc-source-cards">
                {discovered.map((s) => (
                  <li key={s.id}>
                    <SourceCard
                      source={s}
                      selected={selected?.id === s.id}
                      onSelect={setSelected}
                    />
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {attached.length ? (
            <section className="tl-ioc-sources__group" aria-label="Attached sources">
              <h3 className="tl-ioc-sources__group-title">Attached</h3>
              <ul className="tl-ioc-source-cards">
                {attached.map((s) => (
                  <li key={s.id}>
                    <SourceCard
                      source={s}
                      selected={selected?.id === s.id}
                      onSelect={setSelected}
                    />
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
        </div>

        {selected ? (
          <aside className="tl-ioc-source-drawer" aria-label="Source detail" data-testid="ioc-source-drawer">
            <header className="tl-ioc-source-drawer__header">
              <div className="tl-ioc-source-drawer__head-row">
                <span className="tl-ioc-source-card__type">{sourceTypeLabel(selected.source_type)}</span>
                {selectedBadge ? (
                  <span className="tl-badge" style={badgeStyle(selectedBadge)}>{selectedBadge.label}</span>
                ) : null}
              </div>
              <h3 className="tl-ioc-source-drawer__title">{shortSourceTitle(selected)}</h3>
              <p className="tl-ioc-source-drawer__url" title={selected.original_url || ''}>
                {selected.original_url}
              </p>
              {selected.canonical_url && selected.canonical_url !== selected.original_url ? (
                <p className="tl-ioc-source-drawer__canonical">
                  Canonical: {selected.canonical_url}
                </p>
              ) : null}
            </header>

            <dl className="tl-ioc-source-meta">
              <div><dt>Status</dt><dd>{selected.lifecycle_status}</dd></div>
              <div><dt>Type</dt><dd>{sourceTypeLabel(selected.source_type)}</dd></div>
              <div><dt>Discovery</dt><dd>{selected.discovery_method || '—'}</dd></div>
              <div><dt>Inspection</dt><dd>{selected.inspection_status || '—'}</dd></div>
              <div><dt>Extraction</dt><dd>{selected.extraction_status || '—'}</dd></div>
              {selected.repo_revision ? (
                <div><dt>Revision</dt><dd className="tl-ioc-source-meta__mono">{selected.repo_revision}</dd></div>
              ) : null}
              {selected.last_fetched_at ? (
                <div><dt>Last fetch</dt><dd>{formatUserDateTime(selected.last_fetched_at)}</dd></div>
              ) : null}
              {selected.approved_at ? (
                <div><dt>Approved</dt><dd>{formatUserDateTime(selected.approved_at)}</dd></div>
              ) : null}
            </dl>

            {selected.discovery_evidence?.link_text || selected.discovery_evidence?.surrounding_text ? (
              <div className="tl-ioc-source-drawer__block">
                <h4 className="tl-ioc-source-drawer__h">Discovery evidence</h4>
                {selected.discovery_evidence.link_text ? (
                  <p className="tl-ioc-source-drawer__body">Link text: {selected.discovery_evidence.link_text}</p>
                ) : null}
                {selected.discovery_evidence.surrounding_text ? (
                  <p className="tl-ioc-source-drawer__muted">
                    {selected.discovery_evidence.surrounding_text}
                  </p>
                ) : null}
              </div>
            ) : null}

            <PreviewBlock preview={selected.preview} />

            {selected.error_detail ? (
              <p role="alert" className="tl-ioc-source-drawer__error">
                {selected.error_code ? `${selected.error_code}: ` : ''}{selected.error_detail}
              </p>
            ) : null}

            {Array.isArray(selected.files) && selected.files.length ? (
              <div className="tl-ioc-source-drawer__block">
                <h4 className="tl-ioc-source-drawer__h">Files</h4>
                <ul className="tl-ioc-source-files">
                  {selected.files.map((f) => (
                    <li key={f.path}>
                      <label className="tl-ioc-source-files__row">
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
                          <code className="tl-ioc-source-files__path">{f.path}</code>
                          <span className="tl-ioc-source-files__meta">
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
              <div className="tl-ioc-source-actions">
                {['discovered', 'inspected', 'failed', 'blocked', 'unsupported', 'attached', 'extracted', 'stale'].includes(selected.lifecycle_status) ? (
                  <button
                    type="button"
                    style={ui.btn}
                    disabled={Boolean(busy)}
                    onClick={() => runAction('inspect', () => api.post(`/threat-library/ioc-sources/${selected.id}/retry-inspect`))}
                  >
                    {busy === 'inspect' ? 'Queuing…' : 'Retry inspection'}
                  </button>
                ) : null}
                {['inspected', 'failed', 'stale'].includes(selected.lifecycle_status) ? (
                  <button
                    type="button"
                    style={ui.btnPrimary}
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
                    style={ui.btn}
                    disabled={Boolean(busy)}
                    onClick={() => runAction('extract', () => api.post(`/threat-library/ioc-sources/${selected.id}/retry-extract`))}
                  >
                    {busy === 'extract' ? 'Queuing…' : 'Retry extraction'}
                  </button>
                ) : null}
                {['discovered', 'inspected', 'failed', 'blocked', 'unsupported', 'stale'].includes(selected.lifecycle_status) ? (
                  <button
                    type="button"
                    style={ui.btnDanger}
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
    </section>
  );
}
