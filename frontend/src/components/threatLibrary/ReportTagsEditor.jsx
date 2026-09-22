import React, { useEffect, useRef, useState } from 'react';
import { api } from '../../lib/api.js';
import { normalizeReportTags, reportTagPickerParams, REPORT_TAG_HELP } from './reportTags.js';

const chipStyle = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: 5,
  padding: '2px 8px',
  borderRadius: 999,
  border: '1px solid #0f766e',
  fontSize: 12,
  color: '#5eead4',
  background: 'rgba(15,118,110,0.12)'
};

/**
 * Report header tag chips + picker (same catalog and picker pattern as IOC tags).
 * Adds/removes via /threat-library/reports/:id/tags and reports the server's
 * resulting tag list through onChange.
 */
export default function ReportTagsEditor({ reportId, tags, canWrite, disabled, onChange, onError }) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [suggestions, setSuggestions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const wrapRef = useRef(null);
  const current = normalizeReportTags(tags);

  useEffect(() => {
    if (!open) return undefined;
    let active = true;
    const handle = setTimeout(async () => {
      setLoading(true);
      try {
        const res = await api.get('/tags', { params: reportTagPickerParams(current, search) });
        if (active) setSuggestions(Array.isArray(res.data) ? res.data : []);
      } catch {
        if (active) setSuggestions([]);
      } finally {
        if (active) setLoading(false);
      }
    }, 200);
    return () => { active = false; clearTimeout(handle); };
    // current ids drive exclusion; re-query when the set changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, search, current.map((t) => t.id).join(',')]);

  useEffect(() => {
    if (!open) return undefined;
    function onDocClick(e) {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, [open]);

  async function mutate(request) {
    setSaving(true);
    try {
      const { data } = await request();
      onChange?.(normalizeReportTags(data?.tags));
    } catch (err) {
      onError?.(err?.response?.data?.message || 'Failed to update report tags');
    } finally {
      setSaving(false);
    }
  }

  const busy = Boolean(disabled) || saving;
  if (!canWrite && !current.length) return null;

  return (
    <span
      data-testid="report-tags"
      title={REPORT_TAG_HELP}
      style={{ display: 'inline-flex', flexWrap: 'wrap', alignItems: 'center', gap: 6 }}
    >
      {current.map((t) => (
        <span key={t.id} style={chipStyle} data-report-tag={t.name}>
          {t.name}
          {canWrite ? (
            <button
              type="button"
              onClick={() => mutate(() => api.delete(`/threat-library/reports/${reportId}/tags/${t.id}`))}
              disabled={busy}
              title="Remove report tag"
              aria-label={`Remove report tag ${t.name}`}
              style={{ padding: 0, border: 'none', background: 'transparent', color: '#2dd4bf', cursor: busy ? 'wait' : 'pointer', lineHeight: 1, fontSize: 14 }}
            >
              ×
            </button>
          ) : null}
        </span>
      ))}
      {canWrite ? (
        <span style={{ position: 'relative' }} ref={wrapRef}>
          <button
            type="button"
            className="tl-ghost-btn"
            style={{ minHeight: 24, padding: '2px 8px', fontSize: 11 }}
            disabled={busy}
            onClick={() => setOpen((v) => !v)}
            aria-label="Add report tag"
          >
            + Tag
          </button>
          {open ? (
            <div style={{ position: 'absolute', top: 'calc(100% + 6px)', left: 0, width: 240, border: '1px solid #334155', borderRadius: 10, background: '#0b1220', zIndex: 30, padding: 8 }}>
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search tag..."
                autoFocus
                style={{ width: '100%', marginBottom: 8, padding: '6px 8px', borderRadius: 8, border: '1px solid #475569', background: '#020617', color: '#e2e8f0', boxSizing: 'border-box' }}
              />
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 240, overflowY: 'auto' }}>
                {loading ? <div style={{ color: '#94a3b8', fontSize: 12 }}>Loading…</div> : null}
                {!loading && suggestions.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      setOpen(false);
                      setSearch('');
                      mutate(() => api.post(`/threat-library/reports/${reportId}/tags`, { tag_id: Number(t.id) }));
                    }}
                    style={{ textAlign: 'left', border: '1px solid #334155', borderRadius: 8, padding: '5px 8px', background: '#111827', color: '#e5e7eb', cursor: busy ? 'wait' : 'pointer' }}
                  >
                    {t.name}
                  </button>
                ))}
                {!loading && !suggestions.length ? (
                  <div style={{ color: '#94a3b8', fontSize: 12 }}>{search.trim() ? 'No tag found' : 'No tags available'}</div>
                ) : null}
              </div>
            </div>
          ) : null}
        </span>
      ) : null}
    </span>
  );
}
