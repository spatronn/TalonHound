import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../../lib/api.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import ImportIntelligenceModal from './ImportIntelligenceModal.jsx';
import { statusLabel } from './stages.js';
import {
  REPORT_LIST_PAGE_SIZE,
  REPORT_LIST_SEARCH_DEBOUNCE_MS,
  REPORT_LIST_SEARCH_MAX_LENGTH,
  buildReportListQueryParams,
  buildReportListUrlSearchParams,
  describeReportListEmptyState,
  formatReportListShowingLabel,
  normalizeReportListSearch,
  parseReportListUrlState
} from './reportList.js';
import { indicatorListCell } from './reportPhase.js';
import { TlpBadge, isElevatedTlp } from './tlp.jsx';
import { ui, badgeStyle } from './styles.js';

function sourceLabel(row) {
  if (row.source_name) return row.source_name;
  if (row.source_type === 'url') return row.source_url || 'URL';
  if (row.source_type === 'pdf') return row.source_file_name || 'PDF';
  if (row.source_type === 'thib') return 'THIB bundle';
  return row.source_type || '—';
}

function statusColors(report) {
  const a = String(report?.analysis_status || '').toLowerCase();
  if (a === 'failed') return { border: '#7f1d1d', bg: 'rgba(220,38,38,0.14)', color: '#fca5a5' };
  if (a === 'review_required') return { border: '#92400e', bg: 'rgba(217,119,6,0.14)', color: '#fcd34d' };
  if (a === 'ready' || a === 'skipped') return { border: '#166534', bg: 'rgba(22,163,74,0.14)', color: '#86efac' };
  return { border: '#0f766e', bg: 'rgba(15,118,110,0.18)', color: '#99f6e4' };
}

const searchInputStyle = { ...ui.input, padding: '8px 12px', fontSize: 13, minHeight: 36 };
const srOnly = { position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' };

export default function ThreatLibraryPage({ AppShell, useSession }) {
  const { isAdmin, canWrite } = useSession();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const initial = useMemo(() => parseReportListUrlState(searchParams), []); // eslint-disable-line react-hooks/exhaustive-deps
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [importOpen, setImportOpen] = useState(false);
  // searchInput follows every keystroke; search is the debounced, trimmed term
  // that drives requests and the URL (same split as the threat-actor list).
  const [searchInput, setSearchInput] = useState(initial.search);
  const [search, setSearch] = useState(initial.search);
  // Overlapping list requests: only the most recently issued response may land.
  const requestSeqRef = useRef(0);
  const abortRef = useRef(null);

  const load = useCallback(async () => {
    const seq = ++requestSeqRef.current;
    if (abortRef.current) abortRef.current.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setLoading(true);
    setError('');
    try {
      const params = buildReportListQueryParams({ search, limit: REPORT_LIST_PAGE_SIZE, offset: 0 });
      const { data } = await api.get('/threat-library/reports', { params, signal: controller.signal });
      if (seq !== requestSeqRef.current) return;
      setItems(data?.items || []);
      setTotal(Number(data?.total || 0));
    } catch (err) {
      if (err?.code === 'ERR_CANCELED' || err?.name === 'CanceledError' || err?.name === 'AbortError') return;
      if (seq !== requestSeqRef.current) return;
      setError(err?.response?.data?.message || 'Failed to load Threat Library');
      setItems([]);
      setTotal(0);
    } finally {
      if (seq === requestSeqRef.current) setLoading(false);
    }
  }, [search]);

  useEffect(() => {
    load().catch(() => {});
    return () => {
      if (abortRef.current) abortRef.current.abort();
    };
  }, [load]);

  useEffect(() => {
    const t = setTimeout(() => {
      const next = normalizeReportListSearch(searchInput);
      setSearch((prev) => (prev === next ? prev : next));
    }, REPORT_LIST_SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [searchInput]);

  useEffect(() => {
    const next = buildReportListUrlSearchParams({ search });
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [search, searchParams, setSearchParams]);

  const emptyState = describeReportListEmptyState({ loading, itemCount: items.length, search, canWrite });

  function onImported(report) {
    if (report?.id) {
      navigate(`/threat-intelligence/threat-library/${report.id}`);
      return;
    }
    load().catch(() => {});
  }

  return (
    <AppShell>
      <section style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, marginBottom: 12, flexWrap: 'wrap' }}>
          <div>
            <h1 style={ui.pageTitle}>Threat Library</h1>
            <p style={{ margin: '8px 0 0', fontSize: 13, color: '#94a3b8', maxWidth: 640, lineHeight: 1.5 }}>
              Import vendor reports and intelligence bundles, review extracted indicators, and promote matched IOCs.
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0, flexWrap: 'wrap' }}>
            {isAdmin ? (
              <Link to="/threat-intelligence/threat-library/ai-settings" style={{ ...ui.btn, textDecoration: 'none' }}>
                AI Settings
              </Link>
            ) : null}
            <button type="button" style={ui.btn} onClick={() => load().catch(() => {})}>Refresh</button>
            {canWrite ? (
              <button type="button" style={ui.btnPrimary} onClick={() => setImportOpen(true)}>
                Import Intelligence
              </button>
            ) : null}
          </div>
        </div>

        {error ? <div style={{ ...ui.error, marginBottom: 12 }} role="alert">{error}</div> : null}

        <div style={{ marginBottom: 12, maxWidth: 380 }}>
          <label htmlFor="tl-report-search" style={srOnly}>Search reports</label>
          <input
            id="tl-report-search"
            type="search"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Escape') setSearchInput(''); }}
            placeholder="Search reports..."
            maxLength={REPORT_LIST_SEARCH_MAX_LENGTH}
            autoComplete="off"
            spellCheck={false}
            style={searchInputStyle}
          />
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table width="100%" cellPadding="0" style={{ borderCollapse: 'collapse', fontSize: 13, background: 'transparent' }}>
            <thead>
              <tr style={ui.thead}>
                <th style={ui.th}>Report</th>
                <th style={ui.th}>Source</th>
                <th style={ui.th}>Published</th>
                <th style={ui.th}>TLP</th>
                <th style={ui.th}>Type</th>
                <th style={ui.th}>Entities</th>
                <th style={ui.th}>Indicators</th>
                <th style={ui.th}>Matched</th>
                <th style={ui.th}>Status</th>
                <th style={ui.th}>Imported</th>
              </tr>
            </thead>
            <tbody>
              {emptyState.kind === 'loading' ? (
                <tr style={ui.tr}><td colSpan={10} style={ui.td}>Loading…</td></tr>
              ) : emptyState.kind !== 'none' ? (
                <tr style={ui.tr}>
                  <td colSpan={10} style={{ ...ui.td, color: '#94a3b8' }} data-testid={`report-list-${emptyState.kind}`}>
                    {emptyState.message}{emptyState.hint ? ` ${emptyState.hint}` : ''}
                  </td>
                </tr>
              ) : items.map((row) => (
                <tr
                  key={row.id}
                  style={{ ...ui.tr, cursor: 'pointer' }}
                  onClick={() => navigate(`/threat-intelligence/threat-library/${row.id}`)}
                >
                  <td style={ui.td}>
                    <div style={{ fontWeight: 600, color: '#f1f5f9' }}>{row.title || 'Untitled report'}</div>
                    {isElevatedTlp(row.tlp) ? (
                      <div style={{ fontSize: 11, color: '#fcd34d', marginTop: 4 }}>Elevated TLP — handle carefully</div>
                    ) : null}
                  </td>
                  <td style={ui.td}>
                    <div>{sourceLabel(row)}</div>
                    <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{row.source_type || '—'}</div>
                  </td>
                  <td style={ui.td}>{row.published_at ? formatUserDateTime(row.published_at) : '—'}</td>
                  <td style={ui.td}><TlpBadge tlp={row.tlp} display={row.tlp_display} /></td>
                  <td style={ui.td}>{row.report_type || '—'}</td>
                  <td style={ui.td}>{row.entity_count ?? 0}</td>
                  <td style={ui.td}>{indicatorListCell(row)}</td>
                  <td style={ui.td}>{row.matched_count ?? 0}</td>
                  <td style={ui.td}>
                    <span style={badgeStyle(statusColors(row))}>{statusLabel(row)}</span>
                  </td>
                  <td style={ui.td}>{row.created_at ? formatUserDateTime(row.created_at) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {!loading && total > 0 ? (
          <div style={{ marginTop: 12, fontSize: 12, color: '#64748b' }}>
            {formatReportListShowingLabel({ shown: items.length, total, search })}
          </div>
        ) : null}
      </section>

      <ImportIntelligenceModal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={onImported}
      />
    </AppShell>
  );
}
