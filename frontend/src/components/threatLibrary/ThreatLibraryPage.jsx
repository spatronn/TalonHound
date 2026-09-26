import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../../lib/api.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import ImportIntelligenceModal from './ImportIntelligenceModal.jsx';
import { statusLabel } from './stages.js';
import {
  REPORT_LIST_PAGE_SIZE,
  REPORT_LIST_PAGE_SIZE_OPTIONS,
  REPORT_LIST_SEARCH_DEBOUNCE_MS,
  REPORT_LIST_SEARCH_MAX_LENGTH,
  buildReportListUrlSearchParams,
  describeReportListEmptyState,
  describeReportListPagination,
  formatReportListShowingLabel,
  normalizeReportListSearch,
  parseReportListUrlState
} from './reportList.js';
import { createReportListLoader } from './reportListLoader.js';
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
const pagerBtn = { ...ui.btn, minHeight: 30, padding: '4px 10px', fontSize: 12 };
const pageSizeSelect = { ...ui.select, width: 'auto', minHeight: 30, padding: '4px 8px', fontSize: 12 };

export default function ThreatLibraryPage({ AppShell, useSession }) {
  const { isAdmin, canWrite } = useSession();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  // The URL is the single source of truth for the debounced search term, the
  // page and the rows per page (?search=&page=&limit=), so reload, Back/Forward
  // and shared links all land on the same list state and nothing can fight the router.
  const { search, page, pageSize } = useMemo(() => parseReportListUrlState(searchParams), [searchParams]);
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [importOpen, setImportOpen] = useState(false);
  // searchInput follows every keystroke; the URL `search` is its debounced,
  // trimmed form (same split as the threat-actor list).
  const [searchInput, setSearchInput] = useState(search);
  // Overlapping list requests (search, page, Refresh) go through one loader:
  // only the most recently issued response may land, and an out-of-range page
  // is clamped to the last valid one instead of stranding the user.
  const loaderRef = useRef(null);
  if (!loaderRef.current) {
    loaderRef.current = createReportListLoader({
      pageSize: REPORT_LIST_PAGE_SIZE,
      fetchPage: async (params, signal) => (await api.get('/threat-library/reports', { params, signal })).data
    });
  }

  // react-router recreates searchParams AND setSearchParams on every URL change;
  // read both through a ref so setListUrl (and therefore load) keeps one identity
  // and a URL rewrite never re-issues the list request by itself.
  const routerRef = useRef({ searchParams, setSearchParams });
  routerRef.current = { searchParams, setSearchParams };
  const setListUrl = useCallback((next) => {
    const params = buildReportListUrlSearchParams(next);
    const router = routerRef.current;
    if (params.toString() !== router.searchParams.toString()) router.setSearchParams(params, { replace: true });
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    const result = await loaderRef.current.load({ search, page, pageSize });
    if (result.kind === 'stale') return;
    if (result.kind === 'clamped') {
      // Result set shrank below this page (search narrowed, rows deleted):
      // keep the loading placeholder and reload the last valid page.
      setTotal(result.total);
      setListUrl({ search, page: result.page, pageSize });
      return;
    }
    if (result.kind === 'error') {
      setError(result.message);
      setItems([]);
      setTotal(0);
    } else {
      setItems(result.items);
      setTotal(result.total);
    }
    setLoading(false);
  }, [search, page, pageSize, setListUrl]);

  useEffect(() => {
    load().catch(() => {});
  }, [load]);

  useEffect(() => () => loaderRef.current?.abort(), []);

  // Debounced term -> URL. A new term (or clearing it) always starts from page 1.
  useEffect(() => {
    const t = setTimeout(() => {
      const next = normalizeReportListSearch(searchInput);
      if (next !== search) setListUrl({ search: next, page: 1, pageSize });
    }, REPORT_LIST_SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [searchInput, search, pageSize, setListUrl]);

  // URL term changed underneath the field (Back/Forward, shared link): reflect it,
  // but leave the raw input alone while it already normalises to the same term.
  useEffect(() => {
    setSearchInput((prev) => (normalizeReportListSearch(prev) === search ? prev : search));
  }, [search]);

  // Canonicalise a hand-typed URL (page=1, padded search, junk page / limit)
  // once; the serialised form of the parsed state is a fixed point, so this cannot loop.
  useEffect(() => {
    setListUrl({ search, page, pageSize });
  }, [search, page, pageSize, setListUrl]);

  const goToPage = (next) => setListUrl({ search, page: next, pageSize });
  // A new page size restarts at page 1 so the first visible row is never skipped.
  const changePageSize = (next) => setListUrl({ search, page: 1, pageSize: next });

  const pagination = describeReportListPagination({ page, total, pageSize });
  const emptyState = describeReportListEmptyState({ loading, itemCount: items.length, total, search, canWrite });

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
                <th style={ui.th}>TLP</th>
                <th style={ui.th}>Entities</th>
                <th style={ui.th}>Indicators</th>
                <th style={ui.th}>Matched</th>
                <th style={ui.th}>Status</th>
                <th style={ui.th}>Imported</th>
              </tr>
            </thead>
            <tbody>
              {emptyState.kind === 'loading' ? (
                <tr style={ui.tr}><td colSpan={8} style={ui.td}>Loading…</td></tr>
              ) : emptyState.kind !== 'none' ? (
                <tr style={ui.tr}>
                  <td colSpan={8} style={{ ...ui.td, color: '#94a3b8' }} data-testid={`report-list-${emptyState.kind}`}>
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
                  <td style={ui.td}><TlpBadge tlp={row.tlp} display={row.tlp_display} /></td>
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

        {total > 0 ? (
          <div style={{ marginTop: 12, display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center', justifyContent: 'space-between', fontSize: 12, color: '#64748b' }}>
            <div>
              {formatReportListShowingLabel({ from: pagination.from, to: pagination.to, total, search })}
              {loading ? ' \u00b7 Updating\u2026' : ''}
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <label htmlFor="tl-report-page-size" style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                Rows per page
                <select
                  id="tl-report-page-size"
                  style={pageSizeSelect}
                  value={pageSize}
                  onChange={(e) => changePageSize(Number(e.target.value))}
                >
                  {REPORT_LIST_PAGE_SIZE_OPTIONS.map((n) => (
                    <option key={n} value={n}>{n}</option>
                  ))}
                </select>
              </label>
              <button
                type="button"
                style={pagerBtn}
                disabled={!pagination.hasPrevious || loading}
                onClick={() => goToPage(Math.max(1, page - 1))}
              >
                Previous
              </button>
              <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{pagination.pageLabel}</span>
              <button
                type="button"
                style={pagerBtn}
                disabled={!pagination.hasNext || loading}
                onClick={() => goToPage(page + 1)}
              >
                Next
              </button>
            </div>
          </div>
        ) : null}
      </section>

      <ImportIntelligenceModal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={onImported}
        onOpenReport={(reportId) => navigate(`/threat-intelligence/threat-library/${reportId}`)}
      />
    </AppShell>
  );
}
