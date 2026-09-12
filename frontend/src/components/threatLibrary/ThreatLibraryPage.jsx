import React, { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../../lib/api.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import ImportIntelligenceModal from './ImportIntelligenceModal.jsx';
import { statusLabel } from './stages.js';
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

export default function ThreatLibraryPage({ AppShell, useSession }) {
  const { isAdmin, canWrite } = useSession();
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [importOpen, setImportOpen] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get('/threat-library/reports', { params: { limit: 100, offset: 0 } });
      setItems(data?.items || []);
      setTotal(Number(data?.total || 0));
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to load Threat Library');
      setItems([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load().catch(() => {}); }, [load]);

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
              {loading ? (
                <tr style={ui.tr}><td colSpan={10} style={ui.td}>Loading…</td></tr>
              ) : items.length === 0 ? (
                <tr style={ui.tr}>
                  <td colSpan={10} style={{ ...ui.td, color: '#94a3b8' }}>
                    No reports yet.{canWrite ? ' Use Import Intelligence to add the first one.' : ''}
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
                  <td style={ui.td}>{row.indicator_count ?? 0}</td>
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
            Showing {items.length} of {total} report{total === 1 ? '' : 's'}
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
