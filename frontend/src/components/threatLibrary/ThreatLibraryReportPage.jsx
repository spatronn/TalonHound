import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api } from '../../lib/api.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import {
  buildProgressChecklist,
  isProcessingStatus,
  statusLabel
} from './stages.js';
import { TlpBadge, isElevatedTlp, normalizeTlp } from './tlp.jsx';
import { ui, badgeStyle } from './styles.js';

const REVIEW_FILTERS = [
  { id: 'all', label: 'All' },
  { id: 'existing', label: 'Existing' },
  { id: 'new', label: 'New' },
  { id: 'context_only', label: 'Context Only' },
  { id: 'needs_review', label: 'Needs Review' }
];

function matchFilter(candidate, filter) {
  if (filter === 'all') return true;
  const state = String(candidate.match_state || '').toLowerCase();
  const review = String(candidate.review_status || '').toLowerCase();
  if (filter === 'existing') return state === 'existing' || Boolean(candidate.matched_ioc_id);
  if (filter === 'new') return state === 'new';
  if (filter === 'context_only') return state === 'context_only' || review === 'context_only' || candidate.assessment === 'context_only';
  if (filter === 'needs_review') return state === 'needs_review' || review === 'pending';
  return true;
}

function ProgressChecklist({ report, job }) {
  const items = buildProgressChecklist(report, job);
  return (
    <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 8 }}>
      {items.map((item) => {
        const color = item.state === 'done' ? '#86efac'
          : item.state === 'active' ? '#5eead4'
            : item.state === 'failed' ? '#fca5a5'
              : '#64748b';
        const mark = item.state === 'done' ? '✓'
          : item.state === 'active' ? '●'
            : item.state === 'failed' ? '✕'
              : '○';
        return (
          <li key={item.key} style={{ display: 'flex', alignItems: 'center', gap: 10, color, fontSize: 13 }}>
            <span style={{ width: 18, textAlign: 'center', fontWeight: 700 }}>{mark}</span>
            <span style={{ fontWeight: item.state === 'active' ? 700 : 500 }}>{item.label}</span>
          </li>
        );
      })}
    </ul>
  );
}

function SectionCard({ title, children, actions }) {
  return (
    <div style={{ ...ui.formPanel, marginBottom: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center', marginBottom: 10, flexWrap: 'wrap' }}>
        <h2 style={{ ...ui.formTitle, margin: 0 }}>{title}</h2>
        {actions || null}
      </div>
      {children}
    </div>
  );
}

export default function ThreatLibraryReportPage({ AppShell, useSession }) {
  const { reportId } = useParams();
  const navigate = useNavigate();
  const { isAdmin, canWrite } = useSession();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [feedback, setFeedback] = useState('');
  const [report, setReport] = useState(null);
  const [candidates, setCandidates] = useState([]);
  const [entities, setEntities] = useState([]);
  const [relationships, setRelationships] = useState([]);
  const [artifacts, setArtifacts] = useState([]);
  const [documentMeta, setDocumentMeta] = useState(null);
  const [job, setJob] = useState(null);
  const [filter, setFilter] = useState('all');
  const [selected, setSelected] = useState(() => new Set());
  const [busy, setBusy] = useState('');

  const loadDetail = useCallback(async () => {
    const { data } = await api.get(`/threat-library/reports/${reportId}`);
    setReport(data?.report || null);
    setCandidates(data?.candidates || []);
    setEntities(data?.entities || []);
    setRelationships(data?.relationships || []);
    setArtifacts(data?.artifacts || []);
    setDocumentMeta(data?.document_meta || null);
    const jobs = data?.jobs || [];
    setJob(jobs[0] || null);
    return data;
  }, [reportId]);

  const loadStatus = useCallback(async () => {
    const { data } = await api.get(`/threat-library/reports/${reportId}/status`);
    if (data?.report) setReport(data.report);
    setJob(data?.job || null);
    return data;
  }, [reportId]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    loadDetail()
      .catch((err) => {
        if (!cancelled) setError(err?.response?.data?.message || 'Failed to load report');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [loadDetail]);

  const processing = isProcessingStatus(report);

  useEffect(() => {
    if (!processing || !reportId) return undefined;
    const timer = window.setInterval(() => {
      loadStatus()
        .then((data) => {
          const next = data?.report;
          if (!isProcessingStatus(next)) {
            return loadDetail();
          }
          return null;
        })
        .catch(() => {});
    }, 2000);
    return () => window.clearInterval(timer);
  }, [processing, reportId, loadStatus, loadDetail]);

  const filtered = useMemo(
    () => candidates.filter((c) => matchFilter(c, filter)),
    [candidates, filter]
  );

  function toggleOne(id) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAllFiltered() {
    setSelected((prev) => {
      const ids = filtered.map((c) => c.id);
      const allOn = ids.length > 0 && ids.every((id) => prev.has(id));
      const next = new Set(prev);
      if (allOn) ids.forEach((id) => next.delete(id));
      else ids.forEach((id) => next.add(id));
      return next;
    });
  }

  async function runReview(action) {
    if (!canWrite) return;
    setBusy(action);
    setFeedback('');
    setError('');
    try {
      const body = { action };
      if (action !== 'approve_high_confidence_malicious') {
        body.candidate_ids = [...selected];
      }
      const { data } = await api.post(`/threat-library/reports/${reportId}/review`, body);
      if (data?.errors?.length) {
        setFeedback(`Completed with ${data.errors.length} error(s).`);
      } else {
        setFeedback(action === 'create_iocs'
          ? `Created ${data?.created?.length || 0} IOC(s).`
          : 'Review action applied.');
      }
      setSelected(new Set());
      await loadDetail();
    } catch (err) {
      setError(err?.response?.data?.message || 'Review action failed');
    } finally {
      setBusy('');
    }
  }

  async function finalize() {
    if (!canWrite) return;
    setBusy('finalize');
    setError('');
    try {
      await api.post(`/threat-library/reports/${reportId}/finalize`);
      setFeedback('Report finalized.');
      await loadDetail();
    } catch (err) {
      setError(err?.response?.data?.message || 'Finalize failed');
    } finally {
      setBusy('');
    }
  }

  async function retry() {
    if (!canWrite) return;
    setBusy('retry');
    setError('');
    try {
      await api.post(`/threat-library/reports/${reportId}/retry`);
      setFeedback('Analysis restarted.');
      await loadStatus();
    } catch (err) {
      setError(err?.response?.data?.message || 'Retry failed');
    } finally {
      setBusy('');
    }
  }

  async function exportThib() {
    if (!canWrite) return;
    setBusy('export');
    setError('');
    try {
      const tlp = normalizeTlp(report?.tlp);
      let confirmRed = '';
      if (tlp === 'red') {
        if (!isAdmin) {
          setError('TLP:RED export requires admin.');
          return;
        }
        const ok = window.confirm('This report is TLP:RED. Export deliberately?');
        if (!ok) return;
        confirmRed = '?confirm_red=1';
      }
      const res = await api.get(`/threat-library/reports/${reportId}/export/thib${confirmRed}`, {
        responseType: 'blob'
      });
      const blob = new Blob([res.data], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${String(report?.title || 'report').replace(/[^\w.\-]+/g, '_').slice(0, 80)}.thib.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setFeedback('Bundle downloaded.');
    } catch (err) {
      let message = 'Export failed';
      const data = err?.response?.data;
      if (data instanceof Blob) {
        try {
          const text = await data.text();
          const parsed = JSON.parse(text);
          message = parsed.message || message;
        } catch { /* ignore */ }
      } else if (data?.message) {
        message = data.message;
      }
      setError(message);
    } finally {
      setBusy('');
    }
  }

  async function removeReport() {
    if (!isAdmin) return;
    const ok = window.confirm('Delete this Threat Library report permanently?');
    if (!ok) return;
    setBusy('delete');
    try {
      await api.delete(`/threat-library/reports/${reportId}`);
      navigate('/threat-intelligence/threat-library');
    } catch (err) {
      setError(err?.response?.data?.message || 'Delete failed');
      setBusy('');
    }
  }

  const showReview = report && !processing && ['review_required', 'ready', 'skipped'].includes(String(report.analysis_status || ''));

  return (
    <AppShell>
      <section style={ui.section}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
          <div>
            <Link to="/threat-intelligence/threat-library" style={{ color: '#94a3b8', fontSize: 12, textDecoration: 'none' }}>
              ← Threat Library
            </Link>
            <h1 style={{ ...ui.pageTitle, marginTop: 8 }}>
              {loading ? 'Loading…' : (report?.title || 'Report')}
            </h1>
            {report ? (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', marginTop: 8 }}>
                <TlpBadge tlp={report.tlp} display={report.tlp_display} />
                <span style={badgeStyle({ border: '#334155', bg: '#1e293b', color: '#cbd5e1' })}>
                  {statusLabel(report)}
                </span>
                {report.report_type ? (
                  <span style={{ fontSize: 12, color: '#94a3b8' }}>{report.report_type}</span>
                ) : null}
              </div>
            ) : null}
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {canWrite && report?.analysis_status === 'failed' ? (
              <button type="button" style={ui.btn} disabled={Boolean(busy)} onClick={() => retry().catch(() => {})}>
                Retry analysis
              </button>
            ) : null}
            {canWrite ? (
              <button type="button" style={ui.btn} disabled={Boolean(busy) || !report} onClick={() => exportThib().catch(() => {})}>
                Export THIB
              </button>
            ) : null}
            {isAdmin ? (
              <button type="button" style={ui.btnDanger} disabled={Boolean(busy)} onClick={() => removeReport().catch(() => {})}>
                Delete
              </button>
            ) : null}
          </div>
        </div>

        {isElevatedTlp(report?.tlp) ? (
          <div style={ui.warnBanner}>
            This report is marked {report?.tlp_display || 'with an elevated TLP'}. Limit redistribution and export carefully.
          </div>
        ) : null}

        {error ? <div style={{ ...ui.error, marginBottom: 10 }} role="alert">{error}</div> : null}
        {feedback ? <div style={{ ...ui.infoBanner }}>{feedback}</div> : null}

        {loading ? <div style={ui.muted}>Loading report…</div> : null}
        {!loading && !report ? <div style={ui.muted}>Report not found.</div> : null}

        {report && processing ? (
          <SectionCard title="Processing">
            <p style={{ margin: '0 0 12px', fontSize: 13, color: '#94a3b8' }}>
              Analysis is running. Progress updates every few seconds from the worker — not a fake timer.
            </p>
            <ProgressChecklist report={report} job={job} />
            {report.failure_reason ? (
              <div style={{ ...ui.error, marginTop: 12 }}>{report.failure_reason}</div>
            ) : null}
            {job?.error_message ? (
              <div style={{ ...ui.error, marginTop: 8 }}>{job.error_message}</div>
            ) : null}
          </SectionCard>
        ) : null}

        {report && report.analysis_status === 'failed' && !processing ? (
          <SectionCard title="Processing failed">
            <ProgressChecklist report={report} job={job} />
            <div style={{ ...ui.error, marginTop: 12 }}>
              {report.failure_reason || job?.error_message || 'Analysis failed'}
              {report.failure_stage ? ` (stage: ${report.failure_stage})` : ''}
            </div>
          </SectionCard>
        ) : null}

        {showReview ? (
          <SectionCard
            title="Review indicators"
            actions={canWrite ? (
              <button type="button" style={ui.btnPrimary} disabled={Boolean(busy)} onClick={() => finalize().catch(() => {})}>
                {busy === 'finalize' ? 'Finalizing…' : 'Finalize report'}
              </button>
            ) : null}
          >
            <div style={ui.tabRow}>
              {REVIEW_FILTERS.map((f) => (
                <button key={f.id} type="button" style={ui.tab(filter === f.id)} onClick={() => setFilter(f.id)}>
                  {f.label}
                </button>
              ))}
            </div>

            {canWrite ? (
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
                <button type="button" style={ui.btn} disabled={!selected.size || Boolean(busy)} onClick={() => runReview('approve').catch(() => {})}>
                  Approve
                </button>
                <button type="button" style={ui.btn} disabled={!selected.size || Boolean(busy)} onClick={() => runReview('context_only').catch(() => {})}>
                  Context only
                </button>
                <button type="button" style={ui.btn} disabled={!selected.size || Boolean(busy)} onClick={() => runReview('ignore').catch(() => {})}>
                  Ignore
                </button>
                <button type="button" style={ui.btnPrimary} disabled={!selected.size || Boolean(busy)} onClick={() => runReview('create_iocs').catch(() => {})}>
                  Create IOCs
                </button>
                <button type="button" style={ui.btn} disabled={Boolean(busy)} onClick={() => runReview('approve_high_confidence_malicious').catch(() => {})}>
                  Approve high-confidence malicious
                </button>
              </div>
            ) : null}

            <div style={{ overflowX: 'auto' }}>
              <table width="100%" cellPadding="0" style={{ borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={ui.thead}>
                    {canWrite ? (
                      <th style={ui.th}>
                        <input
                          type="checkbox"
                          checked={filtered.length > 0 && filtered.every((c) => selected.has(c.id))}
                          onChange={toggleAllFiltered}
                          aria-label="Select all filtered"
                        />
                      </th>
                    ) : null}
                    <th style={ui.th}>Type</th>
                    <th style={ui.th}>Value</th>
                    <th style={ui.th}>Assessment</th>
                    <th style={ui.th}>Role</th>
                    <th style={ui.th}>Confidence</th>
                    <th style={ui.th}>Match</th>
                    <th style={ui.th}>Review</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 ? (
                    <tr style={ui.tr}><td colSpan={canWrite ? 8 : 7} style={{ ...ui.td, color: '#94a3b8' }}>No candidates in this filter.</td></tr>
                  ) : filtered.map((c) => (
                    <tr key={c.id || c.public_id} style={ui.tr}>
                      {canWrite ? (
                        <td style={ui.td}>
                          <input
                            type="checkbox"
                            checked={selected.has(c.id)}
                            onChange={() => toggleOne(c.id)}
                            aria-label={`Select candidate ${c.id}`}
                          />
                        </td>
                      ) : null}
                      <td style={ui.td}>{c.candidate_type}</td>
                      <td style={{ ...ui.td, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', wordBreak: 'break-all' }}>
                        {/* Intentionally plain text — do not auto-link potentially malicious values */}
                        {c.normalized_value || c.original_value || '—'}
                      </td>
                      <td style={ui.td}>{c.assessment || '—'}</td>
                      <td style={ui.td}>{c.role || '—'}</td>
                      <td style={ui.td}>
                        {c.confidence == null ? '—' : `${Math.round(Number(c.confidence) * 100)}%`}
                      </td>
                      <td style={ui.td}>
                        {c.matched_ioc_id
                          ? `Matched (${c.matched_ioc_observable_type || c.candidate_type})`
                          : (c.match_state || '—')}
                      </td>
                      <td style={ui.td}>{c.review_status || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SectionCard>
        ) : null}

        {report ? (
          <>
            <SectionCard title="Metadata">
              <div style={{ display: 'grid', gap: 8, gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', fontSize: 13 }}>
                <Meta label="Source type" value={report.source_type} />
                <Meta label="Source name" value={report.source_name} />
                <Meta label="Language" value={report.language} />
                <Meta label="Confidence" value={report.confidence} />
                <Meta label="Published" value={report.published_at ? formatUserDateTime(report.published_at) : null} />
                <Meta label="Imported" value={report.created_at ? formatUserDateTime(report.created_at) : null} />
                <Meta label="Finalized" value={report.finalized_at ? formatUserDateTime(report.finalized_at) : null} />
                <Meta label="Entities" value={report.entity_count} />
                <Meta label="Indicators" value={report.indicator_count} />
                <Meta label="Matched" value={report.matched_count} />
              </div>
            </SectionCard>

            <SectionCard title="Summary">
              <div style={{ fontSize: 14, color: '#cbd5e1', lineHeight: 1.55, whiteSpace: 'pre-wrap' }}>
                {report.summary || 'No summary available yet.'}
              </div>
            </SectionCard>

            <SectionCard title="Entities">
              {entities.length === 0 ? (
                <div style={ui.muted}>No entities extracted.</div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table width="100%" cellPadding="0" style={{ borderCollapse: 'collapse', fontSize: 13 }}>
                    <thead>
                      <tr style={ui.thead}>
                        <th style={ui.th}>Type</th>
                        <th style={ui.th}>Name</th>
                        <th style={ui.th}>Confidence</th>
                        <th style={ui.th}>Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {entities.map((e) => (
                        <tr key={e.id} style={ui.tr}>
                          <td style={ui.td}>{e.entity_type}</td>
                          <td style={ui.td}>{e.name}</td>
                          <td style={ui.td}>{e.confidence == null ? '—' : `${Math.round(Number(e.confidence) * 100)}%`}</td>
                          <td style={{ ...ui.td, color: '#94a3b8', maxWidth: 360 }}>{e.evidence_text || e.description || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </SectionCard>

            <SectionCard title="Indicators">
              <div style={ui.muted}>
                {candidates.length} candidate{candidates.length === 1 ? '' : 's'}
                {showReview ? ' — use the review table above for actions.' : '.'}
              </div>
              {!showReview && candidates.length > 0 ? (
                <ul style={{ margin: '10px 0 0', paddingLeft: 18, color: '#cbd5e1', fontSize: 13 }}>
                  {candidates.slice(0, 25).map((c) => (
                    <li key={c.id || c.public_id} style={{ marginBottom: 4, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace' }}>
                      [{c.candidate_type}] {c.normalized_value || c.original_value}
                    </li>
                  ))}
                </ul>
              ) : null}
            </SectionCard>

            <SectionCard title="Relationships">
              {relationships.length === 0 ? (
                <div style={ui.muted}>No relationships recorded.</div>
              ) : (
                <ul style={{ margin: 0, paddingLeft: 18, color: '#cbd5e1', fontSize: 13, lineHeight: 1.5 }}>
                  {relationships.map((rel) => (
                    <li key={rel.id || `${rel.relationship_type}-${rel.subject_entity_id}-${rel.object_candidate_id}`}>
                      {rel.relationship_type || 'related'}
                      {rel.confidence != null ? ` (${Math.round(Number(rel.confidence) * 100)}%)` : ''}
                    </li>
                  ))}
                </ul>
              )}
            </SectionCard>

            <SectionCard title="Source">
              <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
                <Meta label="Source URL" value={report.source_url} asSafeUrl />
                <Meta label="File name" value={report.source_file_name} />
                <Meta label="SHA-256" value={report.source_sha256} mono />
                {documentMeta ? (
                  <Meta
                    label="Document"
                    value={`${documentMeta.title || 'Untitled'} · ${documentMeta.block_count || 0} blocks`}
                  />
                ) : null}
                {artifacts?.length ? (
                  <div>
                    <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 4 }}>Artifacts</div>
                    <ul style={{ margin: 0, paddingLeft: 18, color: '#cbd5e1' }}>
                      {artifacts.map((a) => (
                        <li key={a.id || a.storage_key}>
                          {a.artifact_type}: {a.file_name || a.storage_key}
                          {a.size_bytes != null ? ` (${a.size_bytes} bytes)` : ''}
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </div>
            </SectionCard>
          </>
        ) : null}
      </section>
    </AppShell>
  );
}

function Meta({ label, value, mono, asSafeUrl }) {
  return (
    <div>
      <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 2 }}>{label}</div>
      {asSafeUrl && value ? (
        <a
          href={String(value)}
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: '#5eead4', wordBreak: 'break-all' }}
        >
          {String(value)}
        </a>
      ) : (
        <div style={{
          color: '#e2e8f0',
          wordBreak: 'break-all',
          fontFamily: mono ? 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace' : undefined
        }}
        >
          {value == null || value === '' ? '—' : String(value)}
        </div>
      )}
    </div>
  );
}
