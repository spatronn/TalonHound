import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api.js';
import { formatUserDateTime } from '../lib/formatDate.js';
import { buildUrlscanView } from '../lib/urlscanScanView.js';

const MONO = 'ui-monospace, SFMono-Regular, Menlo, monospace';

const CLASSIFICATION_STYLE = {
  malicious: { border: '#7f1d1d', bg: '#450a0a', color: '#fca5a5' },
  benign: { border: '#334155', bg: '#0b1220', color: '#cbd5e1' },
  unclassified: { border: '#475569', bg: '#0b1220', color: '#e2e8f0' },
  unknown: { border: '#475569', bg: '#0b1220', color: '#94a3b8' }
};

const sectionLabelStyle = {
  fontSize: 11,
  fontWeight: 700,
  letterSpacing: 0.4,
  textTransform: 'uppercase',
  color: '#94a3b8',
  margin: '14px 0 6px'
};

const kvGridStyle = {
  display: 'grid',
  gridTemplateColumns: 'minmax(96px, 36%) minmax(0, 1fr)',
  columnGap: 10,
  rowGap: 4,
  fontSize: 13
};

const toggleStyle = { marginTop: 8, fontSize: 12 };

function CopyValue({ value }) {
  const [copied, setCopied] = useState(false);
  if (!value || !navigator?.clipboard?.writeText) return null;
  return (
    <button
      type="button"
      title="Copy value"
      aria-label={`Copy ${value}`}
      onClick={() => {
        navigator.clipboard.writeText(String(value))
          .then(() => { setCopied(true); setTimeout(() => setCopied(false), 1200); })
          .catch(() => {});
      }}
      style={{ marginLeft: 6, minHeight: 0, padding: '1px 6px', borderRadius: 4, fontSize: 11, fontWeight: 500, lineHeight: '16px', verticalAlign: 'baseline' }}
    >
      {copied ? 'Copied' : 'Copy'}
    </button>
  );
}

function KeyValueRows({ rows }) {
  if (!rows?.length) return null;
  return (
    <div style={kvGridStyle}>
      {rows.map((row) => (
        <React.Fragment key={row.label}>
          <div style={{ color: '#94a3b8' }}>{row.label}</div>
          <div style={{
            color: row.tone === 'caution' ? '#fde68a' : '#e2e8f0',
            minWidth: 0,
            overflowWrap: 'anywhere',
            fontFamily: row.mono ? MONO : undefined,
            fontSize: row.mono ? 12 : undefined
          }}
          >
            {row.date ? formatUserDateTime(row.value) : row.value}
            {row.copy ? <CopyValue value={row.value} /> : null}
          </div>
        </React.Fragment>
      ))}
    </div>
  );
}

function assessmentStyle(assessment) {
  switch (assessment) {
    case 'malicious_evidence':
      return { border: '#7f1d1d', bg: '#450a0a', color: '#fca5a5' };
    case 'no_malicious_evidence':
      return { border: '#334155', bg: '#0b1220', color: '#cbd5e1' };
    case 'no_results':
      return { border: '#475569', bg: '#0b1220', color: '#94a3b8' };
    case 'insufficient_evidence':
      return { border: '#854d0e', bg: '#422006', color: '#fde68a' };
    case 'privacy_restricted':
      return { border: '#6b21a8', bg: '#3b0764', color: '#e9d5ff' };
    case 'rate_limited':
    case 'error':
      return { border: '#9a3412', bg: '#431407', color: '#fdba74' };
    default:
      return { border: '#334155', bg: '#0b1220', color: '#94a3b8' };
  }
}

export default function UrlscanEnrichmentCard({
  iocId,
  active = true,
  canRefresh = true,
  isAdmin = false,
  compact = false,
  onSnapshot
}) {
  const [state, setState] = useState({ status: 'loading', data: null, message: '' });
  const [refreshing, setRefreshing] = useState(false);
  const [showScans, setShowScans] = useState(false);
  const [showRelated, setShowRelated] = useState(false);

  const applyPayload = useCallback((data) => {
    const status = String(data?.provider_status || data?.status || 'not_run').toLowerCase();
    const assessment = data?.evidence_assessment || data?.summary?.evidence_assessment || null;
    if (status === 'not_configured' || status === 'api_key_missing') {
      setState({ status: 'not_configured', data, message: data?.message || 'urlscan.io API key is not configured' });
      return;
    }
    if (status === 'disabled') {
      setState({ status: 'disabled', data, message: 'urlscan.io provider is disabled' });
      return;
    }
    if (status === 'not_run' || (status === 'not_found' && !data?.summary && !data?.enriched)) {
      // Distinguish "never run" (no summary) from "ran, no results" (summary with no_results).
      if (!data?.summary) {
        setState({ status: 'not_run', data, message: data?.message || 'No urlscan data yet' });
        return;
      }
    }
    if (status === 'rate_limited') {
      setState({ status: 'rate_limited', data, message: data?.message || 'urlscan.io rate limit reached' });
      return;
    }
    if (status === 'error' || status === 'failed' || status === 'auth_error') {
      setState({ status: 'error', data, message: data?.error_message || data?.message || 'urlscan.io enrichment failed' });
      return;
    }
    if (status === 'skipped' || assessment === 'privacy_restricted') {
      setState({
        status: 'privacy_restricted',
        data,
        message: data?.error_message || data?.message || 'Lookup skipped for privacy'
      });
      return;
    }
    if (status === 'unsupported' || status === 'unsupported_private_ip') {
      setState({ status: 'unsupported', data, message: data?.message || 'Unsupported for urlscan enrichment' });
      return;
    }
    setState({
      status: assessment === 'no_results' || status === 'not_found' ? 'no_results' : 'success',
      data,
      message: ''
    });
  }, []);

  const load = useCallback(async () => {
    if (!iocId || !active) return;
    setState((s) => ({ ...s, status: 'loading' }));
    try {
      const { data } = await api.get(`/ioc/${iocId}/enrichments/urlscan`);
      applyPayload(data);
    } catch (err) {
      setState({
        status: 'error',
        data: err?.response?.data || null,
        message: err?.response?.data?.message || 'Failed to load urlscan enrichment'
      });
    }
  }, [iocId, active, applyPayload]);

  useEffect(() => {
    if (!active) return;
    load().catch(() => {});
  }, [load, active]);

  async function refresh(force = false) {
    if (!canRefresh) return;
    if (force && !isAdmin) return;
    setRefreshing(true);
    try {
      const { data } = await api.post(`/ioc/${iocId}/enrichments/urlscan/refresh`, { force });
      applyPayload(data);
    } catch (err) {
      const body = err?.response?.data || {};
      const status = err?.response?.status;
      if (status === 429) {
        setState({ status: 'rate_limited', data: body, message: body.message || 'urlscan.io rate limit reached' });
      } else if (status === 409 && body.provider_status === 'not_configured') {
        setState({ status: 'not_configured', data: body, message: body.message || 'urlscan.io API key is not configured' });
      } else if (status === 409) {
        setState({ status: 'disabled', data: body, message: body.message || 'urlscan.io provider is disabled' });
      } else {
        setState({
          status: 'error',
          data: body,
          message: body.message || body.error || 'urlscan.io enrichment failed'
        });
      }
    } finally {
      setRefreshing(false);
    }
  }

  const summary = state.data?.summary || null;
  const assessment = summary?.evidence_assessment || state.data?.evidence_assessment || null;
  const assessmentLabel = summary?.evidence_assessment_label
    || state.data?.evidence_assessment_label
    || null;
  const view = useMemo(() => buildUrlscanView(summary), [summary]);

  useEffect(() => {
    if (!onSnapshot) return;
    onSnapshot({
      status: state.status,
      assessment,
      hasResult: Boolean(summary),
      found: assessment === 'no_results' ? false : Boolean(summary),
      matches_retrieved: summary?.matches_retrieved ?? null,
      malicious_scan_count: summary?.malicious_scan_count ?? null,
      fetched_at: state.data?.fetched_at || summary?.fetched_at || null
    });
  }, [onSnapshot, state.status, state.data, summary, assessment]);

  const cardShellStyle = compact
    ? { marginBottom: 0, padding: 12, border: '1px solid #334155', borderRadius: 10, background: '#0b1220' }
    : { marginBottom: 14, padding: 14, border: '1px solid #334155', borderRadius: 12, background: '#0f172a' };

  const header = (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
      <div style={{ fontWeight: 700, color: '#e2e8f0' }}>
        urlscan.io
        <span style={{
          marginLeft: 8,
          border: '1px solid #1d4ed8',
          color: '#93c5fd',
          borderRadius: 999,
          padding: '2px 8px',
          fontSize: 11
        }}
        >
          Web / URL Intelligence
        </span>
        <span style={{
          marginLeft: 6,
          border: '1px solid #475569',
          color: '#94a3b8',
          borderRadius: 999,
          padding: '2px 8px',
          fontSize: 11
        }}
        >
          Passive
        </span>
      </div>
      {canRefresh ? (
        <button type="button" onClick={() => refresh(false).catch(() => {})} disabled={refreshing || state.status === 'loading'}>
          {refreshing ? 'Refreshing…' : 'Refresh'}
        </button>
      ) : null}
    </div>
  );

  if (state.status === 'loading') {
    return (
      <div style={cardShellStyle}>
        <span style={{ color: '#94a3b8', fontSize: 13 }}>Loading urlscan enrichment...</span>
      </div>
    );
  }

  if (state.status === 'not_configured') {
    return (
      <div style={cardShellStyle}>
        {header}
        <div style={{ color: '#fcd34d', fontSize: 13, marginTop: 8 }}>urlscan.io API key is not configured</div>
      </div>
    );
  }

  if (state.status === 'disabled') {
    return (
      <div style={cardShellStyle}>
        {header}
        <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 8 }}>urlscan.io provider is disabled</div>
      </div>
    );
  }

  if (state.status === 'not_run') {
    return (
      <div style={cardShellStyle}>
        {header}
        <div style={{ color: '#cbd5e1', fontSize: 13, marginTop: 8 }}>No urlscan data yet for this observable</div>
      </div>
    );
  }

  if (state.status === 'unsupported') {
    return (
      <div style={cardShellStyle}>
        {header}
        <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 8 }}>{state.message}</div>
      </div>
    );
  }

  if (state.status === 'privacy_restricted') {
    return (
      <div style={cardShellStyle}>
        {header}
        <div style={{ color: '#e9d5ff', fontSize: 13, marginTop: 8 }}>{state.message}</div>
        <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>
          Sensitive URL components were not stripped to force a lookup.
        </div>
      </div>
    );
  }

  if (state.status === 'rate_limited' || state.status === 'error') {
    return (
      <div style={cardShellStyle}>
        {header}
        <div style={{ color: '#fdba74', fontSize: 13, marginTop: 8 }}>{state.message}</div>
      </div>
    );
  }

  const style = assessmentStyle(assessment);

  if (state.status === 'no_results' || !view) {
    return (
      <div style={cardShellStyle}>
        {header}
        <div style={{
          marginTop: 10,
          border: `1px solid ${style.border}`,
          background: style.bg,
          color: style.color,
          borderRadius: 8,
          padding: '8px 10px',
          fontSize: 13,
          fontWeight: 600
        }}
        >
          {assessmentLabel || 'No results'}
        </div>
        <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 8 }}>
          No historical scans were found in the configured lookback window. This is not a clean or safe verdict.
        </div>
        {summary?.fetched_at ? (
          <div style={{ color: '#64748b', fontSize: 11, marginTop: 10 }}>
            Evidence refreshed: {formatUserDateTime(summary.fetched_at)}
          </div>
        ) : null}
      </div>
    );
  }

  const cls = CLASSIFICATION_STYLE[view.classification.state] || CLASSIFICATION_STYLE.unknown;
  const history = view.history;
  const visibleHistory = showScans ? history.rows : history.rows.slice(0, 3);

  return (
    <div style={cardShellStyle}>
      {header}

      {/* Section 1 — Assessment (provider evidence, never a TalonHound verdict) */}
      <div style={{
        marginTop: 10,
        border: `1px solid ${cls.border}`,
        background: cls.bg,
        borderRadius: 8,
        padding: '8px 10px'
      }}
      >
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ color: '#94a3b8', fontSize: 12 }}>urlscan classification</span>
          <span style={{ color: cls.color, fontSize: 14, fontWeight: 700 }}>{view.classification.label}</span>
          {view.classification.score !== null ? (
            <span style={{ color: '#94a3b8', fontSize: 12 }} title="urlscan scale −100 (legitimate) … 100 (malicious). Not a probability and not TalonHound confidence.">
              score {view.classification.score}
            </span>
          ) : null}
        </div>
        {view.classification.categories.length || view.classification.brands.length ? (
          <div style={{ color: '#cbd5e1', fontSize: 12, marginTop: 4, overflowWrap: 'anywhere' }}>
            {view.classification.categories.length ? <>Categories: {view.classification.categories.join(', ')}</> : null}
            {view.classification.categories.length && view.classification.brands.length ? ' · ' : null}
            {view.classification.brands.length ? <>Targeted brands: {view.classification.brands.join(', ')}</> : null}
          </div>
        ) : null}
        {view.verdictSources.length ? (
          <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4, overflowWrap: 'anywhere' }}>
            {view.verdictSources.map((v, i) => (
              <span key={v.source}>
                {i ? ' · ' : ''}
                {v.source}: <span style={{ color: v.caution ? '#fde68a' : '#cbd5e1' }}>{v.value}</span>
              </span>
            ))}
          </div>
        ) : null}
        <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>
          Sample assessment: <span style={{ color: style.color }}>{assessmentLabel || '—'}</span>
          {' · '}
          {view.counts.retrieved} scan{view.counts.retrieved === 1 ? '' : 's'} retrieved
          {view.counts.bounded ? ' (bounded sample)' : ''}
          {' · '}
          {view.counts.exact} exact / {view.counts.related} related
          {' · '}
          {view.counts.malicious} malicious
        </div>
      </div>

      {view.observations.length ? (
        <ul style={{ listStyle: 'none', margin: '8px 0 0', padding: 0, display: 'grid', gap: 6 }}>
          {view.observations.map((o) => (
            <li
              key={o.code}
              style={{
                borderLeft: `3px solid ${o.level === 'caution' ? '#ca8a04' : '#475569'}`,
                padding: '2px 0 2px 8px',
                fontSize: 12
              }}
            >
              <div style={{ color: o.level === 'caution' ? '#fde68a' : '#cbd5e1', fontWeight: 600 }}>{o.label}</div>
              {o.detail ? <div style={{ color: '#94a3b8', overflowWrap: 'anywhere' }}>{o.detail}</div> : null}
            </li>
          ))}
        </ul>
      ) : null}

      {view.needsRefreshForDetail ? (
        <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 8 }}>
          Stored before detailed scan parsing. Use Refresh to load the scan verdict, network activity, TLS and related observables.
        </div>
      ) : null}

      <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 8, overflowWrap: 'anywhere' }}>
        {view.primaryScan.scanned_at ? <>Scan: <span style={{ color: '#cbd5e1' }}>{formatUserDateTime(view.primaryScan.scanned_at)}</span></> : null}
        {view.primaryScan.relation ? <> · {view.primaryScan.relation}{view.primaryScan.exact ? ' (exact)' : ''}</> : null}
        {view.primaryScan.href ? (
          <>
            {' · '}
            <a href={view.primaryScan.href} target="_blank" rel="noopener noreferrer" style={{ color: '#93c5fd' }}>
              Open urlscan result
            </a>
          </>
        ) : null}
      </div>

      {/* Section 2 — Page & Hosting */}
      {view.pageRows.length || view.hostingRows.length ? (
        <>
          <div style={sectionLabelStyle}>Page &amp; hosting</div>
          <KeyValueRows rows={[...view.pageRows, ...view.hostingRows]} />
        </>
      ) : null}

      {/* Section 3 — Network activity (aggregates only) */}
      {view.networkStats.length ? (
        <>
          <div style={sectionLabelStyle}>Network activity</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(92px, 1fr))', gap: 6 }}>
            {view.networkStats.map((s) => (
              <div key={s.label} style={{ border: '1px solid #1e293b', borderRadius: 6, padding: '4px 8px', background: '#0f172a' }}>
                <div style={{ fontSize: 15, fontWeight: 700, color: s.tone === 'caution' ? '#fde68a' : '#e2e8f0' }}>{s.value}</div>
                <div style={{ fontSize: 11, color: '#94a3b8' }}>{s.label}</div>
              </div>
            ))}
          </div>
          {view.statusCodes.length || view.resourceTypes.length || view.failedErrors.length ? (
            <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 6, display: 'grid', gap: 2, overflowWrap: 'anywhere' }}>
              {view.statusCodes.length ? <div>Response codes: <span style={{ color: '#cbd5e1' }}>{view.statusCodes.join(' · ')}</span></div> : null}
              {view.resourceTypes.length ? <div>Resource types: <span style={{ color: '#cbd5e1' }}>{view.resourceTypes.join(' · ')}</span></div> : null}
              {view.failedErrors.length ? <div>Failed loads: <span style={{ color: '#fde68a' }}>{view.failedErrors.join(' · ')}</span></div> : null}
            </div>
          ) : null}
          {view.redirects.length ? (
            <ol style={{ margin: '6px 0 0', paddingLeft: 18, color: '#cbd5e1', fontSize: 12, fontFamily: MONO }}>
              {view.redirects.map((r, i) => (
                <li key={`${r.from}-${i}`} style={{ overflowWrap: 'anywhere', marginBottom: 2 }}>
                  {r.status ? <span style={{ color: '#94a3b8' }}>{r.status} </span> : null}
                  {r.from} <span style={{ color: '#94a3b8' }}>→</span> {r.to}
                </li>
              ))}
            </ol>
          ) : null}
        </>
      ) : null}

      {/* Section 4 — TLS / Technologies (omitted when the scan has none) */}
      {view.tlsRows.length ? (
        <>
          <div style={sectionLabelStyle}>TLS certificate</div>
          <KeyValueRows rows={view.tlsRows} />
        </>
      ) : null}
      {view.technologies.length ? (
        <>
          <div style={sectionLabelStyle}>Detected technologies</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {view.technologies.map((t) => (
              <span
                key={t.name}
                title={t.categories.join(', ') || undefined}
                style={{ border: '1px solid #334155', borderRadius: 999, padding: '1px 8px', fontSize: 12, color: '#cbd5e1' }}
              >
                {t.name}
              </span>
            ))}
          </div>
        </>
      ) : null}

      {/* Section 5 — Related observables (evidence only; never auto-created or enriched) */}
      {view.related.length ? (
        <>
          <div style={sectionLabelStyle}>Related observables ({view.related.length})</div>
          <button type="button" onClick={() => setShowRelated((v) => !v)} style={{ ...toggleStyle, marginTop: 0 }}>
            {showRelated ? 'Hide related observables' : 'Show related observables'}
          </button>
          {showRelated ? (
            <>
              <ul style={{ listStyle: 'none', margin: '8px 0 0', padding: 0, display: 'grid', gap: 6 }}>
                {view.related.map((r) => (
                  <li key={`${r.type}|${r.value}`} style={{ borderTop: '1px solid #1e293b', paddingTop: 6, fontSize: 12 }}>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'baseline', flexWrap: 'wrap' }}>
                      <span style={{ border: '1px solid #334155', borderRadius: 4, padding: '0 5px', fontSize: 10, color: '#94a3b8', textTransform: 'uppercase' }}>{r.type}</span>
                      <span style={{ color: '#e2e8f0', fontFamily: MONO, overflowWrap: 'anywhere', minWidth: 0 }}>{r.value}</span>
                      <CopyValue value={r.value} />
                    </div>
                    <div style={{ color: '#94a3b8', marginTop: 2, overflowWrap: 'anywhere' }}>
                      {r.relationship}
                      {r.role ? ` · ${r.role}` : ''}
                      {r.note ? ` · ${r.note}` : ''}
                      {r.origin ? <span style={{ color: '#64748b' }}> · {r.origin}</span> : null}
                    </div>
                  </li>
                ))}
              </ul>
              <div style={{ color: '#64748b', fontSize: 11, marginTop: 6 }}>
                Observed in this scan only. Not added to TalonHound and not enriched automatically.
                {view.hashTotal !== null && view.hashTotal > view.related.filter((r) => r.type === 'sha256').length
                  ? ` ${view.hashTotal} response-body hashes in the scan; largest shown.`
                  : ''}
              </div>
            </>
          ) : null}
        </>
      ) : null}

      {/* Section 6 — Historical results (bounded to the retrieved search sample) */}
      {history.rows.length ? (
        <>
          <div style={sectionLabelStyle}>Scan history</div>
          {history.changes.length ? (
            <div style={{ display: 'grid', gap: 2, fontSize: 12, marginBottom: 6 }}>
              {history.changes.map((c) => (
                <div key={c.label} style={{ color: '#fde68a', overflowWrap: 'anywhere' }}>
                  {c.label} changed: <span style={{ color: '#cbd5e1' }}>{c.values.join(' · ')}</span>
                </div>
              ))}
            </div>
          ) : history.compared !== null && history.compared > 1 ? (
            <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 6 }}>
              No IP, ASN, title, status or TLS-issuer change across {history.compared} directly matching scans.
            </div>
          ) : null}
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 6 }}>
            {visibleHistory.map((row) => (
              <li key={row.scan_id} style={{ borderTop: '1px solid #1e293b', paddingTop: 6, fontSize: 12, color: '#cbd5e1', overflowWrap: 'anywhere' }}>
                <div>
                  {row.scanned_at ? formatUserDateTime(row.scanned_at) : 'Unknown date'}
                  {row.relation ? <span style={{ color: '#94a3b8' }}> · {row.relation}</span> : null}
                  {' · '}
                  <span style={{ color: row.malicious ? '#fca5a5' : '#94a3b8' }}>{row.verdict}</span>
                  {row.href ? (
                    <>
                      {' · '}
                      <a href={row.href} target="_blank" rel="noopener noreferrer" style={{ color: '#93c5fd' }}>result</a>
                    </>
                  ) : null}
                </div>
                <div style={{ color: '#94a3b8' }}>
                  {[row.status ? `HTTP ${row.status}` : null, row.title ? `“${row.title}”` : null, row.ip, row.asn].filter(Boolean).join(' · ') || '—'}
                </div>
              </li>
            ))}
          </ul>
          {history.rows.length > 3 ? (
            <button type="button" onClick={() => setShowScans((v) => !v)} style={toggleStyle}>
              {showScans ? 'Show fewer scans' : `Show all ${history.rows.length} retrieved scans`}
            </button>
          ) : null}
          <div style={{ color: '#64748b', fontSize: 11, marginTop: 6 }}>
            {history.retrieved} of {history.total ?? history.retrieved} scan{(history.total ?? history.retrieved) === 1 ? '' : 's'} in the lookback window retrieved
            {history.bounded ? ' (bounded sample — not a complete history)' : ''}.
            {' '}Verdicts are only retrieved for the top detailed scans.
          </div>
        </>
      ) : null}

      {view.fetchedAt ? (
        <div style={{ color: '#64748b', fontSize: 11, marginTop: 10 }}>
          Evidence refreshed: {formatUserDateTime(view.fetchedAt)}
        </div>
      ) : null}
    </div>
  );
}
