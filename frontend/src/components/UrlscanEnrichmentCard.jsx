import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

const RELATION_LABELS = {
  exact_url: 'Exact URL',
  canonical_url: 'Canonical URL',
  page_hostname: 'Page hostname',
  task_hostname: 'Task hostname',
  page_apex: 'Page apex domain',
  subdomain_of_ioc: 'Subdomain of IOC',
  ioc_subdomain_of_page: 'IOC is subdomain of page',
  contacted_domain: 'Contacted domain',
  primary_page_ip: 'Primary page IP',
  contacted_ip: 'Contacted IP (related)',
  related: 'Related'
};

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

function isOfficialResultUrl(href) {
  try {
    const u = new URL(String(href || ''));
    return u.protocol === 'https:'
      && u.hostname === 'urlscan.io'
      && /^\/result\/[0-9a-f-]{36}\/?$/i.test(u.pathname);
  } catch {
    return false;
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
  const scans = Array.isArray(summary?.scans) ? summary.scans : [];
  const latest = summary?.most_recent_scan || scans[0] || null;
  const resultHref = latest?.result_url && isOfficialResultUrl(latest.result_url) ? latest.result_url : null;

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
        {assessmentLabel || (state.status === 'no_results' ? 'No results' : 'Evidence available')}
      </div>
      {state.status === 'no_results' ? (
        <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 8 }}>
          No historical scans were found in the configured lookback window. This is not a clean or safe verdict.
        </div>
      ) : (
        <div style={{ display: 'grid', gap: 6, marginTop: 10, fontSize: 13, color: '#cbd5e1' }}>
          <div>
            <span style={{ color: '#94a3b8' }}>{summary?.matches_retrieved_label || 'Matches retrieved'}: </span>
            <b>{summary?.matches_retrieved ?? 0}</b>
            {summary?.results_are_exhaustive === false ? (
              <span style={{ color: '#64748b', marginLeft: 6 }}>(bounded sample)</span>
            ) : null}
          </div>
          <div>
            <span style={{ color: '#94a3b8' }}>Exact / related: </span>
            <b>{summary?.exact_match_count ?? 0}</b>
            <span style={{ color: '#64748b' }}> / </span>
            <b>{summary?.related_match_count ?? 0}</b>
          </div>
          <div>
            <span style={{ color: '#94a3b8' }}>Malicious scans (in sample): </span>
            <b>{summary?.malicious_scan_count ?? 0}</b>
          </div>
          {latest?.scanned_at ? (
            <div>
              <span style={{ color: '#94a3b8' }}>Latest scan: </span>
              <b style={{ wordBreak: 'break-all' }}>{latest.scanned_at}</b>
            </div>
          ) : null}
          {latest?.urlscan_score != null ? (
            <div>
              <span style={{ color: '#94a3b8' }}>urlscan score: </span>
              <b>{latest.urlscan_score}</b>
              <span style={{ color: '#64748b', marginLeft: 6 }}>(not TalonHound confidence)</span>
            </div>
          ) : null}
          {Array.isArray(latest?.categories) && latest.categories.length ? (
            <div>
              <span style={{ color: '#94a3b8' }}>Categories: </span>
              {latest.categories.join(', ')}
            </div>
          ) : null}
          {latest?.match_relation ? (
            <div>
              <span style={{ color: '#94a3b8' }}>Latest match: </span>
              {RELATION_LABELS[latest.match_relation] || latest.match_relation}
              {latest.exact_match ? ' (exact)' : ''}
            </div>
          ) : null}
          {resultHref ? (
            <div>
              <a href={resultHref} target="_blank" rel="noopener noreferrer" style={{ color: '#93c5fd' }}>
                Open latest urlscan result
              </a>
            </div>
          ) : null}
          {scans.length > 1 ? (
            <div>
              <button type="button" onClick={() => setShowScans((v) => !v)} style={{ marginTop: 4 }}>
                {showScans ? 'Hide scan list' : `Show ${scans.length} scans`}
              </button>
              {showScans ? (
                <ul style={{ margin: '8px 0 0', paddingLeft: 18, color: '#94a3b8', fontSize: 12 }}>
                  {scans.slice(0, 20).map((scan) => {
                    const href = isOfficialResultUrl(scan.result_url) ? scan.result_url : null;
                    return (
                      <li key={scan.scan_id} style={{ marginBottom: 4, wordBreak: 'break-word' }}>
                        {scan.scanned_at || 'unknown date'}
                        {' · '}
                        {RELATION_LABELS[scan.match_relation] || scan.match_relation}
                        {scan.malicious === true ? ' · malicious evidence' : ''}
                        {href ? (
                          <>
                            {' · '}
                            <a href={href} target="_blank" rel="noopener noreferrer" style={{ color: '#93c5fd' }}>result</a>
                          </>
                        ) : null}
                      </li>
                    );
                  })}
                </ul>
              ) : null}
            </div>
          ) : null}
        </div>
      )}
      {summary?.fetched_at ? (
        <div style={{ color: '#64748b', fontSize: 11, marginTop: 10 }}>
          Evidence refreshed: {summary.fetched_at}
        </div>
      ) : null}
    </div>
  );
}
