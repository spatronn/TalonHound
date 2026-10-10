import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api.js';
import { formatUserDateTime } from '../lib/formatDate.js';
import { buttonClassName } from '../lib/uiButtons.js';
import {
  buildUrlscanView,
  urlscanPayloadState,
  urlscanRefreshErrorState
} from '../lib/urlscanScanView.js';
import { IocDetailIcons } from './iocDetails/IocDetailIcons.jsx';
import UrlscanIntelligenceBody from './urlscan/UrlscanIntelligenceBody.jsx';

const badgeStyle = {
  border: '1px solid #475569',
  color: '#94a3b8',
  borderRadius: 999,
  padding: '1px 8px',
  fontSize: 11,
  fontWeight: 500,
  whiteSpace: 'nowrap'
};

/** Message shown for every non-result provider state. */
const STATE_MESSAGE_COLOR = {
  not_configured: '#fcd34d',
  disabled: '#94a3b8',
  not_run: '#cbd5e1',
  unsupported: '#94a3b8',
  privacy_restricted: '#e9d5ff',
  rate_limited: '#fdba74',
  error: '#fdba74'
};

export function UrlscanCardHeader({ canRefresh, refreshing, disabled, reportHref, onRefresh }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', minWidth: 0 }}>
        <span style={{ fontWeight: 700, color: '#e2e8f0', fontSize: 15, marginRight: 2 }}>urlscan.io</span>
        <span style={{ ...badgeStyle, borderColor: '#1d4ed8', color: '#93c5fd' }}>Web / URL Intelligence</span>
        <span style={badgeStyle}>Passive</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        {reportHref ? (
          <a
            href={reportHref}
            target="_blank"
            rel="noopener noreferrer"
            className={buttonClassName({ variant: 'ghost', size: 'sm' })}
            // a.th-btn outranks the compact size class; match the Refresh button.
            style={{ minHeight: 30, padding: '5px 10px', fontSize: 12 }}
            aria-label="Open the urlscan.io report for this scan (opens in a new tab)"
          >
            Report <IocDetailIcons.external size={13} />
          </a>
        ) : null}
        {canRefresh ? (
          <button
            type="button"
            className={buttonClassName({ variant: 'secondary', size: 'sm' })}
            onClick={onRefresh}
            disabled={disabled}
            aria-busy={refreshing || undefined}
          >
            <IocDetailIcons.refresh size={13} />
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        ) : null}
      </div>
    </div>
  );
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

  const applyPayload = useCallback((data) => {
    setState({ ...urlscanPayloadState(data), data });
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
      setState({ ...urlscanRefreshErrorState(err?.response?.status, body), data: body });
    } finally {
      setRefreshing(false);
    }
  }

  const summary = state.data?.summary || null;
  const assessment = summary?.evidence_assessment || state.data?.evidence_assessment || null;
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
    ? { marginBottom: 0, padding: 14, border: '1px solid #334155', borderRadius: 10, background: '#0b1220', minWidth: 0 }
    : { marginBottom: 14, padding: 16, border: '1px solid #334155', borderRadius: 12, background: '#0f172a', minWidth: 0 };

  if (state.status === 'loading') {
    return (
      <div style={cardShellStyle} aria-busy="true">
        <span style={{ color: '#94a3b8', fontSize: 13 }}>Loading urlscan enrichment...</span>
      </div>
    );
  }

  const showResult = state.status === 'success' && view;
  const header = (
    <UrlscanCardHeader
      canRefresh={canRefresh}
      refreshing={refreshing}
      disabled={refreshing}
      reportHref={showResult ? view.primaryScan.href : null}
      onRefresh={() => refresh(false).catch(() => {})}
    />
  );

  if (STATE_MESSAGE_COLOR[state.status]) {
    const message = {
      not_configured: 'urlscan.io API key is not configured',
      disabled: 'urlscan.io provider is disabled',
      not_run: 'No urlscan data yet for this observable'
    }[state.status] || state.message;
    return (
      <div style={cardShellStyle}>
        {header}
        <div role={state.status === 'error' || state.status === 'rate_limited' ? 'alert' : undefined} style={{ color: STATE_MESSAGE_COLOR[state.status], fontSize: 13, marginTop: 10 }}>
          {message}
        </div>
        {state.status === 'privacy_restricted' ? (
          <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>
            Sensitive URL components were not stripped to force a lookup.
          </div>
        ) : null}
      </div>
    );
  }

  if (!showResult) {
    return (
      <div style={cardShellStyle}>
        {header}
        <div style={{ marginTop: 12, padding: '10px 12px', border: '1px solid #334155', borderRadius: 10, background: '#0f172a' }}>
          <div style={{ color: '#cbd5e1', fontSize: 14, fontWeight: 600 }}>
            {summary?.evidence_assessment_label || 'No results'}
          </div>
          <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>
            No historical scans were found in the configured lookback window. This is not a clean or safe verdict.
          </div>
        </div>
        {summary?.fetched_at ? (
          <div style={{ color: '#64748b', fontSize: 11, marginTop: 10 }}>
            Evidence refreshed: {formatUserDateTime(summary.fetched_at)}
          </div>
        ) : null}
      </div>
    );
  }

  return (
    <div style={cardShellStyle}>
      {header}
      <UrlscanIntelligenceBody view={view} />
      {view.fetchedAt ? (
        <div style={{ color: '#64748b', fontSize: 11, marginTop: 10 }}>
          Evidence refreshed: {formatUserDateTime(view.fetchedAt)}
        </div>
      ) : null}
    </div>
  );
}
