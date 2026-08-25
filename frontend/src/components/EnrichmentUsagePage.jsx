import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../lib/api.js';
import { getSystemTimezone } from '../lib/formatDate.js';
import {
  DEFAULT_RANGE,
  RANGE_OPTIONS,
  IOC_TYPE_OPTIONS,
  TREND_SERIES,
  formatNumber,
  formatPercent,
  formatMs,
  formatDateLabel,
  mergeSeries,
  computeChartGeometry,
  summaryCards,
  hasAnyUsage,
  sortProviderRows,
  quotaView,
  providerFilterOptions,
  todayInTimeZone,
  daysAgoInTimeZone
} from '../lib/enrichmentUsage.js';
import './enrichmentUsage.css';

const CHART_W = 720;
const CHART_H = 260;
const CHART_PAD = { top: 16, right: 16, bottom: 28, left: 48 };

export default function EnrichmentUsagePage({ AppShell }) {
  // Read-only page: RBAC is enforced server-side (GET allowed for every role) and the
  // route is wrapped in <Protected>, so no session gating is needed here.
  const [searchParams, setSearchParams] = useSearchParams();

  // "Today" for the custom pickers is the canonical System Timezone (same anchor the
  // backend uses via CURRENT_DATE), never the browser's local tz.
  const systemTz = getSystemTimezone();
  const systemToday = todayInTimeZone(systemTz);

  const [range, setRange] = useState(DEFAULT_RANGE);
  const [customFrom, setCustomFrom] = useState(() => daysAgoInTimeZone(systemTz, 29));
  const [customTo, setCustomTo] = useState(() => todayInTimeZone(systemTz));
  const [provider, setProvider] = useState(searchParams.get('provider') || '');
  const [iocType, setIocType] = useState('');

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeSeries, setActiveSeries] = useState(() => new Set(TREND_SERIES.map((s) => s.key)));
  const [sort, setSort] = useState({ key: 'external_call_count', dir: 'desc' });
  const [hoverIdx, setHoverIdx] = useState(null);
  const chartRef = useRef(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = { range };
      if (range === 'custom') { params.from = customFrom; params.to = customTo; }
      if (provider) params.provider = provider;
      if (iocType) params.iocType = iocType;
      const { data: body } = await api.get('/enrichment-usage', { params });
      setData(body);
    } catch (err) {
      const msg = err?.response?.data?.message || err?.response?.data?.error || 'Failed to load enrichment usage';
      setError(msg);
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [range, customFrom, customTo, provider, iocType]);

  useEffect(() => { load().catch(() => {}); }, [load]);

  // Keep the provider filter reflected in the URL so the page is shareable /
  // deep-linkable (matches the "?provider=" preselect contract from the provider page).
  useEffect(() => {
    const current = searchParams.get('provider') || '';
    if (current === provider) return;
    const next = new URLSearchParams(searchParams);
    if (provider) next.set('provider', provider);
    else next.delete('provider');
    setSearchParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider]);

  const summary = data?.summary || {};
  const cards = summaryCards(summary);
  const primaryCards = cards.filter((c) => !c.secondary);
  const secondaryCards = cards.filter((c) => c.secondary);

  const providerRows = useMemo(
    () => sortProviderRows(data?.providers || [], sort.key, sort.dir),
    [data, sort]
  );
  const providerOptions = useMemo(() => providerFilterOptions(data?.providers || []), [data]);

  const buckets = useMemo(() => {
    if (!data?.range) return [];
    return mergeSeries(data.range.from, data.range.to, data.series || [], {
      collectionStartedOn: data.collection_started_on
    });
  }, [data]);

  const activeSeriesDefs = TREND_SERIES.filter((s) => activeSeries.has(s.key));
  const geo = useMemo(
    () => computeChartGeometry(buckets, activeSeriesDefs, { width: CHART_W, height: CHART_H, padding: CHART_PAD }),
    [buckets, activeSeriesDefs]
  );

  const quotaProviders = (data?.providers || []).filter((p) => p.quota && Number(p.quota.limit) > 0);
  const typeRows = data?.ioc_types || [];
  const maxTypeReq = Math.max(1, ...typeRows.map((t) => Number(t.request_count || 0)));

  const collectionNote = data?.collection_started_on && data?.range?.from < data.collection_started_on
    ? `Usage telemetry has been collected since ${formatDateLabel(data.collection_started_on)}. Earlier dates in this range predate collection and are shown as “not collected,” not real zero usage.`
    : '';

  function toggleSeries(key) {
    setActiveSeries((prev) => {
      const next = new Set(prev);
      if (next.has(key)) { if (next.size > 1) next.delete(key); } // keep at least one series
      else next.add(key);
      return next;
    });
  }

  function onSort(key) {
    setSort((prev) => prev.key === key
      ? { key, dir: prev.dir === 'desc' ? 'asc' : 'desc' }
      : { key, dir: key === 'display_name' ? 'asc' : 'desc' });
  }

  function onChartMove(e) {
    if (!chartRef.current || buckets.length === 0) return;
    const rect = chartRef.current.getBoundingClientRect();
    const vx = ((e.clientX - rect.left) / rect.width) * CHART_W;
    const { left, right } = CHART_PAD;
    const innerW = CHART_W - left - right;
    const rel = Math.max(0, Math.min(1, (vx - left) / innerW));
    const idx = Math.round(rel * (buckets.length - 1));
    setHoverIdx(Number.isFinite(idx) ? idx : null);
  }

  const hover = hoverIdx != null && buckets[hoverIdx] ? buckets[hoverIdx] : null;
  const hoverX = hover ? geo.lines[0]?.points[hoverIdx]?.x ?? null : null;

  return (
    <AppShell>
      <section className="ep-page">
        <h2 className="ep-page-title">Enrichment Usage</h2>

        {/* Filters */}
        <div className="eu-toolbar">
          <div className="eu-filter">
            <span className="eu-filter-label">Date Range</span>
            <div className="eu-segment" role="group" aria-label="Date range">
              {RANGE_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  className={range === opt.value ? 'is-active' : ''}
                  onClick={() => setRange(opt.value)}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {range === 'custom' ? (
            <>
              <div className="eu-filter">
                <span className="eu-filter-label">From</span>
                <input type="date" className="eu-date" value={customFrom} max={customTo} onChange={(e) => setCustomFrom(e.target.value)} />
              </div>
              <div className="eu-filter">
                <span className="eu-filter-label">To</span>
                <input type="date" className="eu-date" value={customTo} min={customFrom} max={systemToday} onChange={(e) => setCustomTo(e.target.value)} />
              </div>
            </>
          ) : null}

          <div className="eu-filter">
            <span className="eu-filter-label">Provider</span>
            <select className="eu-select" value={provider} onChange={(e) => setProvider(e.target.value)}>
              {providerOptions.map((o) => <option key={o.value || 'all'} value={o.value}>{o.label}</option>)}
            </select>
          </div>

          <div className="eu-filter">
            <span className="eu-filter-label">IOC Type</span>
            <select className="eu-select" value={iocType} onChange={(e) => setIocType(e.target.value)}>
              {IOC_TYPE_OPTIONS.map((o) => <option key={o.value || 'all'} value={o.value}>{o.label}</option>)}
            </select>
          </div>

          <button type="button" className="eu-refresh" onClick={() => load().catch(() => {})} disabled={loading}>
            {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>

        {error ? <div className="ep-banner ep-banner--error">{error}</div> : null}
        {!error && collectionNote ? <div className="ep-banner ep-banner--info">{collectionNote}</div> : null}
        {!error && !loading && data && !hasAnyUsage(summary) ? (
          <div className="ep-banner ep-banner--info">
            No enrichment activity recorded for the selected filters. Metrics show zero for counts and “—” where a rate is not yet meaningful.
          </div>
        ) : null}

        {/* Summary cards */}
        <div className="eu-cards">
          {primaryCards.map((c) => (
            <div key={c.key} className={`eu-card${c.tone && c.tone !== 'default' ? ` eu-card--${c.tone}` : ''}`}>
              <div className="eu-card-label">{c.label}</div>
              <div className="eu-card-value">{c.value}</div>
              {c.hint ? <div className="eu-card-hint">{c.hint}</div> : null}
            </div>
          ))}
        </div>
        <div className="eu-cards eu-cards--secondary">
          {secondaryCards.map((c) => (
            <div key={c.key} className="eu-card eu-card--secondary">
              <div className="eu-card-label">{c.label}</div>
              <div className="eu-card-value">{c.value}</div>
            </div>
          ))}
        </div>

        {/* Trend chart */}
        <div className="eu-section">
          <div className="eu-section-head">
            <span className="eu-section-title">Consumption Over Time</span>
            <div className="eu-legend">
              {TREND_SERIES.map((s) => (
                <button
                  key={s.key}
                  type="button"
                  className={activeSeries.has(s.key) ? 'is-on' : ''}
                  onClick={() => toggleSeries(s.key)}
                  aria-pressed={activeSeries.has(s.key)}
                >
                  <span className="dot" style={{ background: s.color }} />
                  {s.label}
                </button>
              ))}
            </div>
          </div>

          {loading ? (
            <div className="eu-state">Loading usage…</div>
          ) : error ? (
            <div className="eu-state eu-state--error">Chart unavailable — {error}</div>
          ) : buckets.length === 0 ? (
            <div className="eu-state">No data for the selected range.</div>
          ) : (
            <div className="eu-chart-wrap" style={{ position: 'relative' }}>
              <svg
                ref={chartRef}
                className="eu-chart"
                viewBox={`0 0 ${CHART_W} ${CHART_H}`}
                preserveAspectRatio="xMidYMid meet"
                onMouseMove={onChartMove}
                onMouseLeave={() => setHoverIdx(null)}
                role="img"
                aria-label="Enrichment consumption over time"
              >
                <g className="eu-grid">
                  {geo.yTicks.map((t, i) => (
                    <line key={i} x1={CHART_PAD.left} y1={t.y} x2={CHART_W - CHART_PAD.right} y2={t.y} />
                  ))}
                </g>
                <g className="eu-axis">
                  {geo.yTicks.map((t, i) => (
                    <text key={i} x={CHART_PAD.left - 6} y={t.y + 3} textAnchor="end">{formatNumber(t.value)}</text>
                  ))}
                  {geo.xTicks.map((t, i) => (
                    <text key={i} x={t.x} y={CHART_H - 8} textAnchor="middle">{t.label}</text>
                  ))}
                </g>
                {hoverX != null ? (
                  <line x1={hoverX} y1={CHART_PAD.top} x2={hoverX} y2={CHART_H - CHART_PAD.bottom} stroke="#475569" strokeWidth="1" strokeDasharray="3 3" />
                ) : null}
                {geo.lines.map((line) => (
                  <g key={line.key}>
                    <polyline points={line.polyline} fill="none" stroke={line.color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
                    {hoverIdx != null && line.points[hoverIdx] ? (
                      <circle cx={line.points[hoverIdx].x} cy={line.points[hoverIdx].y} r="3.5" fill={line.color} />
                    ) : null}
                  </g>
                ))}
              </svg>

              {hover ? (
                <div
                  style={{
                    position: 'absolute', top: 6,
                    left: `${Math.min(78, Math.max(2, ((hoverX ?? 0) / CHART_W) * 100))}%`,
                    background: '#0b1526', border: '1px solid #334155', borderRadius: 8,
                    padding: '8px 10px', pointerEvents: 'none', fontSize: 12, color: '#e2e8f0', minWidth: 150
                  }}
                >
                  <div style={{ color: '#94a3b8', marginBottom: 4 }}>
                    {formatDateLabel(hover.date)}{hover.collected === false ? ' · not collected' : ''}
                  </div>
                  {activeSeriesDefs.map((s) => (
                    <div key={s.key} style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                      <span><span className="dot" style={{ background: s.color, display: 'inline-block', width: 8, height: 8, borderRadius: 2, marginRight: 6 }} />{s.label}</span>
                      <b>{formatNumber(hover[s.key])}</b>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          )}
        </div>

        {/* Provider breakdown */}
        <div className="eu-section">
          <div className="eu-section-head">
            <span className="eu-section-title">Provider Breakdown</span>
            {provider ? (
              <button type="button" className="eu-refresh" style={{ margin: 0 }} onClick={() => setProvider('')}>Clear provider filter</button>
            ) : null}
          </div>
          {loading ? (
            <div className="eu-state">Loading…</div>
          ) : providerRows.length === 0 ? (
            <div className="eu-state">No providers to display.</div>
          ) : (
            <div className="eu-table-wrap">
              <table className="eu-table">
                <thead>
                  <tr>
                    {[
                      ['display_name', 'Provider'],
                      ['request_count', 'Requests'],
                      ['external_call_count', 'External Calls'],
                      ['cache_hit_count', 'Cache Hits'],
                      ['cache_hit_rate', 'Cache Hit Rate'],
                      ['success_count', 'Success'],
                      ['failure_count', 'Failed'],
                      ['rate_limit_count', 'Rate Limits'],
                      ['avg_external_response_time_ms', 'Avg Latency']
                    ].map(([key, label]) => (
                      <th key={key} className={sort.key === key ? 'is-sorted' : ''} onClick={() => onSort(key)}>
                        {label}{sort.key === key ? (sort.dir === 'desc' ? ' ↓' : ' ↑') : ''}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {providerRows.map((p) => (
                    <tr
                      key={p.provider_key}
                      className={provider === p.provider_key ? 'is-selected' : ''}
                      onClick={() => setProvider(provider === p.provider_key ? '' : p.provider_key)}
                      title="Filter the page to this provider"
                    >
                      <td>
                        <span className="eu-prov">
                          <span className="eu-prov-name">{p.display_name}</span>
                          {p.enabled === false ? <span className="eu-chip eu-chip--disabled">Disabled</span> : null}
                          {p.known === false ? <span className="eu-chip eu-chip--unknown" title="No longer in the provider registry (renamed or removed)">Legacy</span> : null}
                        </span>
                      </td>
                      <td>{formatNumber(p.request_count)}</td>
                      <td><b>{formatNumber(p.external_call_count)}</b></td>
                      <td>{formatNumber(p.cache_hit_count)}</td>
                      <td>{p.cache_hit_rate == null ? <span className="eu-muted">—</span> : formatPercent(p.cache_hit_rate)}</td>
                      <td>{formatNumber(p.success_count)}</td>
                      <td>{formatNumber(p.failure_count)}</td>
                      <td>{formatNumber(p.rate_limit_count)}</td>
                      <td>{p.avg_external_response_time_ms == null ? <span className="eu-muted">—</span> : formatMs(p.avg_external_response_time_ms)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Quota */}
        <div className="eu-section">
          <div className="eu-section-head"><span className="eu-section-title">Quota</span></div>
          {quotaProviders.length === 0 ? (
            <div className="eu-quota-unavailable">No provider quota is configured. Quota is shown only when a provider reliably reports or is configured with a limit.</div>
          ) : (
            <div className="eu-quota-grid">
              {quotaProviders.map((p) => {
                const q = quotaView(p.quota);
                const cls = q.barPct == null ? '' : q.barPct >= 90 ? 'is-crit' : q.barPct >= 75 ? 'is-high' : '';
                return (
                  <div key={p.provider_key} className="eu-quota">
                    <div className="eu-quota-head">
                      <span className="eu-quota-name">{p.display_name}</span>
                      <span className="eu-quota-val">{q.pct != null ? formatPercent(q.pct) : (q.window || '')}</span>
                    </div>
                    <div className="eu-quota-val" style={{ marginBottom: 6 }}>{q.label}{q.window ? ` · ${q.window}` : ''}</div>
                    {q.barPct != null ? (
                      <div className="eu-quota-bar"><span className={cls} style={{ width: `${q.barPct}%` }} /></div>
                    ) : null}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Usage by IOC Type */}
        {typeRows.length > 0 ? (
          <div className="eu-section">
            <div className="eu-section-head"><span className="eu-section-title">Usage by IOC Type</span></div>
            {typeRows.map((t) => (
              <div key={t.ioc_type} className="eu-type-row">
                <span className="eu-type-label">{t.ioc_type}</span>
                <span className="eu-type-track"><span style={{ width: `${Math.max(2, (Number(t.request_count || 0) / maxTypeReq) * 100)}%` }} /></span>
                <span className="eu-type-val">{formatNumber(t.request_count)} req · {formatNumber(t.external_call_count)} ext</span>
              </div>
            ))}
          </div>
        ) : null}
      </section>
    </AppShell>
  );
}
