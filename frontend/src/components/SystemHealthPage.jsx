import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';
import { formatUserDateTime, utcIsoTooltip } from '../lib/formatDate.js';
import { healthLabel, normalizeHealthStatus, reasonLabel, summaryLabel } from '../lib/systemHealthView.js';
import ProviderStatusBadge from './enrichmentProviders/ProviderStatusBadge.jsx';
import './SystemHealthPage.css';

const SECTION_TITLES = {
  core: 'Core Services',
  workers: 'Workers',
  feeds: 'Threat Feeds',
  providers: 'Enrichment Providers',
  queues: 'Queues / Jobs'
};

function Timestamp({ value }) {
  if (!value) return <span className="sh-muted">—</span>;
  return <span className="sh-muted" title={utcIsoTooltip(value)}>{formatUserDateTime(value)}</span>;
}

function SummaryCard({ label, summary, overall }) {
  const status = overall ? normalizeHealthStatus(overall.status) : (
    Number(summary?.unhealthy || 0) ? 'unhealthy'
      : Number(summary?.degraded || 0) ? 'degraded'
        : Number(summary?.unknown || 0) ? 'unknown'
          : Number(summary?.healthy || 0) ? 'healthy'
            : 'unknown'
  );
  return (
    <div className="ep-stat">
      <div className="ep-stat-top">
        <span className="ep-stat-label">{label}</span>
        <ProviderStatusBadge status={status} />
      </div>
      <div className="sh-summary-value">{overall ? healthLabel(status) : summaryLabel(summary)}</div>
    </div>
  );
}

function HealthSection({ sectionKey, items }) {
  return (
    <section className="sh-section">
      <h3>{SECTION_TITLES[sectionKey]}</h3>
      <div className="sh-table-wrap">
        <table className="sh-table">
          <thead>
            <tr>
              <th>Component</th>
              <th>Status</th>
              <th>Evidence</th>
              <th>Last success</th>
              <th>Last failure</th>
            </tr>
          </thead>
          <tbody>
            {(items || []).map((item) => (
              <tr key={item.key}>
                <td>
                  <div className="sh-name">{item.name}</div>
                  {item.enabled === false ? <div className="sh-muted">Disabled</div> : null}
                </td>
                <td><ProviderStatusBadge status={normalizeHealthStatus(item.status)} /></td>
                <td className="sh-evidence">{reasonLabel(item.reason)}</td>
                <td><Timestamp value={item.last_success_at} /></td>
                <td><Timestamp value={item.last_failure_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function SystemHealthPage({ AppShell }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const response = await api.get('/system/health');
      setData(response.data);
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to load system health.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load().catch(() => {}); }, [load]);

  return (
    <AppShell>
      <section className="ep-page sh-page">
        <div className="sh-header">
          <div>
            <h2 className="ep-page-title">System Health</h2>
            <p className="ep-page-subtitle">Operational evidence for TalonHound services, workers, feeds, queues, and providers.</p>
          </div>
          <button type="button" className="th-btn th-btn--secondary" onClick={() => load().catch(() => {})} disabled={loading}>
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>

        {error ? <div className="ep-banner ep-banner--error">{error}</div> : null}
        {data ? (
          <>
            <div className="ep-stats sh-stats">
              <SummaryCard label="Overall Health" overall={data.overall} />
              <SummaryCard label="Core Services" summary={data.summary?.core} />
              <SummaryCard label="Workers" summary={data.summary?.workers} />
              <SummaryCard label="Threat Feeds" summary={data.summary?.feeds} />
              <SummaryCard label="Enrichment Providers" summary={data.summary?.providers} />
            </div>
            <div className="sh-checked">
              Last checked: <Timestamp value={data.checked_at} />
            </div>
            {Object.keys(SECTION_TITLES).map((key) => (
              <HealthSection key={key} sectionKey={key} items={data.sections?.[key]} />
            ))}
          </>
        ) : loading ? <div className="sh-loading">Loading health evidence…</div> : null}
      </section>
    </AppShell>
  );
}
