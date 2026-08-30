import React from 'react';

function StatCard({ label, value, tone = 'default', icon }) {
  return (
    <div className={`ep-stat ep-stat--${tone}`}>
      <div className="ep-stat-top">
        <span className="ep-stat-label">{label}</span>
        <span className="ep-stat-icon" aria-hidden="true">{icon}</span>
      </div>
      <div className="ep-stat-value">{value}</div>
    </div>
  );
}

export default function ProviderSummaryStats({ providers = [] }) {
  const total = providers.length;
  const healthy = providers.filter((p) => String(p.status || '').toLowerCase() === 'healthy').length;
  const enabled = providers.filter((p) => p.enabled !== false).length;
  const disabled = total - enabled;

  return (
    <div className="ep-stats">
      <StatCard label="Total Providers" value={total} tone="info" icon={<CubeIcon />} />
      <StatCard label="Healthy" value={healthy} tone="success" icon={<PulseIcon />} />
      <StatCard label="Enabled" value={enabled} tone="info" icon={<PlugIcon />} />
      <StatCard label="Disabled" value={disabled} tone="muted" icon={<BanIcon />} />
    </div>
  );
}

function CubeIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2 3 7v10l9 5 9-5V7l-9-5Z" />
      <path d="M12 22V12" />
      <path d="m3 7 9 5 9-5" />
    </svg>
  );
}

function PulseIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 12h-4l-3 7L9 5l-3 7H2" />
    </svg>
  );
}

function PlugIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22v-5" />
      <path d="M9 8V2" />
      <path d="M15 8V2" />
      <path d="M18 8v5a6 6 0 0 1-12 0V8Z" />
    </svg>
  );
}

function BanIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <path d="m4.9 4.9 14.2 14.2" />
    </svg>
  );
}
