import React from 'react';

const STATUS_STYLES = {
  healthy: { label: 'Healthy', tone: 'success' },
  degraded: { label: 'Degraded', tone: 'warn' },
  unhealthy: { label: 'Unhealthy', tone: 'danger' },
  unknown: { label: 'Unknown', tone: 'muted' }
};

export default function ProviderStatusBadge({ status, label }) {
  const meta = STATUS_STYLES[String(status || '').toLowerCase()] || STATUS_STYLES.unknown;
  return (
    <span className={`ep-badge ep-badge--${meta.tone}`} role="status">
      {label || meta.label}
    </span>
  );
}
