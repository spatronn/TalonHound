import React from 'react';

const STATUS_STYLES = {
  healthy: { label: 'Healthy', tone: 'success' },
  error: { label: 'Error', tone: 'danger' },
  rate_limited: { label: 'Rate limited', tone: 'warn' },
  configured: { label: 'Configured', tone: 'info' },
  disabled: { label: 'Disabled', tone: 'muted' },
  never_synced: { label: 'Never synced', tone: 'muted' },
  running: { label: 'Running', tone: 'info' },
  not_configured: { label: 'Not configured', tone: 'muted' }
};

export default function ProviderStatusBadge({ status, label }) {
  const meta = STATUS_STYLES[String(status || '').toLowerCase()] || STATUS_STYLES.not_configured;
  return (
    <span className={`ep-badge ep-badge--${meta.tone}`} role="status">
      {label || meta.label}
    </span>
  );
}
