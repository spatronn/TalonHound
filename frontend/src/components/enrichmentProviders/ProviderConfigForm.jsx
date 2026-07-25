import React from 'react';
import ProviderStatusBadge from './ProviderStatusBadge.jsx';

function formatRelativeTime(value) {
  if (!value) return 'Never';
  const ts = new Date(value).getTime();
  if (Number.isNaN(ts)) return 'Never';
  const diffSec = Math.round((Date.now() - ts) / 1000);
  if (diffSec < 60) return 'Just now';
  if (diffSec < 3600) {
    const m = Math.floor(diffSec / 60);
    return `${m} minute${m === 1 ? '' : 's'} ago`;
  }
  if (diffSec < 86400) {
    const h = Math.floor(diffSec / 3600);
    return `${h} hour${h === 1 ? '' : 's'} ago`;
  }
  const d = Math.floor(diffSec / 86400);
  return `${d} day${d === 1 ? '' : 's'} ago`;
}

export default function ProviderConfigForm({
  left,
  status,
  statusLabel,
  enabled,
  onEnabledChange,
  enabledDisabled = false,
  showEnabledToggle = true,
  lastTestAt,
  lastTestLabel = 'Last Test',
  showLastTest = true,
  description,
  extraRight,
  actions,
  errorMessage
}) {
  return (
    <div className="ep-config">
      <div className="ep-config-grid">
        <div className="ep-config-left">{left}</div>
        <aside className="ep-config-right">
          <div className="ep-side-row">
            <span className="ep-side-label">Status</span>
            <div className="ep-side-value">
              <span className={`ep-status-dot ep-status-dot--${String(status || 'muted').toLowerCase()}`} />
              <ProviderStatusBadge status={status} label={statusLabel} />
            </div>
          </div>

          {showEnabledToggle ? (
            <div className="ep-side-row">
              <span className="ep-side-label">Enabled</span>
              <label className={`ep-toggle${enabledDisabled ? ' is-disabled' : ''}`}>
                <input
                  type="checkbox"
                  checked={!!enabled}
                  onChange={(e) => onEnabledChange?.(e.target.checked)}
                  disabled={enabledDisabled}
                />
                <span className="ep-toggle-track" aria-hidden="true" />
              </label>
            </div>
          ) : (
            <div className="ep-side-row">
              <span className="ep-side-label">Enabled</span>
              <div className="ep-side-value ep-side-muted">{enabled !== false ? 'Yes' : 'No'}</div>
            </div>
          )}

          {showLastTest ? (
            <div className="ep-side-row">
              <span className="ep-side-label">{lastTestLabel}</span>
              <div className="ep-side-value ep-side-muted">
                {lastTestAt ? (
                  <>
                    <span className="ep-check-ok" aria-hidden="true">✓</span>
                    {formatRelativeTime(lastTestAt)}
                  </>
                ) : (
                  'Never'
                )}
              </div>
            </div>
          ) : null}

          {description ? (
            <div className="ep-side-desc">
              <div className="ep-side-label">Description</div>
              <p>{description}</p>
            </div>
          ) : null}

          {extraRight}
        </aside>
      </div>

      {errorMessage ? (
        <div className="ep-error-banner">
          <b>Last error:</b> {errorMessage}
        </div>
      ) : null}

      {actions ? <div className="ep-config-actions">{actions}</div> : null}
    </div>
  );
}

export function ProviderField({ id, label, hint, children }) {
  return (
    <label htmlFor={id} className="ep-field">
      <span className="ep-field-label">{label}</span>
      {children}
      {hint ? <span className="ep-field-hint">{hint}</span> : null}
    </label>
  );
}
