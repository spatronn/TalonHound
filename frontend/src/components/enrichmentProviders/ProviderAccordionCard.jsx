import React from 'react';
import ProviderLogo from './ProviderLogo.jsx';
import ProviderStatusBadge from './ProviderStatusBadge.jsx';

export default function ProviderAccordionCard({
  providerKey,
  name,
  description,
  status,
  statusLabel,
  enabled,
  open,
  onToggle,
  children
}) {
  return (
    <article className={`ep-card${open ? ' is-open' : ''}`}>
      <button
        type="button"
        className="ep-card-header"
        onClick={onToggle}
        aria-expanded={open}
      >
        <div className="ep-card-identity">
          <ProviderLogo providerKey={providerKey} name={name} />
          <div className="ep-card-text">
            <div className="ep-card-title">{name}</div>
            {description ? <div className="ep-card-desc">{description}</div> : null}
          </div>
        </div>
        <div className="ep-card-meta">
          <ProviderStatusBadge status={status} label={statusLabel} />
          <span className={`ep-enabled-chip${enabled ? ' is-on' : ''}`}>
            {enabled ? 'Enabled' : 'Disabled'}
          </span>
          <span className="ep-chevron" aria-hidden="true">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d={open ? 'm18 15-6-6-6 6' : 'm6 9 6 6 6-6'} />
            </svg>
          </span>
        </div>
      </button>
      {open ? <div className="ep-card-body">{children}</div> : null}
    </article>
  );
}
