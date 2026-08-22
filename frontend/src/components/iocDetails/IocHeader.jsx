import React, { useState } from 'react';
import { IocDetailIcons } from './IocDetailIcons.jsx';
import { buttonClassName } from '../../lib/uiButtons.js';

export function IocHeader({
  title = 'IOC Details',
  subtitle = 'Analyst-focused detail page for faster triage',
  observable,
  statusBadge,
  ui,
  onMarkFalsePositive,
  onDelete,
  onBack,
  onRefresh,
  showMarkFalsePositive,
  showDelete
}) {
  const [copied, setCopied] = useState(false);
  const value = String(observable || '').trim();

  async function copyObservable() {
    if (!value || value === '-') return;
    try {
      await navigator.clipboard?.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
        <div style={{ minWidth: 0 }}>
          <h2 style={{ margin: 0, color: '#f1f5f9', fontSize: 22 }}>{title}</h2>
          <div style={{ marginTop: 6, color: '#94a3b8', fontSize: 13 }}>{subtitle}</div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {showMarkFalsePositive ? (
            <button type="button" className={buttonClassName({ variant: 'secondary' })} onClick={onMarkFalsePositive}>Mark as False Positive</button>
          ) : null}
          {showDelete ? (
            <button type="button" className={buttonClassName({ variant: 'danger' })} onClick={onDelete} aria-label="Delete IOC Record" title="Global IOC deletion (removes the IOC entirely, not just one source)">Delete IOC Record</button>
          ) : null}
          <button type="button" className={buttonClassName({ variant: 'secondary' })} onClick={onBack}>Back to IOC List</button>
          <button type="button" className={buttonClassName({ variant: 'secondary' })} onClick={onRefresh} aria-label="Refresh IOC details">
            <IocDetailIcons.refresh size={14} />
            Refresh
          </button>
        </div>
      </div>

      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 12,
        padding: '12px 14px',
        border: '1px solid #334155',
        borderRadius: 10,
        background: '#111827',
        flexWrap: 'wrap'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0, flex: '1 1 240px' }}>
          <div style={{
            fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace",
            fontSize: 14,
            fontWeight: 700,
            color: '#f1f5f9',
            overflowWrap: 'anywhere',
            wordBreak: 'break-all',
            minWidth: 0,
            lineHeight: 1.45
          }}>
            {value || '—'}
          </div>
          {value && value !== '-' ? (
            <button
              type="button"
              className={buttonClassName({ variant: 'ghost', size: 'sm', className: 'th-btn--icon' })}
              style={{ flexShrink: 0 }}
              onClick={() => copyObservable().catch(() => {})}
              aria-label={copied ? 'Copied' : 'Copy IOC value'}
              title={copied ? 'Copied' : 'Copy'}
            >
              <IocDetailIcons.copy size={14} />
            </button>
          ) : null}
        </div>
        <div style={{ flexShrink: 0 }}>{statusBadge}</div>
      </div>
    </div>
  );
}
