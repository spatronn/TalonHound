import React, { useState } from 'react';
import { IocDetailIcons } from './IocDetailIcons.jsx';

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

  const outlineBtn = {
    ...ui.btn,
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    whiteSpace: 'nowrap'
  };

  const deleteBtn = {
    ...outlineBtn,
    borderColor: '#7f1d1d',
    color: '#fca5a5',
    background: 'rgba(127,29,29,0.12)'
  };

  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
        <div style={{ minWidth: 0 }}>
          <h2 style={{ margin: 0, color: '#f1f5f9', fontSize: 22 }}>{title}</h2>
          <div style={{ marginTop: 6, color: '#94a3b8', fontSize: 13 }}>{subtitle}</div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {showMarkFalsePositive ? (
            <button type="button" style={outlineBtn} onClick={onMarkFalsePositive}>Mark as False Positive</button>
          ) : null}
          {showDelete ? (
            <button type="button" style={deleteBtn} onClick={onDelete} aria-label="Delete IOC">Delete IOC</button>
          ) : null}
          <button type="button" style={outlineBtn} onClick={onBack}>Back to IOC List</button>
          <button type="button" style={outlineBtn} onClick={onRefresh} aria-label="Refresh IOC details">
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
              onClick={() => copyObservable().catch(() => {})}
              aria-label={copied ? 'Copied' : 'Copy IOC value'}
              title={copied ? 'Copied' : 'Copy'}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 30,
                height: 30,
                borderRadius: 8,
                border: '1px solid #475569',
                background: '#0f172a',
                color: copied ? '#86efac' : '#94a3b8',
                cursor: 'pointer',
                flexShrink: 0
              }}
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
