import React, { useEffect, useId, useRef, useState } from 'react';
import { IocDetailIcons, InfoTip } from './IocDetailIcons.jsx';
import { IOC_SOURCE_TIMESTAMP_PRESENTATION } from '../../lib/iocSourceTimestampPresentation.js';
import { formatIocDetailDateTime, listSourceMembershipActions } from '../../lib/iocDetailTimestamps.js';

function SourceActionsMenu({
  src,
  isAdmin,
  actionLoading,
  onAction
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);
  const menuId = useId();
  const actions = listSourceMembershipActions(src);
  const canShow = isAdmin && src.source_type === 'feed' && src.actions_enabled;

  useEffect(() => {
    if (!open) return undefined;
    const onDoc = (evt) => {
      if (!rootRef.current?.contains(evt.target)) setOpen(false);
    };
    const onKey = (evt) => {
      if (evt.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  if (!canShow) return '—';

  return (
    <div ref={rootRef} style={{ position: 'relative', display: 'inline-flex' }}>
      <button
        type="button"
        aria-label={`Actions for ${src.name || 'source'}`}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        disabled={actionLoading}
        onClick={() => setOpen((v) => !v)}
        style={{
          width: 30,
          height: 30,
          borderRadius: 8,
          border: '1px solid #475569',
          background: '#0f172a',
          color: '#cbd5e1',
          cursor: actionLoading ? 'wait' : 'pointer',
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}
      >
        <IocDetailIcons.more size={14} />
      </button>
      {open ? (
        <div
          id={menuId}
          role="menu"
          style={{
            position: 'absolute',
            right: 0,
            top: 'calc(100% + 4px)',
            minWidth: 180,
            border: '1px solid #334155',
            borderRadius: 8,
            background: '#0b1220',
            zIndex: 40,
            padding: 4,
            boxShadow: '0 8px 24px rgba(0,0,0,0.35)'
          }}
        >
          {actions.map((action) => (
            <button
              key={action.type}
              type="button"
              role="menuitem"
              disabled={!action.enabled || actionLoading}
              onClick={() => {
                if (!action.enabled) return;
                setOpen(false);
                onAction(action.type, src.membership_id);
              }}
              style={{
                display: 'block',
                width: '100%',
                textAlign: 'left',
                padding: '8px 10px',
                border: 'none',
                borderRadius: 6,
                background: 'transparent',
                color: !action.enabled
                  ? '#475569'
                  : (action.danger ? '#fca5a5' : '#e2e8f0'),
                fontSize: 12,
                cursor: action.enabled && !actionLoading ? 'pointer' : 'not-allowed',
                opacity: action.enabled ? 1 : 0.55
              }}
            >
              {action.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function TimestampHeader({ presentation }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, whiteSpace: 'nowrap' }}>
      {presentation.label}
      <InfoTip text={presentation.tooltip} />
    </span>
  );
}

export function ActiveSourcesTable({
  activeSources,
  importedAt,
  sourceColorIndex,
  SourceBadge,
  iocSourceTypeLabel,
  iocSourceStatusBadge,
  isAdmin,
  actionLoading,
  onMembershipAction
}) {
  return (
    <div style={{ padding: 14, border: '1px solid #334155', borderRadius: 10, background: '#111827' }}>
      <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 10 }}>Active Sources</div>
      {activeSources.length ? (
        <div style={{ overflowX: 'auto' }}>
          <table width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', fontSize: 12, color: '#e2e8f0', minWidth: 980 }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                <th>Source</th>
                <th>Type</th>
                <th>Status</th>
                <th><TimestampHeader presentation={IOC_SOURCE_TIMESTAMP_PRESENTATION.first} /></th>
                <th><TimestampHeader presentation={IOC_SOURCE_TIMESTAMP_PRESENTATION.imported} /></th>
                <th><TimestampHeader presentation={IOC_SOURCE_TIMESTAMP_PRESENTATION.last} /></th>
                <th>Policy expires</th>
                <th>Effective expires</th>
                <th>Override</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {activeSources.map((src) => (
                <tr key={src.id} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td><SourceBadge index={sourceColorIndex} label={src.name} /></td>
                  <td>{iocSourceTypeLabel(src)}</td>
                  <td>{iocSourceStatusBadge(src)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatIocDetailDateTime(src.first_seen_at)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatIocDetailDateTime(importedAt)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatIocDetailDateTime(src.last_changed_at)}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{src.source_type === 'feed' ? formatIocDetailDateTime(src.policy_expires_at) : '—'}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>{formatIocDetailDateTime(src.expires_at)}</td>
                  <td>{src.source_type === 'feed' ? (src.override_enabled ? 'Yes' : 'No') : '—'}</td>
                  <td>
                    <SourceActionsMenu
                      src={src}
                      isAdmin={isAdmin}
                      actionLoading={actionLoading}
                      onAction={onMembershipAction}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div style={{ fontSize: 13, color: '#94a3b8' }}>No active sources.</div>
      )}
    </div>
  );
}

export function IocSummaryStrip({ summary }) {
  if (!summary) return null;
  const items = [
    { label: 'Type', value: summary.observable_type || '—' },
    {
      label: 'Sources',
      value: `${summary.active_source_count ?? 0} / ${summary.total_source_membership_count ?? summary.source_count ?? summary.active_source_count ?? 0} total`
    },
    { label: 'First Seen', value: formatIocDetailDateTime(summary.first_seen_at) },
    { label: 'Last Seen', value: formatIocDetailDateTime(summary.last_seen_at) }
  ];

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
      gap: 10,
      padding: '10px 12px',
      border: '1px solid #334155',
      borderRadius: 8,
      background: '#0f172a'
    }}>
      {items.map((item) => (
        <div key={item.label} style={{ minWidth: 0 }}>
          <div style={{ fontSize: 11, color: '#64748b', marginBottom: 3 }}>{item.label}</div>
          <div style={{ fontSize: 13, fontWeight: 600, color: '#cbd5e1', overflowWrap: 'anywhere' }}>{item.value}</div>
        </div>
      ))}
    </div>
  );
}
