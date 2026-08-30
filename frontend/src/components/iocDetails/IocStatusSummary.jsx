import React from 'react';
import { IocDetailIcons } from './IocDetailIcons.jsx';
import { IOC_STATUS_ACTION_BUTTONS } from '../../lib/iocStatusCard.js';
import { formatIocDetailDateTime } from '../../lib/iocDetailTimestamps.js';

const ICON_MAP = {
  status: IocDetailIcons.status,
  calendar: IocDetailIcons.calendar,
  sources: IocDetailIcons.sources,
  clock: IocDetailIcons.clock,
  user: IocDetailIcons.user
};

const ICON_COLORS = {
  status: '#86efac',
  calendar: '#93c5fd',
  sources: '#a5b4fc',
  clock: '#67e8f9',
  user: '#c4b5fd'
};

export function IocStatusSummary({
  presentation,
  renderBadge,
  ui,
  isAdmin,
  actionLoading,
  onAction
}) {
  if (!presentation) return null;

  return (
    <div style={{
      padding: '14px 16px',
      border: '1px solid #334155',
      borderRadius: 10,
      background: '#111827'
    }}>
      <div style={{ fontWeight: 700, color: '#e2e8f0', marginBottom: 12, fontSize: 14 }}>IOC Status Summary</div>
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 1fr) auto',
        gap: 14,
        alignItems: 'start'
      }}
        className="ioc-status-summary-grid"
      >
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
          gap: 12
        }}>
          {presentation.fields.map((field) => {
            const Icon = ICON_MAP[field.icon] || IocDetailIcons.info;
            const color = ICON_COLORS[field.icon] || '#94a3b8';
            const value = field.kind === 'badge'
              ? renderBadge(field.status)
              : field.kind === 'datetime'
                ? formatIocDetailDateTime(field.raw)
                : field.value;
            return (
              <div key={field.key} style={{ minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                  <Icon size={15} color={color} />
                  <span style={{ fontSize: 11, color: '#94a3b8', letterSpacing: 0.02 }}>{field.label}</span>
                </div>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0', lineHeight: 1.35 }}>
                  {value}
                </div>
                {field.secondary ? (
                  <div style={{ fontSize: 11, color: '#64748b', marginTop: 3, lineHeight: 1.35 }}>{field.secondary}</div>
                ) : null}
              </div>
            );
          })}
        </div>

        {isAdmin && presentation.buttons.length ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 150 }}>
            {presentation.buttons.map((actionType) => {
              const def = IOC_STATUS_ACTION_BUTTONS[actionType];
              if (!def) return null;
              const btnStyle = {
                ...ui.btn,
                width: '100%',
                justifyContent: 'center',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                whiteSpace: 'nowrap'
              };
              return (
                <button
                  key={actionType}
                  type="button"
                  style={btnStyle}
                  disabled={actionLoading}
                  onClick={() => onAction(actionType)}
                  aria-label={def.label}
                >
                  {actionType === 'custom_expire_ioc' ? <IocDetailIcons.calendar size={13} /> : null}
                  {actionType === 'expire_ioc' ? <IocDetailIcons.clock size={13} /> : null}
                  {def.label}
                </button>
              );
            })}
          </div>
        ) : null}
      </div>
      <style>{`
        @media (max-width: 900px) {
          .ioc-status-summary-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </div>
  );
}
