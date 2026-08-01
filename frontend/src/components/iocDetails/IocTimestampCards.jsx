import React from 'react';
import { IocDetailIcons } from './IocDetailIcons.jsx';
import { buildIocDetailTimestampCards } from '../../lib/iocDetailTimestamps.js';

const ICON_MAP = {
  download: IocDetailIcons.download,
  calendar: IocDetailIcons.calendar,
  edit: IocDetailIcons.edit
};

const ICON_COLORS = {
  download: '#60a5fa',
  calendar: '#a78bfa',
  edit: '#2dd4bf'
};

export function IocTimestampCards({ summary, activeSources = [], historicalSources = [] }) {
  const cards = buildIocDetailTimestampCards(summary, activeSources, historicalSources);

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <div style={{ fontWeight: 700, color: '#e2e8f0', fontSize: 14 }}>IOC Timestamps</div>
        <span title="Platform insert vs source observation times" style={{ display: 'inline-flex', color: '#64748b' }}>
          <IocDetailIcons.info size={14} />
        </span>
      </div>
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
        gap: 12
      }}
        className="ioc-timestamp-cards-grid"
      >
        {cards.map((card) => {
          const Icon = ICON_MAP[card.icon] || IocDetailIcons.info;
          const color = ICON_COLORS[card.icon] || '#94a3b8';
          return (
            <div
              key={card.key}
              style={{
                border: '1px solid #334155',
                borderRadius: 10,
                padding: '12px 14px',
                background: '#111827',
                minWidth: 0,
                display: 'flex',
                flexDirection: 'column',
                gap: 8
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{
                  width: 28,
                  height: 28,
                  borderRadius: 8,
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background: 'rgba(15,23,42,0.9)',
                  border: '1px solid #334155',
                  color
                }}>
                  <Icon size={14} color={color} />
                </span>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0' }}>{card.label}</div>
              </div>
              <div style={{ fontSize: 11, color: '#64748b', lineHeight: 1.4 }}>{card.description}</div>
              <div style={{
                fontSize: 13,
                fontWeight: 700,
                color: '#f1f5f9',
                fontVariantNumeric: 'tabular-nums',
                overflowWrap: 'anywhere'
              }}>
                {card.display}
              </div>
              {card.context ? (
                <div style={{ fontSize: 11, color: '#64748b', marginTop: 'auto' }}>{card.context}</div>
              ) : null}
            </div>
          );
        })}
      </div>
      <style>{`
        @media (max-width: 1200px) {
          .ioc-timestamp-cards-grid { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
        }
        @media (max-width: 640px) {
          .ioc-timestamp-cards-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </div>
  );
}
