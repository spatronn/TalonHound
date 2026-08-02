import React from 'react';
import { getEffectiveThreatClassifications } from '../../lib/classificationSummary.js';

export function IocMetadataCards({
  confidenceCard,
  summary,
  canWrite,
  onEditConfidence,
  onEditThreatClass,
  onEditThreatActor,
  ThreatClassificationBadges
}) {
  const classifications = getEffectiveThreatClassifications(summary);

  const cardStyle = {
    padding: 12,
    border: '1px solid #334155',
    borderRadius: 10,
    background: '#111827',
    minWidth: 0
  };

  const editBtn = {
    fontSize: 12,
    padding: '4px 10px',
    borderRadius: 6,
    border: '1px solid #475569',
    background: '#0f172a',
    color: '#cbd5e1',
    cursor: 'pointer'
  };

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(3, minmax(0, 1fr))',
      gap: 12
    }}
      className="ioc-metadata-cards-grid"
    >
      <div style={cardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 8 }}>
          <div style={{ fontSize: 13, color: '#94a3b8' }}>Confidence</div>
          {canWrite ? (
            <button type="button" onClick={onEditConfidence} style={editBtn} aria-label="Edit confidence">Edit</button>
          ) : null}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
          <span style={{
            display: 'inline-flex',
            alignItems: 'center',
            padding: '4px 10px',
            borderRadius: 999,
            fontSize: 13,
            fontWeight: 700,
            background: confidenceCard.badgeStyle.bg,
            color: confidenceCard.badgeStyle.color,
            border: `1px solid ${confidenceCard.badgeStyle.border}`
          }}>
            {confidenceCard.effectiveLabel}
          </span>
          {confidenceCard.hasOverride ? (
            <span style={{ padding: '2px 8px', borderRadius: 999, fontSize: 11, fontWeight: 700, background: '#312e81', color: '#c7d2fe', border: '1px solid #4338ca' }}>
              Manual override
            </span>
          ) : null}
        </div>
        <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.5 }}>
          {confidenceCard.hasOverride ? confidenceCard.overrideLine : `Source: ${confidenceCard.sourceLine.replace(/^Source: /, '')}`}
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 8 }}>
          <div style={{ fontSize: 13, color: '#94a3b8' }}>Threat Classifications</div>
          {canWrite ? (
            <button type="button" onClick={onEditThreatClass} style={editBtn} aria-label="Edit threat classifications">Edit</button>
          ) : null}
        </div>
        <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {classifications.length ? (
            <ThreatClassificationBadges classifications={classifications} />
          ) : (
            <span style={{ color: '#64748b', fontSize: 13, fontWeight: 500 }}>Not selected</span>
          )}
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 8 }}>
          <div style={{ fontSize: 13, color: '#94a3b8' }}>Threat Actor</div>
          {canWrite ? (
            <button type="button" onClick={onEditThreatActor} style={editBtn} aria-label="Edit threat actor">Edit</button>
          ) : null}
        </div>
        <div style={{ fontSize: 15, fontWeight: 700, color: summary?.threat_actor_name ? '#e2e8f0' : '#64748b' }}>
          {summary?.threat_actor_name || 'Not selected'}
        </div>
      </div>

      <style>{`
        @media (max-width: 900px) {
          .ioc-metadata-cards-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </div>
  );
}
