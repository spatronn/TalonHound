import React from 'react';
import { getEffectiveThreatClassifications } from '../../lib/classificationSummary.js';
import {
  attributionHint,
  getAnalystMalwareFamilyIdsFromSummary,
  getAnalystThreatActorIdsFromSummary,
  getMalwareFamiliesFromSummary,
  getThreatActorsFromSummary
} from '../../lib/iocAttributionSummary.js';

export {
  getThreatActorsFromSummary,
  getMalwareFamiliesFromSummary,
  getAnalystThreatActorIdsFromSummary,
  getAnalystMalwareFamilyIdsFromSummary
};

function entityTitle(entity) {
  const hint = attributionHint(entity);
  const pulses = (entity?.sources || [])
    .filter((s) => s.evidence_ref_type === 'otx_pulse' && s.evidence_ref_id)
    .map((s) => s.evidence_title || s.evidence_ref_id);
  const parts = [entity?.name || '', hint, pulses.length ? `Pulse: ${pulses.join(', ')}` : null].filter(Boolean);
  return parts.join('\n');
}

export function AttributionEntityBadges({ entities, max = 8, emptyLabel = 'Not selected' }) {
  const list = Array.isArray(entities) ? entities.filter((e) => e?.name || e?.id) : [];
  if (!list.length) {
    return <span style={{ color: '#64748b', fontSize: 13, fontWeight: 500 }}>{emptyLabel}</span>;
  }
  const shown = list.slice(0, max);
  const extra = list.length - shown.length;
  return (
    <>
      {shown.map((entity) => {
        const hint = attributionHint(entity);
        const isSourceOnly = entity.attribution === 'source_reported';
        return (
          <span
            key={entity.id || entity.name}
            title={entityTitle(entity)}
            style={{
              display: 'inline-flex',
              flexDirection: 'column',
              alignItems: 'flex-start',
              gap: 2,
              padding: '4px 10px',
              borderRadius: 8,
              fontSize: 12,
              fontWeight: 700,
              background: isSourceOnly ? '#1e293b' : '#312e81',
              color: isSourceOnly ? '#e2e8f0' : '#c7d2fe',
              border: `1px solid ${isSourceOnly ? '#475569' : '#4338ca'}`,
              maxWidth: '100%'
            }}
          >
            <span style={{ wordBreak: 'break-word' }}>{entity.name || entity.id}</span>
            {hint ? (
              <span style={{ fontSize: 10, fontWeight: 600, color: isSourceOnly ? '#94a3b8' : '#a5b4fc', lineHeight: 1.3 }}>
                {hint}
              </span>
            ) : null}
          </span>
        );
      })}
      {extra > 0 ? (
        <span style={{ fontSize: 12, color: '#94a3b8', fontWeight: 600 }}>+{extra} more</span>
      ) : null}
    </>
  );
}

export function IocMetadataCards({
  confidenceCard,
  summary,
  canWrite,
  onEditConfidence,
  onEditThreatClass,
  onEditThreatActor,
  onEditMalwareFamily,
  ThreatClassificationBadges,
  ThreatActorBadges,
  MalwareFamilyBadges
}) {
  const classifications = getEffectiveThreatClassifications(summary);
  const actors = getThreatActorsFromSummary(summary);
  const families = getMalwareFamiliesFromSummary(summary);

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
      gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
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
          <div style={{ fontSize: 13, color: '#94a3b8' }}>Threat Actors</div>
          {canWrite ? (
            <button type="button" onClick={onEditThreatActor} style={editBtn} aria-label="Edit threat actors">Edit</button>
          ) : null}
        </div>
        <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {ThreatActorBadges ? (
            <ThreatActorBadges actors={actors} />
          ) : (
            <AttributionEntityBadges entities={actors} />
          )}
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 8 }}>
          <div style={{ fontSize: 13, color: '#94a3b8' }}>Malware Families</div>
          {canWrite && onEditMalwareFamily ? (
            <button type="button" onClick={onEditMalwareFamily} style={editBtn} aria-label="Edit malware families">Edit</button>
          ) : null}
        </div>
        <div style={{ fontSize: 15, fontWeight: 700, color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {MalwareFamilyBadges ? (
            <MalwareFamilyBadges families={families} />
          ) : (
            <AttributionEntityBadges entities={families} />
          )}
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
