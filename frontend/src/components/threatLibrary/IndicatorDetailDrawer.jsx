import React, { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { describeCandidateDetail } from './candidateDetail.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import {
  assessmentTone,
  matchStateTone,
  promotionOutcomeTone,
  reviewStatusTone
} from './reportDisplayLabels.js';
import { CopyValueButton, SectionTitle, ToneBadge } from './reportPageParts.jsx';
import { ui } from './styles.js';

function toneFor(field) {
  if (field.key === 'assessment') return assessmentTone(field.raw);
  if (field.key === 'review_status') return reviewStatusTone(field.raw);
  if (field.key === 'match') return matchStateTone(field.raw);
  if (field.key === 'ioc_result') return promotionOutcomeTone(field.raw);
  return null;
}

/**
 * Right-side detail panel for one indicator row. Reads the same candidate
 * object the table renders; review actions route through the page's
 * `onReview(action, [id])` so semantics stay identical to the bulk toolbar.
 */
export default function IndicatorDetailDrawer({ candidate, onClose, canWrite, busy, onReview }) {
  const panelRef = useRef(null);
  const open = Boolean(candidate);

  useEffect(() => {
    if (!open) return undefined;
    function onKey(e) {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose?.();
      }
    }
    document.addEventListener('keydown', onKey, true);
    return () => document.removeEventListener('keydown', onKey, true);
  }, [open, onClose]);

  useEffect(() => {
    if (open && panelRef.current) {
      try { panelRef.current.focus({ preventScroll: true }); } catch { /* ignore */ }
    }
  }, [open, candidate?.id]);

  if (!open || typeof document === 'undefined') return null;

  const d = describeCandidateDetail(candidate, { formatDateTime: formatUserDateTime });
  const reviewActions = canWrite && typeof onReview === 'function';
  const title = `${d.typeLabel || 'Indicator'} ${d.value}`;

  return createPortal(
    <>
      <div className="tl-drawer-backdrop" role="presentation" onClick={() => onClose?.()} />
      <aside
        ref={panelRef}
        className="tl-drawer"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        data-testid="indicator-drawer"
      >
        <div className="tl-drawer__head">
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: '#64748b', marginBottom: 4 }}>
              {d.typeLabel || 'Indicator'}
            </div>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
              {/* Inert text by design: never an anchor, even for URLs. */}
              <span className="tl-value" style={{ fontSize: 14, fontWeight: 600 }}>{d.value || '—'}</span>
              {d.value ? <CopyValueButton value={d.value} label="Copy indicator" /> : null}
            </div>
          </div>
          <button
            type="button"
            onClick={() => onClose?.()}
            aria-label="Close details"
            style={{ ...ui.btn, minHeight: 30, padding: '4px 10px', fontSize: 12 }}
          >
            Close
          </button>
        </div>

        <div className="tl-drawer__body">
          <div className="tl-drawer__section">
            <dl className="tl-dl">
              {d.fields.map((f) => {
                const tone = toneFor(f);
                return (
                  <React.Fragment key={f.key}>
                    <dt>{f.label}</dt>
                    <dd className={f.mono ? 'is-mono' : undefined} data-field={f.key}>
                      {tone ? <ToneBadge tone={tone}>{f.value}</ToneBadge> : f.value}
                    </dd>
                  </React.Fragment>
                );
              })}
            </dl>
          </div>

          <div className="tl-drawer__section">
            <SectionTitle>Evidence</SectionTitle>
            <div style={{ fontSize: 13, color: '#e2e8f0' }}>
              {d.evidence.assertion}
              {d.evidence.declaredType ? <span style={{ color: '#94a3b8' }}> · {d.evidence.declaredType}</span> : null}
              {d.evidence.decision ? <span style={{ color: '#94a3b8' }}> · {d.evidence.decision}</span> : null}
              {!d.evidence.direct ? <span style={{ color: '#fbbf24' }}> · derived</span> : null}
            </div>
            {d.evidence.description ? <div style={{ fontSize: 13, color: '#cbd5e1', marginTop: 4 }}>{d.evidence.description}</div> : null}
            {d.evidence.resolution ? (
              <div style={{ fontSize: 12, color: '#fbbf24', marginTop: 4 }}>
                {d.evidence.resolution.label}
                {d.evidence.resolution.detail ? <span style={{ color: '#94a3b8' }}> · {d.evidence.resolution.detail}</span> : null}
              </div>
            ) : null}
            <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
              {d.evidence.occurrenceCount} occurrence{d.evidence.occurrenceCount === 1 ? '' : 's'}
              {d.evidence.ports ? ` · port ${d.evidence.ports}` : ''}
              {d.evidence.urlHost ? ` · host ${d.evidence.urlHost} (URL metadata)` : ''}
            </div>
            {d.evidence.text ? <blockquote className="tl-quote">{d.evidence.text}</blockquote> : null}
          </div>

          {d.tableRows.length ? (
            <div className="tl-drawer__section">
              <SectionTitle>Table references</SectionTitle>
              {d.tableRows.map((r) => (
                <div key={r.key} style={{ fontSize: 12, marginBottom: 6 }}>
                  <div style={{ color: '#e2e8f0' }}>{r.label}</div>
                  {r.description ? <div style={{ color: '#94a3b8' }}>{r.description}</div> : null}
                </div>
              ))}
            </div>
          ) : null}

          {d.occurrences.length ? (
            <div className="tl-drawer__section">
              <SectionTitle>Occurrences</SectionTitle>
              {d.occurrences.map((o) => (
                <div key={o.key} style={{ marginBottom: 10 }}>
                  <div style={{ fontSize: 12, color: '#e2e8f0' }}>{o.label}</div>
                  {o.text ? <blockquote className="tl-quote">{o.text}</blockquote> : null}
                </div>
              ))}
            </div>
          ) : null}
        </div>

        {reviewActions ? (
          <div className="tl-drawer__foot">
            <button type="button" style={ui.btn} disabled={Boolean(busy)} onClick={() => onReview('approve', [candidate.id])}>Approve</button>
            <button type="button" style={ui.btn} disabled={Boolean(busy)} onClick={() => onReview('context_only', [candidate.id])}>Context only</button>
            <button type="button" style={ui.btn} disabled={Boolean(busy)} onClick={() => onReview('ignore', [candidate.id])}>Ignore</button>
          </div>
        ) : null}
      </aside>
    </>,
    document.body
  );
}
