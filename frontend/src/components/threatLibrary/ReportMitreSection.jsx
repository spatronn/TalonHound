import React, { useMemo, useState } from 'react';
import { api } from '../../lib/api.js';
import { formatMitreConfidence, groupMitreByTactic, normalizeMitreMappings } from './reportMitre.js';

/**
 * Overview MITRE ATT&CK mappings. Hidden when empty unless the analyst can add.
 */
export default function ReportMitreSection({ reportId, mappings, canWrite, disabled, onChange, onError }) {
  const items = useMemo(() => normalizeMitreMappings(mappings), [mappings]);
  const groups = useMemo(() => groupMitreByTactic(items), [items]);
  const [openId, setOpenId] = useState(null);
  const [addOpen, setAddOpen] = useState(false);
  const [techniqueId, setTechniqueId] = useState('');
  const [saving, setSaving] = useState(false);
  const busy = Boolean(disabled) || saving;

  if (!items.length && !canWrite) return null;

  async function mutate(request) {
    setSaving(true);
    try {
      const { data } = await request();
      onChange?.(normalizeMitreMappings(data?.mitre_attack));
    } catch (err) {
      onError?.(err?.response?.data?.message || 'Failed to update ATT&CK mapping');
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="tl-intel" data-testid="report-mitre">
      <h2 className="tl-heading">
        MITRE ATT&amp;CK
        {items.length ? <span className="tl-heading__count">{'\u00b7'} {items.length}</span> : null}
      </h2>
      {groups.length ? (
        <div className="tl-mitre">
          {groups.map((group) => (
            <div key={group.id || 'unmapped'} className="tl-mitre__tactic" data-tactic={group.id || 'unmapped'}>
              <h3 className="tl-mitre__tactic-name">{group.name}</h3>
              <ul className="tl-mitre__list">
                {group.items.map((m) => {
                  const expanded = openId === m.technique_id;
                  return (
                    <li key={`${group.id}-${m.technique_id}`} className="tl-mitre__item">
                      <button
                        type="button"
                        className="tl-mitre__row"
                        data-technique-id={m.technique_id}
                        aria-expanded={expanded}
                        onClick={() => setOpenId(expanded ? null : m.technique_id)}
                      >
                        <span className="tl-mitre__id">{m.technique_id}</span>
                        <span className="tl-mitre__name">{m.technique_name ? `— ${m.technique_name}` : ''}</span>
                      </button>
                      {expanded ? (
                        <div className="tl-mitre__detail">
                          {m.tactics.length ? (
                            <div className="tl-mitre__meta">
                              Tactic{m.tactics.length > 1 ? 's' : ''}: {m.tactics.map((t) => t.name).join(', ')}
                            </div>
                          ) : null}
                          {formatMitreConfidence(m.confidence) ? (
                            <div className="tl-mitre__meta">Confidence {formatMitreConfidence(m.confidence)}</div>
                          ) : null}
                          {m.evidence ? <blockquote className="tl-quote">{m.evidence}</blockquote> : null}
                          {canWrite ? (
                            <button
                              type="button"
                              className="tl-ghost-btn"
                              disabled={busy}
                              onClick={() => mutate(() => api.delete(`/threat-library/reports/${reportId}/mitre/${encodeURIComponent(m.technique_id)}`))}
                            >
                              Remove
                            </button>
                          ) : null}
                        </div>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>
      ) : (
        <div className="tl-intel__empty">No ATT&amp;CK mappings yet.</div>
      )}
      {canWrite ? (
        <div className="tl-mitre__add">
          {addOpen ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const id = techniqueId.trim();
                if (!id) return;
                setAddOpen(false);
                setTechniqueId('');
                mutate(() => api.post(`/threat-library/reports/${reportId}/mitre`, { technique_id: id }));
              }}
            >
              <input
                value={techniqueId}
                onChange={(e) => setTechniqueId(e.target.value)}
                placeholder="T1566.002"
                aria-label="ATT&CK technique ID"
                autoFocus
                className="tl-mitre__input"
              />
              <button type="submit" className="tl-ghost-btn" disabled={busy || !techniqueId.trim()}>Add</button>
              <button type="button" className="tl-ghost-btn" onClick={() => { setAddOpen(false); setTechniqueId(''); }}>Cancel</button>
            </form>
          ) : (
            <button type="button" className="tl-ghost-btn" disabled={busy} onClick={() => setAddOpen(true)}>
              + Technique
            </button>
          )}
        </div>
      ) : null}
    </section>
  );
}
