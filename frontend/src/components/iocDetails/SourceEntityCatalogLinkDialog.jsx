import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  buildCatalogLinkRequest,
  catalogKindText,
  catalogLinkTarget,
  describeCandidateMatch,
  evidenceLine,
  interpretCatalogLinkError
} from '../../lib/sourceEntityCatalogLink.js';

const EVIDENCE_SHOWN = 5;

const box = {
  padding: 12,
  border: '1px solid #334155',
  borderRadius: 10,
  background: '#0f172a',
  minWidth: 0
};
const labelStyle = { fontSize: 12, fontWeight: 600, color: '#94a3b8' };
const muted = { fontSize: 12, color: '#94a3b8', lineHeight: 1.45 };
const inputStyle = {
  width: '100%',
  padding: '9px 11px',
  borderRadius: 8,
  border: '1px solid #334155',
  background: '#020617',
  color: '#e2e8f0',
  fontSize: 14,
  boxSizing: 'border-box'
};
const badge = (tone) => ({
  display: 'inline-flex',
  alignItems: 'center',
  padding: '1px 7px',
  borderRadius: 999,
  fontSize: 11,
  fontWeight: 700,
  whiteSpace: 'nowrap',
  border: `1px solid ${tone === 'exact' ? '#166534' : tone === 'warn' ? '#854d0e' : '#475569'}`,
  color: tone === 'exact' ? '#86efac' : tone === 'warn' ? '#fcd34d' : '#cbd5e1',
  background: tone === 'exact' ? 'rgba(34,197,94,0.12)' : tone === 'warn' ? 'rgba(234,179,8,0.12)' : 'transparent'
});

function tabStyle(active) {
  return {
    padding: '7px 12px',
    borderRadius: 8,
    border: `1px solid ${active ? '#6366f1' : '#334155'}`,
    background: active ? '#312e81' : '#111827',
    color: active ? '#e0e7ff' : '#cbd5e1',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer'
  };
}

function mergeCandidates(base, extra) {
  const seen = new Set();
  const out = [];
  for (const c of [...(extra || []), ...(base || [])]) {
    if (!c?.id || seen.has(String(c.id))) continue;
    seen.add(String(c.id));
    out.push(c);
  }
  return out;
}

/**
 * Resolve a source-reported Threat Actor / Malware Family label to the local
 * catalog: link an existing entry or (admins) create one, then link. Shared by
 * both entity kinds. The backend verifies the IOC's stored source evidence and
 * performs the authoritative duplicate check.
 *
 * Props: kind, entity (unlinked chip), summary (IOC), api, ModalOverlay, ui,
 * onClose(), onLinked(response), onRefresh().
 */
export function SourceEntityCatalogLinkDialog({
  kind,
  entity,
  summary,
  api,
  ModalOverlay,
  ui,
  onClose,
  onLinked,
  onRefresh
}) {
  const text = catalogKindText(kind);
  const target = catalogLinkTarget(entity);
  const label = target?.label || entity?.name || '';
  const iocId = Number(summary?.id);
  const observableType = String(summary?.observable_type || '').trim();

  const [ctx, setCtx] = useState(null);
  const [loadError, setLoadError] = useState('');
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [searching, setSearching] = useState(false);
  const [tab, setTab] = useState('link');
  const [selectedId, setSelectedId] = useState('');
  const [extraCandidates, setExtraCandidates] = useState([]);
  const [form, setForm] = useState({ name: label, aliases: '', description: '' });
  const [confirmDistinct, setConfirmDistinct] = useState(false);
  const [needsDistinct, setNeedsDistinct] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState(null);
  const searchRef = useRef(null);
  const seqRef = useRef(0);
  const submittingRef = useRef(false);

  async function fetchContext(q) {
    const seq = ++seqRef.current;
    const { data } = await api.get(`/ioc/${iocId}/source-attributions/catalog-candidates`, {
      params: { observable_type: observableType, entity_kind: kind, source_label: label, q: q || undefined }
    });
    return seq === seqRef.current ? data : null;
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setLoadError('');
      try {
        const data = await fetchContext('');
        if (cancelled || !data) return;
        setCtx(data);
        setForm((f) => ({ ...f, name: data.create_prefill?.name || f.name }));
      } catch (err) {
        if (!cancelled) setLoadError(interpretCatalogLinkError(err, kind).message);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })().catch(() => {});
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [iocId, observableType, kind, label]);

  // Errors render at the end of a scrolling body: bring them into view.
  const errorRef = useRef(null);
  useEffect(() => {
    if (submitError) {
      try { errorRef.current?.scrollIntoView?.({ block: 'nearest' }); } catch { /* ignore */ }
    }
  }, [submitError]);

  // The search box only exists once the context has loaded (after the modal's
  // own initial focus ran): move focus there for keyboard users.
  const ctxLoaded = Boolean(ctx);
  useEffect(() => {
    if (ctxLoaded) {
      try { searchRef.current?.focus({ preventScroll: true }); } catch { /* ignore */ }
    }
  }, [ctxLoaded]);

  // Debounced catalog search (server-side, bounded).
  useEffect(() => {
    if (!ctx) return undefined;
    const q = query.trim();
    const timer = setTimeout(async () => {
      setSearching(true);
      try {
        const data = await fetchContext(q);
        if (data) setCtx((prev) => ({ ...prev, candidates: data.candidates }));
      } catch {
        /* keep previous candidates; the analyst can retry the search */
      } finally {
        setSearching(false);
      }
    }, q ? 250 : 0);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query]);

  const candidates = useMemo(
    () => mergeCandidates(ctx?.candidates || [], extraCandidates),
    [ctx, extraCandidates]
  );
  const exactCandidates = candidates.filter((c) => c.exact);
  const canLink = Boolean(ctx?.permissions?.can_link);
  const canCreate = Boolean(ctx?.permissions?.can_create);
  const alreadyLinked = ctx?.link_state === 'linked';
  const selected = candidates.find((c) => String(c.id) === String(selectedId)) || null;

  async function submit() {
    if (submittingRef.current) return;
    const mode = tab === 'create' ? 'create' : 'link';
    if (mode === 'link' && !selected?.linkable) return;
    if (mode === 'create' && !form.name.trim()) return;
    submittingRef.current = true;
    setSubmitting(true);
    setSubmitError(null);
    try {
      const body = buildCatalogLinkRequest({
        summary,
        kind,
        label,
        mode,
        entityId: selected?.id || null,
        create: form,
        confirmDistinct: mode === 'create' && confirmDistinct
      });
      const { data } = await api.post(`/ioc/${iocId}/source-attributions/catalog-link`, body);
      if (!data?.success) {
        setSubmitError({ message: data?.error || 'Request failed — nothing was changed.' });
        return;
      }
      onLinked(data);
    } catch (err) {
      const info = interpretCatalogLinkError(err, kind);
      setSubmitError(info);
      if (info.candidates?.length) setExtraCandidates((prev) => mergeCandidates(prev, info.candidates));
      if (info.needsDistinctConfirmation) setNeedsDistinct(true);
      if (info.switchToLink) setTab('link');
    } finally {
      submittingRef.current = false;
      setSubmitting(false);
    }
  }

  const evidence = ctx?.evidence || [];
  const primaryDisabled = submitting || loading || !ctx || alreadyLinked || (tab === 'link'
    ? !canLink || !selected?.linkable
    : !canCreate || !form.name.trim() || (needsDistinct && !confirmDistinct));
  const primaryLabel = tab === 'create'
    ? (submitting ? 'Creating…' : 'Create and link')
    : (submitting ? 'Linking…' : 'Link');

  return (
    <ModalOverlay
      title={`Link ${text.title} to catalog`}
      size="md"
      initialFocusRef={searchRef}
      onClose={submitting ? null : onClose}
      footer={(
        <>
          <button type="button" data-modal-cancel style={ui.btn} onClick={onClose} disabled={submitting}>
            {alreadyLinked ? 'Close' : 'Cancel'}
          </button>
          {!alreadyLinked ? (
            <button type="button" style={ui.btnPrimary} onClick={() => submit().catch(() => {})} disabled={primaryDisabled}>
              {primaryLabel}
            </button>
          ) : null}
        </>
      )}
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minWidth: 0 }}>
        <div style={box}>
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 130px) minmax(0, 1fr)', gap: '6px 10px', fontSize: 13 }}>
            <span style={labelStyle}>Source-reported name</span>
            <span style={{ color: '#e2e8f0', fontWeight: 700, overflowWrap: 'anywhere' }}>{ctx?.source_label || label}</span>
            <span style={labelStyle}>Reported by</span>
            <span style={{ color: '#cbd5e1', overflowWrap: 'anywhere' }}>
              {loading ? 'Loading…' : evidence.length ? (
                <>
                  {evidence.slice(0, EVIDENCE_SHOWN).map((e) => (
                    <span key={`${e.feed_key}|${e.evidence_ref_type}|${e.evidence_ref_id}`} style={{ display: 'block' }}>
                      {e.evidence_url ? (
                        <a href={e.evidence_url} target="_blank" rel="noopener noreferrer" style={{ color: '#93c5fd' }}>{evidenceLine(e)}</a>
                      ) : evidenceLine(e)}
                    </span>
                  ))}
                  {(ctx?.evidence_total || evidence.length) > EVIDENCE_SHOWN ? (
                    <span style={muted}>+{(ctx?.evidence_total || evidence.length) - EVIDENCE_SHOWN} more</span>
                  ) : null}
                </>
              ) : '—'}
            </span>
          </div>
          <div style={{ ...muted, marginTop: 8 }}>
            Linking sets which catalog {text.noun} this label refers to. The association stays source-reported; it does not confirm the attribution.
          </div>
        </div>

        {loadError ? <div role="alert" style={{ color: '#fca5a5', fontSize: 13 }}>{loadError}</div> : null}

        {alreadyLinked ? (
          <div role="status" style={{ ...box, borderColor: '#166534', color: '#86efac', fontSize: 13 }}>
            Already linked to {(ctx?.linked_entities || []).map((e) => e.name).join(', ') || 'a catalog entry'}.{' '}
            <button type="button" style={{ ...ui.btnCompact, marginLeft: 6 }} onClick={() => { onRefresh?.(); onClose(); }}>Refresh</button>
          </div>
        ) : null}

        {ctx && !alreadyLinked ? (
          <>
            <div role="tablist" aria-label="Resolution" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button type="button" role="tab" aria-selected={tab === 'link'} style={tabStyle(tab === 'link')} onClick={() => setTab('link')}>
                Link existing
              </button>
              <button type="button" role="tab" aria-selected={tab === 'create'} style={tabStyle(tab === 'create')} onClick={() => setTab('create')}>
                Create new
              </button>
            </div>

            {tab === 'link' ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0 }}>
                <input
                  ref={searchRef}
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={`Search ${text.catalog} (name or alias)…`}
                  aria-label={`Search ${text.catalog} catalog`}
                  style={inputStyle}
                  maxLength={100}
                />
                {exactCandidates.length > 1 ? (
                  <div style={{ ...muted, color: '#fcd34d' }}>
                    Several catalog entries match exactly — choose the right one.
                  </div>
                ) : null}
                <div
                  role="radiogroup"
                  aria-label={`${text.catalog} candidates`}
                  style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 280, overflowY: 'auto', minWidth: 0 }}
                >
                  {candidates.map((c) => {
                    const checked = String(c.id) === String(selectedId);
                    const id = `catalog-cand-${c.id}`;
                    return (
                      <label
                        key={c.id}
                        htmlFor={id}
                        style={{
                          display: 'flex',
                          gap: 10,
                          alignItems: 'flex-start',
                          padding: '8px 10px',
                          borderRadius: 8,
                          border: `1px solid ${checked ? '#6366f1' : '#334155'}`,
                          background: checked ? 'rgba(99,102,241,0.12)' : '#111827',
                          cursor: c.linkable ? 'pointer' : 'not-allowed',
                          opacity: c.linkable ? 1 : 0.6,
                          minWidth: 0
                        }}
                      >
                        <input
                          id={id}
                          type="radio"
                          name="catalog-candidate"
                          value={c.id}
                          checked={checked}
                          disabled={!c.linkable || submitting}
                          onChange={() => setSelectedId(String(c.id))}
                          style={{ marginTop: 3, flexShrink: 0 }}
                        />
                        <span style={{ display: 'flex', flexDirection: 'column', gap: 3, minWidth: 0, flex: 1 }}>
                          <span style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center', minWidth: 0 }}>
                            <span style={{ color: '#e2e8f0', fontWeight: 700, fontSize: 13, overflowWrap: 'anywhere' }}>{c.name}</span>
                            <span style={badge(c.exact ? 'exact' : c.match === 'similar' ? 'warn' : 'plain')}>{describeCandidateMatch(c)}</span>
                            {c.attack_id && c.match !== 'attack_id' ? <span style={badge('plain')}>{c.attack_id}</span> : null}
                            {!c.active ? <span style={badge('warn')}>Disabled</span> : null}
                          </span>
                          {c.aliases?.length ? (
                            <span style={{ ...muted, fontSize: 11, overflowWrap: 'anywhere' }}>
                              Aliases: {c.aliases.slice(0, 6).join(', ')}{c.aliases.length > 6 ? ` +${c.aliases.length - 6}` : ''}
                            </span>
                          ) : null}
                        </span>
                      </label>
                    );
                  })}
                  {!candidates.length ? (
                    <div style={{ ...muted, padding: '6px 2px' }}>
                      {searching ? 'Searching…' : `No matching ${text.noun} in the catalog.`}{' '}
                      {!searching && canCreate ? (
                        <button type="button" style={{ ...ui.btnCompact, marginLeft: 4 }} onClick={() => setTab('create')}>Create new</button>
                      ) : null}
                      {!searching && !canCreate ? 'Search by another name or alias, or ask an administrator to add it.' : null}
                    </div>
                  ) : null}
                </div>
                {!canLink ? <div style={muted}>Your role cannot link catalog entries.</div> : null}
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minWidth: 0 }}>
                {!canCreate ? (
                  <div role="note" style={{ ...box, borderColor: '#854d0e', color: '#fcd34d', fontSize: 13 }}>
                    Creating catalog entries requires an administrator. Link an existing {text.noun} instead, or ask an administrator to add it.
                  </div>
                ) : null}
                {exactCandidates.length ? (
                  <div role="note" style={{ ...box, borderColor: '#854d0e', color: '#fcd34d', fontSize: 13 }}>
                    Exact match already in the catalog: {exactCandidates.map((c) => c.name).join(', ')}.{' '}
                    <button type="button" style={{ ...ui.btnCompact, marginLeft: 4 }} onClick={() => setTab('link')}>Link existing</button>
                  </div>
                ) : null}
                <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={labelStyle}>Name</span>
                  <input
                    type="text"
                    value={form.name}
                    onChange={(e) => { setForm((f) => ({ ...f, name: e.target.value })); setNeedsDistinct(false); setConfirmDistinct(false); }}
                    disabled={!canCreate || submitting}
                    maxLength={kind === 'threat_actor' ? 100 : 128}
                    style={inputStyle}
                  />
                </label>
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 130px) minmax(0, 1fr)', gap: '4px 10px', fontSize: 13 }}>
                  <span style={labelStyle}>Type</span>
                  <span style={{ color: '#cbd5e1' }}>{text.title}</span>
                  <span style={labelStyle}>Origin</span>
                  <span style={{ color: '#cbd5e1', overflowWrap: 'anywhere' }}>
                    {[...new Set(evidence.map((e) => e.source_name).filter(Boolean))].join(', ') || 'Source'} label “{ctx?.source_label || label}” on this IOC (kept in its evidence and audit history)
                  </span>
                </div>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={labelStyle}>Aliases (optional, comma-separated)</span>
                  <input
                    type="text"
                    value={form.aliases}
                    onChange={(e) => { setForm((f) => ({ ...f, aliases: e.target.value })); setNeedsDistinct(false); setConfirmDistinct(false); }}
                    disabled={!canCreate || submitting}
                    style={inputStyle}
                  />
                </label>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span style={labelStyle}>Description (optional)</span>
                  <textarea
                    value={form.description}
                    onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                    disabled={!canCreate || submitting}
                    rows={3}
                    maxLength={4000}
                    style={{ ...inputStyle, resize: 'vertical', minHeight: 64 }}
                  />
                </label>
                {needsDistinct && submitError?.candidates?.length ? (
                  <div role="note" style={{ ...box, borderColor: '#854d0e', fontSize: 13, color: '#fcd34d' }}>
                    Similar in the catalog:{' '}
                    {submitError.candidates.map((c) => `${c.name}${c.active === false ? ' (disabled)' : ''}`).join(', ')}
                  </div>
                ) : null}
                {needsDistinct ? (
                  <label style={{ display: 'inline-flex', alignItems: 'flex-start', gap: 8, fontSize: 13, color: '#fcd34d', cursor: 'pointer' }}>
                    <input type="checkbox" checked={confirmDistinct} onChange={(e) => setConfirmDistinct(e.target.checked)} disabled={submitting} style={{ marginTop: 3 }} />
                    <span>I checked the similar entries above (Link existing) — this is a distinct {text.noun}.</span>
                  </label>
                ) : null}
              </div>
            )}
          </>
        ) : null}

        {submitError ? (
          <div ref={errorRef} role="alert" style={{ color: '#fca5a5', fontSize: 13, lineHeight: 1.45 }}>
            {submitError.message}
            {submitError.refresh ? (
              <button type="button" style={{ ...ui.btnCompact, marginLeft: 8 }} onClick={() => { onRefresh?.(); onClose(); }}>Refresh</button>
            ) : null}
          </div>
        ) : null}
      </div>
    </ModalOverlay>
  );
}
