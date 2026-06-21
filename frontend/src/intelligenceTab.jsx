import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from './lib/api.js';
import {
  analystConfidenceLabel,
  assessmentImpactLabel,
  assessmentImpactStyle,
  confidenceBadgeStyleAnalyst,
  referenceTypeBadgeStyle,
  referenceTypeLabel,
  tlpBadgeStyle,
  tlpLabel
} from './lib/analystIntelligenceLabels.js';
import {
  computeAnalystRefsSummary,
  computeInfrastructureSummary,
  computeOverallSignal,
  computeProviderCoverage,
  computeReputationSummary,
  providerStateLabel,
  providerStateStyle,
  signalToneStyle
} from './lib/intelligenceSummary.js';
import {
  buildAnalystReferencePayload,
  EMPTY_ANALYST_REFERENCE_FORM,
  toAnalystReferenceForm
} from './lib/analystIntelligenceForm.js';
import { isProviderApplicable } from './lib/iocProviderApplicability.js';

const sectionTitleStyle = { fontWeight: 700, color: '#e2e8f0', fontSize: 16 };
const sectionDescStyle = { color: '#94a3b8', fontSize: 12, marginTop: 4 };
const sectionShellStyle = { border: '1px solid #334155', borderRadius: 12, padding: 14, background: '#0f172a' };
const summaryCardStyle = {
  border: '1px solid #334155',
  borderRadius: 10,
  padding: '10px 12px',
  background: '#0b1220',
  minWidth: 0
};

function badgeEl(label, style) {
  return (
    <span style={{
      display: 'inline-block',
      border: `1px solid ${style.border}`,
      background: style.bg,
      color: style.color,
      borderRadius: 999,
      padding: '3px 8px',
      fontSize: 11,
      fontWeight: 600,
      whiteSpace: 'nowrap'
    }}
    >
      {label}
    </span>
  );
}

export function IntelligenceSummarySection({ providerSnapshots, analystSummary, iocType, rdapEligible = false }) {
  const vtSnap = providerSnapshots?.virustotal || {};
  const abuseSnap = providerSnapshots?.abuseipdb || {};
  const ipinfoSnap = providerSnapshots?.ipinfo || {};
  const rdapSnap = providerSnapshots?.rdap || {};

  const showAbuse = isProviderApplicable('abuseipdb', iocType);
  const showIpinfo = isProviderApplicable('ipinfo', iocType);
  const showRdap = isProviderApplicable('rdap', iocType, { rdapEligible });

  const overall = computeOverallSignal({
    vt: vtSnap.status === 'success' ? {
      status: 'success',
      malicious: vtSnap.malicious,
      suspicious: vtSnap.suspicious,
      detected: vtSnap.detected,
      stats: vtSnap.stats
    } : null,
    abuseipdb: showAbuse && abuseSnap.status === 'success' ? { status: 'success', score: abuseSnap.score } : null
  });
  const reputation = computeReputationSummary({
    vt: vtSnap.status === 'success' ? { status: 'success', detected: vtSnap.detected, total: vtSnap.total } : null,
    abuseipdb: showAbuse && abuseSnap.status === 'success' ? { status: 'success', score: abuseSnap.score } : null
  });
  const infrastructure = computeInfrastructureSummary({
    ipinfo: showIpinfo && ipinfoSnap.status === 'success' ? ipinfoSnap : null,
    abuseipdb: showAbuse && abuseSnap.status === 'success' ? abuseSnap : null,
    rdap: showRdap && rdapSnap.status === 'success' ? rdapSnap : null
  });
  const coverage = computeProviderCoverage(providerSnapshots, { iocType, rdapEligible });
  const analystRefs = computeAnalystRefsSummary(analystSummary);
  const tone = signalToneStyle(overall.tone);

  return (
    <div style={sectionShellStyle}>
      <div style={{ marginBottom: 12 }}>
        <div style={sectionTitleStyle}>Intelligence Summary</div>
        <div style={sectionDescStyle}>At-a-glance signal from automated enrichment and analyst references.</div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10 }}>
        <div style={summaryCardStyle}>
          <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 6 }}>Overall signal</div>
          <div style={{ fontWeight: 700, color: tone.color }}>{overall.label}</div>
        </div>
        <div style={summaryCardStyle}>
          <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 6 }}>Reputation</div>
          {reputation.length ? reputation.map((r) => (
            <div key={r.label} style={{ fontSize: 13, color: '#e2e8f0' }}>{r.label}: <b>{r.value}</b></div>
          )) : <div style={{ color: '#94a3b8', fontSize: 13 }}>No reputation data</div>}
        </div>
        <div style={summaryCardStyle}>
          <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 6 }}>Infrastructure</div>
          <div style={{ fontSize: 12, color: '#cbd5e1', lineHeight: 1.45, overflowWrap: 'anywhere' }}>{infrastructure}</div>
        </div>
        <div style={summaryCardStyle}>
          <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 6 }}>Provider coverage</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {coverage.map((p) => {
              const st = providerStateStyle(p.state);
              return (
                <span key={p.key} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, color: st.color }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: st.dot, display: 'inline-block' }} />
                  {p.label}: {providerStateLabel(p.state)}
                </span>
              );
            })}
          </div>
        </div>
        <div style={summaryCardStyle}>
          <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 6 }}>Analyst refs</div>
          <div style={{ fontSize: 13, color: '#e2e8f0', fontWeight: 600 }}>{analystRefs}</div>
        </div>
      </div>
    </div>
  );
}

function AnalystReferenceFormModal({ open, formSeedKey, initialForm, isEdit = false, saving, error, onClose, onSave }) {
  const [form, setForm] = useState(initialForm);

  useEffect(() => {
    if (open) setForm(initialForm);
  }, [open, formSeedKey, initialForm]);

  if (!open) return null;

  function setField(field, value) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,0.72)', zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: 'min(640px, 100%)', maxHeight: '90vh', overflow: 'auto', background: '#0f172a', border: '1px solid #334155', borderRadius: 12, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div style={{ fontWeight: 700, color: '#e2e8f0' }}>{isEdit ? 'Edit Reference' : 'Add Reference'}</div>
          <button type="button" onClick={onClose}>Close</button>
        </div>
        {error ? <div style={{ color: '#fca5a5', marginBottom: 10, fontSize: 13 }}>{error}</div> : null}
        <div style={{ display: 'grid', gap: 10 }}>
          <label style={{ display: 'grid', gap: 4 }}>
            <span style={{ fontSize: 12, color: '#94a3b8' }}>Title *</span>
            <input value={form.title} maxLength={200} onChange={(e) => setField('title', e.target.value)} />
          </label>
          <label style={{ display: 'grid', gap: 4 }}>
            <span style={{ fontSize: 12, color: '#94a3b8' }}>URL</span>
            <input value={form.url || ''} onChange={(e) => setField('url', e.target.value)} placeholder="https://..." />
          </label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10 }}>
            <label style={{ display: 'grid', gap: 4 }}>
              <span style={{ fontSize: 12, color: '#94a3b8' }}>Reference type</span>
              <select value={form.reference_type} onChange={(e) => setField('reference_type', e.target.value)}>
                <option value="social">Social / X</option>
                <option value="free_ti">Free TI platform</option>
                <option value="vendor_report">Vendor report</option>
                <option value="sandbox">Sandbox</option>
                <option value="blog">Blog</option>
                <option value="internal_note">Internal note</option>
                <option value="other">Other</option>
              </select>
            </label>
            <label style={{ display: 'grid', gap: 4 }}>
              <span style={{ fontSize: 12, color: '#94a3b8' }}>TLP</span>
              <select value={form.tlp} onChange={(e) => setField('tlp', e.target.value)}>
                <option value="clear">TLP:CLEAR</option>
                <option value="green">TLP:GREEN</option>
                <option value="amber">TLP:AMBER</option>
                <option value="red">TLP:RED</option>
              </select>
            </label>
            <label style={{ display: 'grid', gap: 4 }}>
              <span style={{ fontSize: 12, color: '#94a3b8' }}>Confidence</span>
              <select value={form.confidence} onChange={(e) => setField('confidence', e.target.value)}>
                <option value="unknown">Unknown</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </label>
            <label style={{ display: 'grid', gap: 4 }}>
              <span style={{ fontSize: 12, color: '#94a3b8' }}>Assessment impact</span>
              <select value={form.assessment_impact} onChange={(e) => setField('assessment_impact', e.target.value)}>
                <option value="supports_malicious">Supports malicious</option>
                <option value="supports_benign">Supports benign / FP</option>
                <option value="context_only">Context only</option>
                <option value="needs_review">Needs review</option>
              </select>
            </label>
          </div>
          <label style={{ display: 'grid', gap: 4 }}>
            <span style={{ fontSize: 12, color: '#94a3b8' }}>Note</span>
            <textarea rows={4} maxLength={4000} value={form.note || ''} onChange={(e) => setField('note', e.target.value)} />
          </label>
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 14 }}>
          <button type="button" onClick={onClose}>Cancel</button>
          <button type="button" disabled={saving || !String(form.title || '').trim()} onClick={() => onSave(form)}>
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}

export function AnalystIntelligenceSection({ iocId, canWrite, active, onSummaryChange, formatUserDateTime }) {
  const [items, setItems] = useState([]);
  const [summary, setSummary] = useState({ total_count: 0, supports_malicious_count: 0 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  const modalFormSeedKey = editing?.id || 'create';
  const modalInitialForm = useMemo(
    () => (editing ? toAnalystReferenceForm(editing) : { ...EMPTY_ANALYST_REFERENCE_FORM }),
    [modalFormSeedKey, modalOpen]
  );

  const load = useCallback(async () => {
    if (!iocId || !active) return;
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get(`/ioc/${iocId}/analyst-intelligence`);
      setItems(data?.items || []);
      const nextSummary = data?.summary || { total_count: 0, supports_malicious_count: 0 };
      setSummary(nextSummary);
      onSummaryChange?.(nextSummary);
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to load analyst intelligence');
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, [iocId, active, onSummaryChange]);

  useEffect(() => {
    load().catch(() => {});
  }, [load]);

  async function handleSave(form) {
    setSaving(true);
    setFormError('');
    const payload = buildAnalystReferencePayload(form);
    try {
      if (editing?.id) {
        const { data: updated } = await api.put(`/ioc/${iocId}/analyst-intelligence/${editing.id}`, payload);
        setItems((prev) => prev.map((it) => (it.id === updated.id ? updated : it)));
      } else {
        const { data: created } = await api.post(`/ioc/${iocId}/analyst-intelligence`, payload);
        setItems((prev) => [created, ...prev]);
      }
      setModalOpen(false);
      setEditing(null);
      await load();
    } catch (err) {
      setFormError(err?.response?.data?.message || 'Failed to save reference');
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(item) {
    if (!window.confirm(`Delete reference "${item.title}"?`)) return;
    try {
      await api.delete(`/ioc/${iocId}/analyst-intelligence/${item.id}`);
      await load();
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to delete reference');
    }
  }

  return (
    <div style={sectionShellStyle}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, marginBottom: 12 }}>
        <div>
          <div style={sectionTitleStyle}>Analyst Intelligence</div>
          <div style={sectionDescStyle}>External references, OSINT findings, and analyst-added context for this IOC.</div>
        </div>
        {canWrite ? (
          <button type="button" onClick={() => { setEditing(null); setModalOpen(true); }}>+ Add Reference</button>
        ) : null}
      </div>

      {loading ? <div style={{ color: '#94a3b8', fontSize: 13 }}>Loading analyst intelligence…</div> : null}
      {error ? <div style={{ color: '#fca5a5', fontSize: 13, marginBottom: 8 }}>{error}</div> : null}

      {!loading && !items.length ? (
        <div style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.5, padding: '8px 0' }}>
          No analyst intelligence added yet. Add a public TI lookup, social post, vendor report, sandbox result, blog, or internal note.
        </div>
      ) : null}

      <div style={{ display: 'grid', gap: 10 }}>
        {items.map((item) => (
          <div key={item.id} style={{ border: '1px solid #334155', borderRadius: 10, padding: 12, background: '#0b1220' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'flex-start' }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 700, color: '#e2e8f0', overflowWrap: 'anywhere' }}>{item.title}</div>
                {item.url ? (
                  <a href={item.url} target="_blank" rel="noopener noreferrer" style={{ display: 'inline-block', marginTop: 4, fontSize: 12, color: '#93c5fd', overflowWrap: 'anywhere' }}>
                    Open reference
                  </a>
                ) : null}
              </div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                {badgeEl(referenceTypeLabel(item.reference_type), referenceTypeBadgeStyle(item.reference_type))}
                {badgeEl(tlpLabel(item.tlp), tlpBadgeStyle(item.tlp))}
                {badgeEl(analystConfidenceLabel(item.confidence), confidenceBadgeStyleAnalyst(item.confidence))}
                {badgeEl(assessmentImpactLabel(item.assessment_impact), assessmentImpactStyle(item.assessment_impact))}
              </div>
            </div>
            {item.note ? <div style={{ marginTop: 8, fontSize: 13, color: '#cbd5e1', lineHeight: 1.45, overflowWrap: 'anywhere' }}>{item.note}</div> : null}
            <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center', fontSize: 12, color: '#94a3b8' }}>
              <span>Added by {item.created_by_username || 'unknown'}</span>
              <span>{formatUserDateTime(item.created_at)}</span>
              {item.updated_at ? <span>Updated {formatUserDateTime(item.updated_at)}</span> : null}
            </div>
            {canWrite ? (
              <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
                <button type="button" onClick={() => { setEditing(item); setModalOpen(true); }}>Edit</button>
                <button type="button" onClick={() => handleDelete(item)}>Delete</button>
              </div>
            ) : null}
          </div>
        ))}
      </div>

      <AnalystReferenceFormModal
        open={modalOpen}
        formSeedKey={modalFormSeedKey}
        initialForm={modalInitialForm}
        isEdit={Boolean(editing?.id)}
        saving={saving}
        error={formError}
        onClose={() => { setModalOpen(false); setEditing(null); setFormError(''); }}
        onSave={handleSave}
      />
    </div>
  );
}

export function SourceEvidenceSection({ sources, formatUserDateTime, sanitizeSourceNote }) {
  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, overflowX: 'auto' }}>
      <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>Source Evidence</div>
      <table className="ioc-table" width="100%" cellPadding="8" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', minWidth: 760, fontSize: 12 }}>
        <thead>
          <tr style={{ textAlign: 'left', background: '#111827' }}>
            <th>Source</th><th>URL</th><th>Confidence</th><th>Category</th><th>Note</th><th>Created At</th>
          </tr>
        </thead>
        <tbody>
          {(sources || []).map((s) => (
            <tr key={`${s.id}-${s.created_at}`} style={{ borderTop: '1px solid #334155' }}>
              <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{s.source_name || '-'}</td>
              <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{s.source_url || '-'}</td>
              <td>{s.confidence || '-'}</td>
              <td>{s.category || '-'}</td>
              <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{sanitizeSourceNote(s.note)}</td>
              <td>{formatUserDateTime(s.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function IntelligenceTabPanel({
  iocId,
  iocValue,
  iocType,
  active,
  canWrite,
  isAdmin,
  sources,
  formatUserDateTime,
  sanitizeSourceNote,
  isRdapEligible,
  isHashObservable,
  hasMeaningfulFileInfo,
  fileInformation,
  VirusTotalEnrichmentCard,
  IpEnrichmentCard,
  AbuseIpdbEnrichmentCard,
  RdapEnrichmentCard
}) {
  const [providerSnapshots, setProviderSnapshots] = useState({});
  const [analystSummary, setAnalystSummary] = useState({ total_count: 0, supports_malicious_count: 0 });

  useEffect(() => {
    setProviderSnapshots({});
  }, [iocId, iocType]);

  const showVt = isProviderApplicable('virustotal', iocType);
  const showAbuse = isProviderApplicable('abuseipdb', iocType);
  const showIpinfo = isProviderApplicable('ipinfo', iocType);
  const showRdap = isProviderApplicable('rdap', iocType, { rdapEligible: isRdapEligible });

  const onProviderSnapshot = useCallback((provider, snapshot) => {
    setProviderSnapshots((prev) => {
      const next = { ...prev, [provider]: snapshot };
      return next;
    });
  }, []);

  const providerGridStyle = useMemo(() => ({
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
    gap: 12
  }), []);

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <IntelligenceSummarySection
        providerSnapshots={providerSnapshots}
        analystSummary={analystSummary}
        iocType={iocType}
        rdapEligible={isRdapEligible}
      />

      <div style={sectionShellStyle}>
        <div style={{ marginBottom: 12 }}>
          <div style={sectionTitleStyle}>Automated Intelligence</div>
          <div style={sectionDescStyle}>Provider-backed enrichment and reputation checks.</div>
        </div>
        <div style={providerGridStyle}>
          {showVt ? (
            <VirusTotalEnrichmentCard iocId={iocId} active={active} compact onSnapshot={(snap) => onProviderSnapshot('virustotal', snap)} />
          ) : null}
          {showAbuse ? (
            <AbuseIpdbEnrichmentCard iocValue={iocValue} iocType={iocType} active={active} canRefresh={canWrite} isAdmin={isAdmin} compact onSnapshot={(snap) => onProviderSnapshot('abuseipdb', snap)} />
          ) : null}
          {showIpinfo ? (
            <IpEnrichmentCard iocValue={iocValue} iocType={iocType} active={active} isAdmin={isAdmin} compact onSnapshot={(snap) => onProviderSnapshot('ipinfo', snap)} />
          ) : null}
          {showRdap ? (
            <RdapEnrichmentCard iocValue={iocValue} iocType={iocType} active={active} isAdmin={isAdmin} compact onSnapshot={(snap) => onProviderSnapshot('rdap', snap)} />
          ) : null}
        </div>
      </div>

      <AnalystIntelligenceSection
        iocId={iocId}
        canWrite={canWrite}
        active={active}
        onSummaryChange={setAnalystSummary}
        formatUserDateTime={formatUserDateTime}
      />

      {isHashObservable && hasMeaningfulFileInfo ? (
        <div style={{ border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>File Information</div>
          <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', fontSize: 13 }}>
            <tbody>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>File Name</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fileInformation.file_name || '-'}</td></tr>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>File Type</th><td>{fileInformation.file_type || '-'}</td></tr>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>MIME</th><td>{fileInformation.mime || '-'}</td></tr>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>MD5</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fileInformation.md5 || '-'}</td></tr>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SHA1</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fileInformation.sha1 || '-'}</td></tr>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SHA256</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fileInformation.sha256 || '-'}</td></tr>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>IMPHASH</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fileInformation.imphash || '-'}</td></tr>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>TLSH</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fileInformation.tlsh || '-'}</td></tr>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SSDEEP</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fileInformation.ssdeep || '-'}</td></tr>
            </tbody>
          </table>
        </div>
      ) : null}

      <SourceEvidenceSection sources={sources} formatUserDateTime={formatUserDateTime} sanitizeSourceNote={sanitizeSourceNote} />
    </div>
  );
}
