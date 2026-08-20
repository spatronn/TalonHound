import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from './lib/api.js';
import { useAppConfirm } from './lib/appChromeContext.jsx';
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
  computeLayeredProviderCoverage,
  computeProviderCoverage,
  providerStateLabel,
  providerStateStyle
} from './lib/intelligenceSummary.js';
import {
  buildAnalystReferencePayload,
  EMPTY_ANALYST_REFERENCE_FORM,
  toAnalystReferenceForm
} from './lib/analystIntelligenceForm.js';
import { getDerivedInfrastructureContext, isDerivedProviderApplicable, isProviderApplicable } from './lib/iocProviderApplicability.js';

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
const summaryLayoutStyle = {
  display: 'flex',
  flexWrap: 'wrap',
  gap: 10,
  alignItems: 'stretch'
};
const summaryCoverageCardStyle = {
  ...summaryCardStyle,
  flex: '2 1 280px'
};
const summaryRefsCardStyle = {
  ...summaryCardStyle,
  flex: '1 1 140px',
  maxWidth: '100%'
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

function ProviderCoverageBadges({ coverage }) {
  if (!coverage?.length) {
    return <div style={{ color: '#64748b', fontSize: 11 }}>None</div>;
  }
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
      {coverage.map((p) => {
        const st = providerStateStyle(p.state);
        const caption = providerStateLabel(p.state);
        return (
          <span key={p.key} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, color: st.color }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: st.dot, display: 'inline-block' }} />
            {p.label}: {caption}
          </span>
        );
      })}
    </div>
  );
}

export function IntelligenceSummarySection({
  providerSnapshots,
  derivedProviderSnapshots,
  derivedContext,
  analystSummary,
  iocType,
  rdapEligible = false
}) {
  const layeredCoverage = computeLayeredProviderCoverage({
    directSnapshots: providerSnapshots,
    derivedSnapshots: derivedProviderSnapshots,
    iocType,
    rdapEligible,
    derivedContext
  });
  const analystRefs = computeAnalystRefsSummary(analystSummary);
  const hasDerivedCoverage = Boolean(layeredCoverage.derived?.length);

  return (
    <div style={sectionShellStyle}>
      <div style={{ marginBottom: 12 }}>
        <div style={sectionTitleStyle}>Intelligence Summary</div>
        <div style={sectionDescStyle}>At-a-glance provider coverage and analyst references.</div>
      </div>
      <div style={summaryLayoutStyle}>
        <div style={summaryCoverageCardStyle}>
          <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 6 }}>Provider coverage</div>
          {hasDerivedCoverage ? (
            <div style={{ display: 'grid', gap: 10 }}>
              <div>
                <div style={{ fontSize: 10, color: '#64748b', marginBottom: 5, fontWeight: 600, letterSpacing: '0.02em' }}>Direct IOC</div>
                <ProviderCoverageBadges coverage={layeredCoverage.direct} />
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#64748b', marginBottom: 5, fontWeight: 600, letterSpacing: '0.02em' }}>
                  Derived host:{' '}
                  <span style={{ color: '#cbd5e1', fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace", fontWeight: 500, overflowWrap: 'anywhere' }}>
                    {layeredCoverage.derivedHost}
                  </span>
                </div>
                <ProviderCoverageBadges coverage={layeredCoverage.derived} />
              </div>
            </div>
          ) : (
            <ProviderCoverageBadges coverage={layeredCoverage.direct} />
          )}
        </div>
        <div style={summaryRefsCardStyle}>
          <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 6 }}>Analyst refs</div>
          <div style={{ fontSize: 13, color: '#e2e8f0', fontWeight: 600 }}>{analystRefs}</div>
        </div>
      </div>
    </div>
  );
}

function DerivedInfrastructureSection({
  context,
  providerSnapshots,
  active,
  iocId,
  iocValue,
  iocType,
  canWrite,
  isAdmin,
  providerGridStyle,
  onProviderSnapshot,
  IpEnrichmentCard,
  AbuseIpdbEnrichmentCard,
  RdapEnrichmentCard,
  SpamhausDropEnrichmentCard
}) {
  if (!context) return null;

  const coverage = computeProviderCoverage(providerSnapshots, { providerKeys: context.providers });
  const hostKindLabel = context.hostKind === 'ip' ? 'IP address' : 'domain';

  return (
    <div style={{ ...sectionShellStyle, borderColor: '#1e3a5f' }}>
      <div style={{ marginBottom: 12 }}>
        <div style={sectionTitleStyle}>Derived Infrastructure</div>
        <div style={sectionDescStyle}>
          Enrichment for the host extracted from this URL IOC. Results apply to the extracted {hostKindLabel}, not the URL path or query.
        </div>
      </div>
      <div style={{
        marginBottom: 12,
        padding: '10px 12px',
        borderRadius: 8,
        border: '1px solid #334155',
        background: '#0b1220',
        fontSize: 13
      }}
      >
        <div style={{ color: '#94a3b8', fontSize: 11, marginBottom: 4 }}>Extracted host</div>
        <div style={{ color: '#e2e8f0', fontWeight: 600, fontFamily: "'JetBrains Mono', 'SFMono-Regular', Consolas, monospace", overflowWrap: 'anywhere' }}>
          {context.host}
        </div>
        <div style={{ marginTop: 8 }}>
          <ProviderCoverageBadges coverage={coverage} />
        </div>
      </div>
      <div style={providerGridStyle}>
        {isDerivedProviderApplicable('ipinfo', context) ? (
          <IpEnrichmentCard
            iocId={iocId}
            iocValue={iocValue}
            iocType={iocType}
            active={active}
            isAdmin={isAdmin}
            compact
            onSnapshot={(snap) => onProviderSnapshot('ipinfo', snap)}
          />
        ) : null}
        {isDerivedProviderApplicable('abuseipdb', context) ? (
          <AbuseIpdbEnrichmentCard
            iocId={iocId}
            iocValue={iocValue}
            iocType={iocType}
            active={active}
            canRefresh={canWrite}
            isAdmin={isAdmin}
            compact
            onSnapshot={(snap) => onProviderSnapshot('abuseipdb', snap)}
          />
        ) : null}
        {isDerivedProviderApplicable('rdap', context) ? (
          <RdapEnrichmentCard
            iocId={iocId}
            iocValue={iocValue}
            iocType={iocType}
            active={active}
            isAdmin={isAdmin}
            compact
            onSnapshot={(snap) => onProviderSnapshot('rdap', snap)}
          />
        ) : null}
        {isDerivedProviderApplicable('spamhaus_drop', context) && SpamhausDropEnrichmentCard ? (
          <SpamhausDropEnrichmentCard
            iocId={iocId}
            iocValue={iocValue}
            iocType={iocType}
            active={active}
            canRefresh={canWrite}
            isAdmin={isAdmin}
            compact
            onSnapshot={(snap) => onProviderSnapshot('spamhaus_drop', snap)}
          />
        ) : null}
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
  const requestConfirm = useAppConfirm();
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
    const ok = await requestConfirm({
      title: 'Delete reference?',
      description: `Delete reference "${item.title}"?`,
      variant: 'danger',
      confirmLabel: 'Delete'
    });
    if (!ok) return;
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

function FileArtifactInformationCard({ fileInformation, fileArtifact }) {
  const primary = fileArtifact?.primary_hash || null;
  const known = Array.isArray(fileArtifact?.known_hashes) ? fileArtifact.known_hashes : [];
  const fi = fileInformation || {};

  const hashRows = known.length
    ? known
    : [
        fi.md5 ? { hash_type: 'md5', value: fi.md5, is_primary: false } : null,
        fi.sha1 ? { hash_type: 'sha1', value: fi.sha1, is_primary: false } : null,
        fi.sha256 ? { hash_type: 'sha256', value: fi.sha256, is_primary: true } : null
      ].filter(Boolean);

  return (
    <div style={{ border: '1px solid #334155', borderRadius: 10, overflow: 'hidden' }}>
      <div style={{ padding: 10, borderBottom: '1px solid #334155', background: '#1f2937', fontWeight: 700 }}>File Information</div>
      <table className="ioc-table" width="100%" cellPadding="10" style={{ borderCollapse: 'collapse', tableLayout: 'fixed', fontSize: 13 }}>
        <tbody>
          {primary ? (
            <>
              <tr style={{ borderTop: '1px solid #334155' }}>
                <th style={{ width: 180, textAlign: 'left', background: '#111827' }}>Primary Identifier</th>
                <td style={{ textTransform: 'uppercase', fontWeight: 700, color: '#93c5fd' }}>{primary.hash_type}</td>
              </tr>
              <tr style={{ borderTop: '1px solid #334155' }}>
                <th style={{ width: 180, textAlign: 'left', background: '#111827' }}>Primary Value</th>
                <td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}>
                  {primary.value}
                </td>
              </tr>
            </>
          ) : null}
          {hashRows.length ? (
            <tr style={{ borderTop: '1px solid #334155' }}>
              <th style={{ width: 180, textAlign: 'left', background: '#111827', verticalAlign: 'top' }}>Known Hashes</th>
              <td>
                <div style={{ display: 'grid', gap: 6 }}>
                  {hashRows.map((h) => (
                    <div key={`${h.hash_type}-${h.value}`} style={{ display: 'grid', gridTemplateColumns: '72px 1fr', gap: 8 }}>
                      <span style={{ textTransform: 'uppercase', color: h.is_primary ? '#93c5fd' : '#94a3b8', fontWeight: h.is_primary ? 700 : 500 }}>
                        {h.hash_type}
                      </span>
                      <span style={{ whiteSpace: 'normal', overflowWrap: 'anywhere', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace' }}>
                        {h.value}
                      </span>
                    </div>
                  ))}
                </div>
              </td>
            </tr>
          ) : null}
          <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>File Name</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fi.file_name || fileArtifact?.file_name || '-'}</td></tr>
          <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>File Type</th><td>{fi.file_type || fileArtifact?.file_type || '-'}</td></tr>
          <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>MIME</th><td>{fi.mime || fileArtifact?.mime_type || '-'}</td></tr>
          {!known.length ? (
            <>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>MD5</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fi.md5 || '-'}</td></tr>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SHA1</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fi.sha1 || '-'}</td></tr>
              <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SHA256</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fi.sha256 || '-'}</td></tr>
            </>
          ) : null}
          <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>IMPHASH</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fi.imphash || '-'}</td></tr>
          <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>TLSH</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fi.tlsh || '-'}</td></tr>
          <tr style={{ borderTop: '1px solid #334155' }}><th style={{ width: 180, textAlign: 'left', background: '#111827' }}>SSDEEP</th><td style={{ whiteSpace: 'normal', overflowWrap: 'anywhere' }}>{fi.ssdeep || '-'}</td></tr>
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
  formatUserDateTime,
  isRdapEligible,
  isHashObservable,
  hasMeaningfulFileInfo,
  fileInformation,
  fileArtifact,
  VirusTotalEnrichmentCard,
  IpEnrichmentCard,
  AbuseIpdbEnrichmentCard,
  RdapEnrichmentCard,
  SpamhausDropEnrichmentCard
}) {
  const [providerSnapshots, setProviderSnapshots] = useState({});
  const [derivedProviderSnapshots, setDerivedProviderSnapshots] = useState({});
  const [analystSummary, setAnalystSummary] = useState({ total_count: 0, supports_malicious_count: 0 });

  const derivedContext = useMemo(
    () => getDerivedInfrastructureContext(iocValue, iocType, { rdapEligible: isRdapEligible }),
    [iocValue, iocType, isRdapEligible]
  );

  useEffect(() => {
    setProviderSnapshots({});
    setDerivedProviderSnapshots({});
  }, [iocId, iocType, iocValue]);

  const showVt = isProviderApplicable('virustotal', iocType);
  const showAbuse = isProviderApplicable('abuseipdb', iocType);
  const showIpinfo = isProviderApplicable('ipinfo', iocType);
  const showRdap = isProviderApplicable('rdap', iocType, { rdapEligible: isRdapEligible });
  const showSpamhaus = isProviderApplicable('spamhaus_drop', iocType);

  const onProviderSnapshot = useCallback((provider, snapshot) => {
    setProviderSnapshots((prev) => ({ ...prev, [provider]: snapshot }));
  }, []);

  const onDerivedProviderSnapshot = useCallback((provider, snapshot) => {
    setDerivedProviderSnapshots((prev) => ({ ...prev, [provider]: snapshot }));
  }, []);

  const providerGridStyle = useMemo(() => ({
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
    gap: 12,
    alignItems: 'start'
  }), []);

  const showFileInfo = isHashObservable && (hasMeaningfulFileInfo || Boolean(fileArtifact?.known_hashes?.length));

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <IntelligenceSummarySection
        providerSnapshots={providerSnapshots}
        derivedProviderSnapshots={derivedProviderSnapshots}
        derivedContext={derivedContext}
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
            <AbuseIpdbEnrichmentCard iocId={iocId} iocValue={iocValue} iocType={iocType} active={active} canRefresh={canWrite} isAdmin={isAdmin} compact onSnapshot={(snap) => onProviderSnapshot('abuseipdb', snap)} />
          ) : null}
          {showIpinfo ? (
            <IpEnrichmentCard iocId={iocId} iocValue={iocValue} iocType={iocType} active={active} isAdmin={isAdmin} compact onSnapshot={(snap) => onProviderSnapshot('ipinfo', snap)} />
          ) : null}
          {showRdap ? (
            <RdapEnrichmentCard iocId={iocId} iocValue={iocValue} iocType={iocType} active={active} isAdmin={isAdmin} compact onSnapshot={(snap) => onProviderSnapshot('rdap', snap)} />
          ) : null}
          {showSpamhaus && SpamhausDropEnrichmentCard ? (
            <SpamhausDropEnrichmentCard iocId={iocId} iocValue={iocValue} iocType={iocType} active={active} canRefresh={canWrite} isAdmin={isAdmin} compact onSnapshot={(snap) => onProviderSnapshot('spamhaus_drop', snap)} />
          ) : null}
        </div>
      </div>

      <DerivedInfrastructureSection
        context={derivedContext}
        providerSnapshots={derivedProviderSnapshots}
        active={active}
        iocId={iocId}
        iocValue={iocValue}
        iocType={iocType}
        canWrite={canWrite}
        isAdmin={isAdmin}
        providerGridStyle={providerGridStyle}
        onProviderSnapshot={onDerivedProviderSnapshot}
        IpEnrichmentCard={IpEnrichmentCard}
        AbuseIpdbEnrichmentCard={AbuseIpdbEnrichmentCard}
        RdapEnrichmentCard={RdapEnrichmentCard}
        SpamhausDropEnrichmentCard={SpamhausDropEnrichmentCard}
      />

      <AnalystIntelligenceSection
        iocId={iocId}
        canWrite={canWrite}
        active={active}
        onSummaryChange={setAnalystSummary}
        formatUserDateTime={formatUserDateTime}
      />

      {showFileInfo ? (
        <FileArtifactInformationCard fileInformation={fileInformation} fileArtifact={fileArtifact} />
      ) : null}
    </div>
  );
}
