import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../../lib/api.js';
import { formatUserDateTime } from '../../lib/formatDate.js';
import { TlpBadge } from './tlp.jsx';
import { badgeStyle } from './styles.js';

const sectionTitleStyle = { fontWeight: 700, color: '#e2e8f0', fontSize: 16 };
const sectionDescStyle = { color: '#94a3b8', fontSize: 12, marginTop: 4 };
const sectionShellStyle = { border: '1px solid #334155', borderRadius: 12, padding: 14, background: '#0f172a' };

function roleStyle(role) {
  const r = String(role || '').toLowerCase();
  if (r.includes('command') || r.includes('malware') || r.includes('malicious')) {
    return { border: '#7f1d1d', bg: 'rgba(220,38,38,0.14)', color: '#fca5a5' };
  }
  if (r.includes('phish') || r.includes('suspicious') || r.includes('delivery')) {
    return { border: '#92400e', bg: 'rgba(217,119,6,0.14)', color: '#fcd34d' };
  }
  return { border: '#475569', bg: 'rgba(71,85,105,0.18)', color: '#cbd5e1' };
}

/**
 * IOC Details → Intelligence: claims from Threat Library reports that matched this IOC.
 */
export default function IocThreatContextSection({ iocId, active = true }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [claims, setClaims] = useState([]);
  const [relationships, setRelationships] = useState([]);

  const load = useCallback(async () => {
    if (!iocId) return;
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get(`/ioc/${iocId}/threat-context`);
      setClaims(data?.claims || []);
      setRelationships(data?.relationships || []);
    } catch (err) {
      setError(err?.response?.data?.message || 'Failed to load threat context');
      setClaims([]);
      setRelationships([]);
    } finally {
      setLoading(false);
    }
  }, [iocId]);

  useEffect(() => {
    if (!active || !iocId) return;
    load().catch(() => {});
  }, [active, iocId, load]);

  return (
    <div style={sectionShellStyle}>
      <div style={{ marginBottom: 12 }}>
        <div style={sectionTitleStyle}>Threat Context</div>
        <div style={sectionDescStyle}>
          Claims and relationships from Threat Library reports linked to this observable.
        </div>
      </div>

      {loading ? <div style={{ color: '#94a3b8', fontSize: 13 }}>Loading…</div> : null}
      {error ? <div style={{ color: '#fca5a5', fontSize: 13 }} role="alert">{error}</div> : null}

      {!loading && !error && claims.length === 0 ? (
        <div style={{ color: '#64748b', fontSize: 13 }}>No Threat Library context for this IOC yet.</div>
      ) : null}

      {!loading && claims.length > 0 ? (
        <div style={{ display: 'grid', gap: 10 }}>
          {claims.map((c, idx) => (
            <div
              key={`${c.report?.id || 'r'}-${idx}`}
              style={{
                border: '1px solid #1e293b',
                borderRadius: 10,
                padding: 12,
                background: '#0b1220'
              }}
            >
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', marginBottom: 8 }}>
                {c.report?.id ? (
                  <Link
                    to={`/threat-intelligence/threat-library/${c.report.id}`}
                    style={{ color: '#5eead4', fontWeight: 600, textDecoration: 'none', fontSize: 13 }}
                  >
                    {c.report.title || 'Threat report'}
                  </Link>
                ) : (
                  <span style={{ color: '#e2e8f0', fontWeight: 600, fontSize: 13 }}>{c.report?.title || 'Threat report'}</span>
                )}
                {c.report?.tlp ? <TlpBadge tlp={c.report.tlp} display={c.report.tlp_display} /> : null}
                {c.role ? <span style={badgeStyle(roleStyle(c.role))}>{c.role}</span> : null}
                {c.assessment ? (
                  <span style={badgeStyle({ border: '#334155', bg: '#1e293b', color: '#cbd5e1' })}>
                    {c.assessment}
                  </span>
                ) : null}
              </div>
              <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>
                {c.report?.source_name || c.report?.source_type || 'Source unknown'}
                {c.report?.published_at ? ` · ${formatUserDateTime(c.report.published_at)}` : ''}
                {c.confidence != null ? ` · confidence ${Math.round(Number(c.confidence) * 100)}%` : ''}
                {c.section ? ` · ${c.section}` : ''}
                {c.page_number != null ? ` · p.${c.page_number}` : ''}
              </div>
              {c.evidence_text ? (
                <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.45, whiteSpace: 'pre-wrap' }}>
                  {c.evidence_text}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}

      {!loading && relationships?.length > 0 ? (
        <div style={{ marginTop: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: '#94a3b8', marginBottom: 6 }}>Related relationships</div>
          <ul style={{ margin: 0, paddingLeft: 18, color: '#cbd5e1', fontSize: 13, lineHeight: 1.5 }}>
            {relationships.slice(0, 20).map((rel, i) => (
              <li key={rel.id || i}>
                {rel.relationship_type || 'related'}
                {rel.subject_entity_name ? ` · ${rel.subject_entity_name}` : ''}
                {rel.object_entity_name ? ` → ${rel.object_entity_name}` : ''}
                {rel.report_title ? ` (${rel.report_title})` : ''}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
