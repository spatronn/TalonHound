import React from 'react';
import {
  RELATIONSHIP_SCOPE_OPTIONS,
  associationKindLabel,
  relationshipScopeCount
} from '../../lib/malwareFamilyDiscovery.js';

/**
 * Relationship scope filter + per-IOC scope pills shared by the Malware Family
 * and Threat Actor IOC inventories (same scopes as REST/MCP `scope`).
 */

const PILL = {
  display: 'inline-flex',
  alignItems: 'center',
  padding: '2px 8px',
  borderRadius: 999,
  fontSize: 11,
  fontWeight: 700,
  whiteSpace: 'nowrap'
};

export const RELATIONSHIP_SCOPE_PALETTE = Object.freeze({
  direct: { color: '#99f6e4', background: 'rgba(19,78,74,0.45)', border: '1px solid #0f766e' },
  context: { color: '#e2e8f0', background: '#1e293b', border: '1px solid #475569' },
  analyst: { color: '#c7d2fe', background: '#312e81', border: '1px solid #4338ca' }
});

/**
 * @param {{ value: string, summary?: object|null, onChange: (scope: string) => void,
 *   buttonStyle?: object, ariaLabel?: string }} props
 */
export function RelationshipScopeFilter({ value, summary = null, onChange, buttonStyle = {}, ariaLabel = 'Relationship' }) {
  return (
    <div role="group" aria-label={ariaLabel} style={{ display: 'inline-flex', flexWrap: 'wrap', border: '1px solid #334155', borderRadius: 8, overflow: 'hidden' }}>
      {RELATIONSHIP_SCOPE_OPTIONS.map((o) => {
        const active = value === o.value;
        const count = relationshipScopeCount(summary, o.value);
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={active}
            title={o.hint}
            onClick={() => onChange(o.value)}
            style={{
              ...buttonStyle,
              border: 'none',
              borderRadius: 0,
              background: active ? '#1d4ed8' : 'transparent',
              color: active ? '#fff' : '#cbd5e1'
            }}
          >
            {o.label}
            {count != null ? (
              <span style={{ marginLeft: 6, fontVariantNumeric: 'tabular-nums', color: active ? '#dbeafe' : '#94a3b8', fontWeight: 600 }}>
                {count.toLocaleString('en-US')}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

/** Scope pills for one IOC row: Direct (with its kind), Context, Analyst. */
export function RelationshipScopePills({ scopes = [], associationKinds = [] }) {
  const list = Array.isArray(scopes) ? scopes : [];
  if (!list.length) return <span style={{ color: '#64748b' }}>—</span>;
  const directKinds = (associationKinds || [])
    .filter((k) => k === 'directly_attributed_to' || k === 'malware_sample_of')
    .map(associationKindLabel)
    .filter(Boolean);
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
      {list.map((scope) => {
        const option = RELATIONSHIP_SCOPE_OPTIONS.find((o) => o.value === scope);
        if (!option) return null;
        const title = scope === 'direct' && directKinds.length ? `${option.hint} (${directKinds.join(', ')})` : option.hint;
        return (
          <span key={scope} title={title} style={{ ...PILL, ...RELATIONSHIP_SCOPE_PALETTE[scope] }}>
            {scope === 'direct' && directKinds.includes('Sample of') ? 'Direct · sample' : option.label}
          </span>
        );
      })}
    </div>
  );
}
