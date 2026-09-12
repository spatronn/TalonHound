/** Shared inline styles for Threat Library pages (matches Published Feeds / AppShell look). */

export const ui = {
  section: { border: '1px solid #334155', borderRadius: 12, background: '#111827', padding: 16 },
  pageTitle: { margin: 0, fontSize: 22, fontWeight: 700, color: '#f1f5f9' },
  formPanel: {
    marginBottom: 20,
    padding: 16,
    border: '1px solid #334155',
    borderRadius: 10,
    background: '#0f172a'
  },
  formTitle: { marginTop: 0, marginBottom: 14, fontSize: 16, fontWeight: 600, color: '#e2e8f0' },
  label: { display: 'block', fontSize: 12, fontWeight: 600, color: '#94a3b8', marginBottom: 6 },
  input: {
    width: '100%',
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #334155',
    background: '#020617',
    color: '#e2e8f0',
    fontSize: 14,
    boxSizing: 'border-box'
  },
  select: {
    width: '100%',
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #334155',
    background: '#020617',
    color: '#e2e8f0',
    fontSize: 14,
    boxSizing: 'border-box',
    cursor: 'pointer'
  },
  helper: { display: 'block', fontSize: 11, color: '#94a3b8', marginTop: 4, lineHeight: 1.45 },
  btn: {
    padding: '8px 14px',
    borderRadius: 8,
    border: '1px solid #475569',
    background: '#1f2937',
    color: '#e2e8f0',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
    minHeight: 36,
    lineHeight: 1.2,
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    boxSizing: 'border-box'
  },
  btnPrimary: {
    padding: '8px 14px',
    borderRadius: 8,
    border: '1px solid #0f766e',
    background: '#134e4a',
    color: '#ccfbf1',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
    minHeight: 36,
    lineHeight: 1.2,
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    boxSizing: 'border-box'
  },
  btnDanger: {
    padding: '8px 14px',
    borderRadius: 8,
    border: '1px solid #7f1d1d',
    background: '#450a0a',
    color: '#fecaca',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer',
    minHeight: 36,
    lineHeight: 1.2,
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    boxSizing: 'border-box'
  },
  thead: { background: '#0f172a' },
  th: {
    textAlign: 'left',
    padding: '10px 8px',
    borderBottom: '1px solid #334155',
    color: '#94a3b8',
    fontWeight: 600,
    fontSize: 12,
    whiteSpace: 'nowrap'
  },
  tr: { borderBottom: '1px solid #1e293b' },
  td: { padding: '10px 8px', color: '#e2e8f0', verticalAlign: 'top', fontSize: 13 },
  muted: { color: '#94a3b8', fontSize: 13 },
  error: { color: '#fca5a5', fontSize: 13 },
  warnBanner: {
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #92400e',
    background: 'rgba(217,119,6,0.12)',
    color: '#fcd34d',
    fontSize: 13,
    lineHeight: 1.45,
    marginBottom: 12
  },
  infoBanner: {
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #0f766e',
    background: 'rgba(15,118,110,0.12)',
    color: '#99f6e4',
    fontSize: 13,
    lineHeight: 1.45,
    marginBottom: 12
  },
  tabRow: { display: 'flex', gap: 6, marginBottom: 14, flexWrap: 'wrap' },
  tab: (active) => ({
    padding: '7px 12px',
    borderRadius: 8,
    border: `1px solid ${active ? '#0f766e' : '#334155'}`,
    background: active ? 'rgba(15,118,110,0.25)' : '#0f172a',
    color: active ? '#ccfbf1' : '#cbd5e1',
    fontSize: 13,
    fontWeight: 600,
    cursor: 'pointer'
  })
};

export function badgeStyle({ border, bg, color }) {
  return {
    display: 'inline-block',
    border: `1px solid ${border}`,
    background: bg,
    color,
    borderRadius: 999,
    padding: '2px 8px',
    fontSize: 11,
    fontWeight: 700,
    whiteSpace: 'nowrap'
  };
}
