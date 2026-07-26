import React from 'react';

const stroke = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.75,
  strokeLinecap: 'round',
  strokeLinejoin: 'round'
};

function SvgIcon({ children, size = 16, color = 'currentColor', title }) {
  return (
    <span
      aria-hidden={title ? undefined : true}
      title={title}
      style={{ display: 'inline-flex', width: size, height: size, color, flexShrink: 0 }}
    >
      <svg viewBox="0 0 24 24" width={size} height={size} {...stroke}>{children}</svg>
    </span>
  );
}

export const IocDetailIcons = {
  status: (props) => (
    <SvgIcon {...props}><circle cx="12" cy="12" r="9" /><path d="m9 12 2 2 4-4" /></SvgIcon>
  ),
  calendar: (props) => (
    <SvgIcon {...props}>
      <rect x="3" y="5" width="18" height="16" rx="2" />
      <path d="M16 3v4" /><path d="M8 3v4" /><path d="M3 11h18" />
    </SvgIcon>
  ),
  sources: (props) => (
    <SvgIcon {...props}>
      <ellipse cx="12" cy="6" rx="7" ry="3" />
      <path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6" />
      <path d="M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" />
    </SvgIcon>
  ),
  clock: (props) => (
    <SvgIcon {...props}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></SvgIcon>
  ),
  user: (props) => (
    <SvgIcon {...props}><circle cx="12" cy="8" r="4" /><path d="M4 20c1.5-3.5 4-5 8-5s6.5 1.5 8 5" /></SvgIcon>
  ),
  download: (props) => (
    <SvgIcon {...props}><path d="M12 3v12" /><path d="m7 10 5 5 5-5" /><path d="M5 21h14" /></SvgIcon>
  ),
  edit: (props) => (
    <SvgIcon {...props}><path d="M12 20h9" /><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z" /></SvgIcon>
  ),
  eye: (props) => (
    <SvgIcon {...props}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" /><circle cx="12" cy="12" r="3" /></SvgIcon>
  ),
  copy: (props) => (
    <SvgIcon {...props}>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15V5a2 2 0 0 1 2-2h10" />
    </SvgIcon>
  ),
  refresh: (props) => (
    <SvgIcon {...props}><path d="M21 12a9 9 0 1 1-2.6-6.3" /><path d="M21 3v6h-6" /></SvgIcon>
  ),
  more: (props) => (
    <SvgIcon {...props}>
      <circle cx="12" cy="5" r="1.5" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none" />
      <circle cx="12" cy="19" r="1.5" fill="currentColor" stroke="none" />
    </SvgIcon>
  ),
  info: (props) => (
    <SvgIcon {...props}><circle cx="12" cy="12" r="9" /><path d="M12 10v6" /><path d="M12 7h.01" /></SvgIcon>
  )
};

export function InfoTip({ text }) {
  return (
    <span
      tabIndex={0}
      title={text}
      aria-label={text}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        color: '#64748b',
        cursor: 'help',
        outline: 'none'
      }}
      onFocus={(e) => { e.currentTarget.style.color = '#93c5fd'; }}
      onBlur={(e) => { e.currentTarget.style.color = '#64748b'; }}
    >
      <IocDetailIcons.info size={13} />
    </span>
  );
}
