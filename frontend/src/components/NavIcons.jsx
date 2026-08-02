import React from 'react';

const stroke = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.75,
  strokeLinecap: 'round',
  strokeLinejoin: 'round'
};

function Icon({ children }) {
  return (
    <span className="sidebar-nav-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" {...stroke}>{children}</svg>
    </span>
  );
}

export const NavIcons = {
  iocList: (
    <Icon>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
      <path d="M14 2v6h6" />
      <circle cx="11" cy="14" r="3" />
      <path d="m13.5 16.5 2 2" />
    </Icon>
  ),
  addIoc: (
    <Icon>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v8" />
      <path d="M8 12h8" />
    </Icon>
  ),
  suppressions: (
    <Icon>
      <path d="M12 3 4 6v6c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V6l-8-3Z" />
      <path d="m9 12 2 2 4-4" />
    </Icon>
  ),
  actionCenter: (
    <Icon>
      <rect x="3" y="3" width="7" height="7" rx="1.5" />
      <rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" />
      <rect x="14" y="14" width="7" height="7" rx="1.5" />
    </Icon>
  ),
  feeds: (
    <Icon>
      <circle cx="6" cy="18" r="2" />
      <path d="M4 11a9 9 0 0 1 9 9" />
      <path d="M4 4a16 16 0 0 1 16 16" />
    </Icon>
  ),
  customFeeds: (
    <Icon>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
      <path d="M14 2v6h6" />
      <path d="M8 13h8" />
      <path d="M8 17h6" />
    </Icon>
  ),
  jobQueue: (
    <Icon>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
      <path d="M14 2v6h6" />
      <circle cx="12" cy="15" r="3" />
      <path d="M12 14v1.5l1 1" />
    </Icon>
  ),
  publishedFeeds: (
    <Icon>
      <path d="M4 11a9 9 0 0 1 9 9" />
      <path d="M4 4a16 16 0 0 1 16 16" />
      <circle cx="5" cy="19" r="1.5" />
      <path d="M15 3h6v6" />
      <path d="m21 3-8 8" />
    </Icon>
  ),
  settings: (
    <Icon>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z" />
    </Icon>
  ),
  users: (
    <Icon>
      <path d="M16 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2" />
      <circle cx="9.5" cy="7" r="3.5" />
      <path d="M22 21v-2a3.5 3.5 0 0 0-2.5-3.3" />
      <path d="M16.5 3.7a3.5 3.5 0 0 1 0 6.6" />
    </Icon>
  ),
  auditLogs: (
    <Icon>
      <path d="M8 6h13" />
      <path d="M8 12h13" />
      <path d="M8 18h13" />
      <path d="M3 6h.01" />
      <path d="M3 12h.01" />
      <path d="M3 18h.01" />
    </Icon>
  ),
  tags: (
    <Icon>
      <path d="M12 2H3v9l9.7 9.7a2 2 0 0 0 2.8 0l5.2-5.2a2 2 0 0 0 0-2.8L12 2Z" />
      <circle cx="7.5" cy="7.5" r="1.5" />
    </Icon>
  ),
  classifications: (
    <Icon>
      <path d="m12 3 3.5 6H22l-5 4.2 1.8 7L12 16.8 5.2 20.2 7 13.2 2 9h6.5L12 3Z" />
    </Icon>
  ),
  threatActors: (
    <Icon>
      <path d="M17 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <circle cx="9.5" cy="7" r="3.5" />
      <path d="M22 21v-2a3.5 3.5 0 0 0-2.6-3.3" />
      <path d="M16.4 3.8a3.5 3.5 0 0 1 0 6.4" />
    </Icon>
  ),
  iocSources: (
    <Icon>
      <circle cx="12" cy="12" r="2.5" />
      <circle cx="5" cy="7" r="2" />
      <circle cx="19" cy="7" r="2" />
      <circle cx="5" cy="17" r="2" />
      <circle cx="19" cy="17" r="2" />
      <path d="M7 8.2 10.2 10.5" />
      <path d="M17 8.2 13.8 10.5" />
      <path d="M7 15.8 10.2 13.5" />
      <path d="M17 15.8 13.8 13.5" />
    </Icon>
  ),
  apiKeys: (
    <Icon>
      <circle cx="8" cy="15" r="4" />
      <path d="M11.5 12.5 21 3" />
      <path d="M16 5.5 18.5 8" />
      <path d="M18.5 3 21 5.5" />
    </Icon>
  ),
      enrichmentProviders: (
    <Icon>
      <path d="M4 21v-7" />
      <path d="M4 10V3" />
      <path d="M12 21v-9" />
      <path d="M12 8V3" />
      <path d="M20 21v-5" />
      <path d="M20 12V3" />
      <path d="M2 14h4" />
      <path d="M10 8h4" />
      <path d="M18 16h4" />
    </Icon>
  ),
  backupRestore: (
    <Icon>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="M7 10 12 15 17 10" />
      <path d="M12 15V3" />
    </Icon>
  )
};
