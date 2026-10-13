import React from 'react';

/** Decorative 24px stroke icons for the Threat Library list (same style as NavIcons). */
function Svg({ children, size = 15 }) {
  return (
    <svg
      className="tl-lib-icon"
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

export const ListIcons = {
  search: (
    <Svg>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </Svg>
  ),
  refresh: (
    <Svg>
      <path d="M20 11a8 8 0 0 0-14.9-3.9L4 8.5" />
      <path d="M4 4v4.5h4.5" />
      <path d="M4 13a8 8 0 0 0 14.9 3.9l1.1-1.4" />
      <path d="M20 20v-4.5h-4.5" />
    </Svg>
  ),
  upload: (
    <Svg>
      <path d="M12 15V4" />
      <path d="m7.5 8.5 4.5-4.5 4.5 4.5" />
      <path d="M5 15v3a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-3" />
    </Svg>
  ),
  settings: (
    <Svg>
      <path d="M4 7h10M18 7h2M4 17h4M12 17h8" />
      <circle cx="16" cy="7" r="2" />
      <circle cx="10" cy="17" r="2" />
    </Svg>
  ),
  external: (
    <Svg size={13}>
      <path d="M14 4h6v6" />
      <path d="M20 4 11 13" />
      <path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4" />
    </Svg>
  ),
  chevronLeft: (
    <Svg size={14}>
      <path d="m14.5 6-6 6 6 6" />
    </Svg>
  ),
  chevronRight: (
    <Svg size={14}>
      <path d="m9.5 6 6 6-6 6" />
    </Svg>
  ),
  /* Report source types. */
  url: (
    <Svg>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M3.5 12h17" />
      <path d="M12 3.5c2.3 2.4 3.4 5.2 3.4 8.5s-1.1 6.1-3.4 8.5c-2.3-2.4-3.4-5.2-3.4-8.5S9.7 5.9 12 3.5Z" />
    </Svg>
  ),
  pdf: (
    <Svg>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z" />
      <path d="M14 3v5h5" />
      <path d="M9 13h6M9 17h4" />
    </Svg>
  ),
  thib: (
    <Svg>
      <path d="m12 3 8 4.5v9L12 21l-8-4.5v-9Z" />
      <path d="m4 7.5 8 4.5 8-4.5" />
      <path d="M12 12v9" />
    </Svg>
  )
};

/** Source-type icon; unknown types fall back to the document glyph. */
export function sourceTypeIcon(type) {
  return ListIcons[type] || ListIcons.pdf;
}
