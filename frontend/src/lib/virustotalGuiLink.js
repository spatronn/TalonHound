// Guard for the "Open in VirusTotal" browser link.
//
// The backend is the single source of truth for IOC-type -> VirusTotal GUI-route
// mapping (see backend/lib/virustotalEnrichment.js buildVirusTotalGuiUrl); it
// delivers `summary.permalink` already pointing at the human report GUI
// (https://www.virustotal.com/gui/...). This helper is a defensive front-end
// guard, NOT a second copy of that mapping: it simply refuses to render anything
// that is not a VirusTotal GUI URL, so a legacy/API `/api/v3/...` self-link can
// never end up as a browser href (which would hit the API and 401).

const VT_GUI_PREFIX = 'https://www.virustotal.com/gui/';

/**
 * @param {{ permalink?: string|null }|null|undefined} summary
 * @returns {string|null} a safe VirusTotal GUI href, or null when none is available.
 */
export function virusTotalGuiHref(summary) {
  const permalink = summary && typeof summary === 'object' ? summary.permalink : null;
  if (typeof permalink !== 'string') return null;
  const href = permalink.trim();
  if (!href.startsWith(VT_GUI_PREFIX)) return null;
  return href;
}

export { VT_GUI_PREFIX };
