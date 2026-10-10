/**
 * Display helpers for the Threat Library IOC Sources tab.
 * Pure functions — no React, no API calls.
 */

const LIFECYCLE_BADGE = Object.freeze({
  discovered: { label: 'Discovered', border: '#334155', bg: '#1e293b', color: '#cbd5e1' },
  inspecting: { label: 'Inspecting', border: '#854d0e', bg: 'rgba(161,98,7,0.22)', color: '#fde68a' },
  inspected: { label: 'Inspected', border: '#0f766e', bg: 'rgba(15,118,110,0.22)', color: '#99f6e4' },
  attached: { label: 'Attached', border: '#854d0e', bg: 'rgba(161,98,7,0.22)', color: '#fde68a' },
  extracting: { label: 'Extracting', border: '#854d0e', bg: 'rgba(161,98,7,0.22)', color: '#fde68a' },
  extracted: { label: 'Extracted', border: '#166534', bg: 'rgba(22,101,52,0.28)', color: '#86efac' },
  failed: { label: 'Failed', border: '#7f1d1d', bg: 'rgba(127,29,29,0.28)', color: '#fecaca' },
  blocked: { label: 'Blocked', border: '#7f1d1d', bg: 'rgba(127,29,29,0.28)', color: '#fecaca' },
  unsupported: { label: 'Unsupported', border: '#7f1d1d', bg: 'rgba(127,29,29,0.28)', color: '#fecaca' },
  dismissed: { label: 'Dismissed', border: '#334155', bg: '#1e293b', color: '#94a3b8' },
  stale: { label: 'Stale', border: '#854d0e', bg: 'rgba(161,98,7,0.22)', color: '#fde68a' }
});

const SOURCE_TYPE_LABEL = Object.freeze({
  github_dir: 'GitHub directory',
  github_file: 'GitHub file',
  html: 'HTML',
  txt: 'Text',
  csv: 'CSV',
  json: 'JSON',
  pdf: 'PDF',
  unknown: 'Source'
});

/**
 * @param {string|null|undefined} status
 */
export function lifecycleBadge(status) {
  const key = String(status || '').toLowerCase();
  return LIFECYCLE_BADGE[key] || {
    label: key ? key.replace(/_/g, ' ') : 'Unknown',
    border: '#334155',
    bg: '#1e293b',
    color: '#cbd5e1'
  };
}

/**
 * @param {string|null|undefined} sourceType
 */
export function sourceTypeLabel(sourceType) {
  const key = String(sourceType || '').toLowerCase();
  return SOURCE_TYPE_LABEL[key] || (key ? key.replace(/_/g, ' ') : 'Source');
}

/**
 * Compact title for card header — never invents data beyond the URL/type.
 * @param {{ original_url?: string, canonical_url?: string, source_type?: string }} source
 */
export function shortSourceTitle(source) {
  const url = String(source?.canonical_url || source?.original_url || '').trim();
  if (!url) return 'IOC source';

  try {
    const u = new URL(url);
    if (/github\.com$/i.test(u.hostname) || /githubusercontent\.com$/i.test(u.hostname)) {
      const parts = u.pathname.split('/').filter(Boolean);
      // /owner/repo/tree|blob/ref/path...
      if (parts.length >= 2) {
        const ownerRepo = `${parts[0]}/${parts[1]}`;
        const pathStart = parts[0] && parts[2] && /^(tree|blob)$/i.test(parts[2]) ? 4 : 2;
        const pathParts = parts.slice(pathStart);
        if (pathParts.length) return `${ownerRepo} · ${pathParts.join('/')}`;
        return ownerRepo;
      }
    }
    return u.hostname + (u.pathname && u.pathname !== '/' ? u.pathname : '');
  } catch {
    return url.length > 72 ? `${url.slice(0, 69)}…` : url;
  }
}

/**
 * Secondary meta line for a source card (API fields only).
 * @param {object} source
 */
export function sourceCardMeta(source) {
  const parts = [];
  const type = sourceTypeLabel(source?.source_type);
  if (type && type !== 'Source') parts.push(type);

  const extraction = String(source?.extraction_status || '').toLowerCase();
  if (extraction && extraction !== 'idle' && extraction !== 'none') {
    parts.push(`Extraction ${extraction}`);
  } else if (source?.inspection_status) {
    parts.push(`Inspection ${source.inspection_status}`);
  }

  const unique = source?.preview?.unique_count;
  if (unique != null && Number.isFinite(Number(unique))) {
    parts.push(`${Number(unique)} unique indicators`);
  }

  const discovery = String(source?.discovery_method || '').toLowerCase();
  if (discovery === 'manual' || discovery === 'auto') {
    parts.push(discovery === 'manual' ? 'Added manually' : 'Auto-discovered');
  }

  return parts.join(' · ');
}

export function isAttachedLifecycle(status) {
  return ['attached', 'extracting', 'extracted', 'stale'].includes(String(status || '').toLowerCase());
}

export function isPendingLifecycle(status) {
  return ['discovered', 'inspected', 'failed', 'blocked', 'unsupported', 'inspecting'].includes(
    String(status || '').toLowerCase()
  );
}
