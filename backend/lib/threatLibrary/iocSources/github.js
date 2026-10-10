/**
 * Bounded GitHub directory / file enumeration for Additional IOC Sources.
 * Public HTTPS only — no tokens. Content is never executed.
 */

import { IOC_SOURCE_ELIGIBLE_EXTENSIONS, IOC_SOURCE_FETCH } from './constants.js';
import { fetchIocSourceUrl, publicFetchError, validateIocSourceUrl } from './fetchSafe.js';

const GITHUB_TREE_RE = /^https?:\/\/(?:www\.)?github\.com\/([^/]+)\/([^/]+)\/(?:tree|blob)\/([^/]+)\/(.+?)\/?$/i;
const GITHUB_REPO_RE = /^https?:\/\/(?:www\.)?github\.com\/([^/]+)\/([^/]+)\/?$/i;
const GITHUB_RAW_RE = /^https?:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)\/(.+)$/i;

/**
 * @param {string} url
 * @returns {{ kind: 'dir'|'file'|'raw'|'unknown', owner?: string, repo?: string, ref?: string, path?: string }|null}
 */
export function parseGitHubUrl(url) {
  const href = String(url || '').trim();
  let m = href.match(GITHUB_RAW_RE);
  if (m) {
    return { kind: 'raw', owner: m[1], repo: m[2], ref: m[3], path: decodeURIComponent(m[4]) };
  }
  m = href.match(GITHUB_TREE_RE);
  if (m) {
    const isBlob = /\/blob\//i.test(href);
    return {
      kind: isBlob ? 'file' : 'dir',
      owner: m[1],
      repo: m[2].replace(/\.git$/i, ''),
      ref: m[3],
      path: decodeURIComponent(m[4])
    };
  }
  m = href.match(GITHUB_REPO_RE);
  if (m) {
    return { kind: 'dir', owner: m[1], repo: m[2].replace(/\.git$/i, ''), ref: 'HEAD', path: '' };
  }
  return null;
}

export function isEligibleIocFilePath(path) {
  const p = String(path || '').toLowerCase();
  if (!p || p.endsWith('/')) return false;
  // Skip obvious non-IOC noise
  if (/(^|\/)(readme|license|changelog|contributing)(\.|$)/i.test(p)) return false;
  return IOC_SOURCE_ELIGIBLE_EXTENSIONS.some((ext) => p.endsWith(ext));
}

function contentsApiUrl(owner, repo, path, ref) {
  const base = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${path
    .split('/')
    .map(encodeURIComponent)
    .join('/')}`;
  const q = ref && ref !== 'HEAD' ? `?ref=${encodeURIComponent(ref)}` : '';
  return `${base}${q}`;
}

function rawUrl(owner, repo, ref, path) {
  return `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(ref)}/${path
    .split('/')
    .map(encodeURIComponent)
    .join('/')}`;
}

/**
 * Enumerate eligible files in a GitHub directory (depth 1).
 * @param {string} url
 * @param {{ fetchImpl?: Function }} [deps]
 */
export async function enumerateGitHubIocSource(url, deps = {}) {
  const parsed = parseGitHubUrl(url);
  if (!parsed || parsed.kind === 'unknown') {
    return { ok: false, code: 'not_github', message: 'Not a GitHub URL' };
  }

  if (parsed.kind === 'file' || parsed.kind === 'raw') {
    if (!isEligibleIocFilePath(parsed.path || '')) {
      return { ok: false, code: 'unsupported_file', message: 'File type is not supported for IOC extraction' };
    }
    const download =
      parsed.kind === 'raw'
        ? url
        : rawUrl(parsed.owner, parsed.repo, parsed.ref, parsed.path);
    const policy = validateIocSourceUrl(download);
    if (!policy.ok) return { ok: false, code: 'blocked_url', message: policy.error };
    return {
      ok: true,
      source_type: 'github_file',
      repo_revision: parsed.ref,
      files: [
        {
          path: parsed.path,
          download_url: download,
          size_bytes: null,
          content_sha: null,
          selected: true
        }
      ]
    };
  }

  // Directory listing via Contents API
  const apiUrl = contentsApiUrl(parsed.owner, parsed.repo, parsed.path || '', parsed.ref);
  const policy = validateIocSourceUrl(apiUrl);
  if (!policy.ok) return { ok: false, code: 'blocked_url', message: policy.error };

  let listing;
  try {
    listing = await fetchIocSourceUrl(apiUrl, {
      fetchImpl: deps.fetchImpl,
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'TalonHound-ThreatLibrary'
      },
      maxBytes: IOC_SOURCE_FETCH.MAX_BYTES
    });
  } catch (err) {
    const pub = publicFetchError(err);
    return { ok: false, code: pub.code, message: pub.message };
  }

  let items;
  try {
    items = JSON.parse(listing.body);
  } catch {
    return { ok: false, code: 'invalid_github_listing', message: 'GitHub listing was not valid JSON' };
  }
  if (!Array.isArray(items)) {
    // Single-file contents response
    if (items && items.type === 'file' && isEligibleIocFilePath(items.path || items.name || '')) {
      return {
        ok: true,
        source_type: 'github_file',
        repo_revision: parsed.ref,
        content_hash: listing.contentHash,
        files: [
          {
            path: items.path || items.name,
            download_url: items.download_url || rawUrl(parsed.owner, parsed.repo, parsed.ref, items.path || items.name),
            size_bytes: items.size ?? null,
            content_sha: items.sha || null,
            selected: true
          }
        ]
      };
    }
    return { ok: false, code: 'unsupported_github', message: 'GitHub path is not an enumerable IOC directory' };
  }

  const files = [];
  let skipped = 0;
  for (const item of items) {
    if (files.length >= IOC_SOURCE_FETCH.GITHUB_MAX_FILES) {
      skipped += 1;
      continue;
    }
    if (item.type === 'dir') {
      skipped += 1; // depth > 1 not traversed in v1
      continue;
    }
    if (item.type !== 'file') {
      skipped += 1;
      continue;
    }
    const path = item.path || item.name || '';
    if (!isEligibleIocFilePath(path)) {
      skipped += 1;
      continue;
    }
    if (item.size != null && Number(item.size) > IOC_SOURCE_FETCH.GITHUB_MAX_FILE_BYTES) {
      skipped += 1;
      continue;
    }
    const download = item.download_url || rawUrl(parsed.owner, parsed.repo, parsed.ref, path);
    if (!validateIocSourceUrl(download).ok) {
      skipped += 1;
      continue;
    }
    files.push({
      path,
      download_url: download,
      size_bytes: item.size ?? null,
      content_sha: item.sha || null,
      selected: true
    });
  }

  if (!files.length) {
    return { ok: false, code: 'no_eligible_files', message: 'No eligible IOC files found in the GitHub directory' };
  }

  return {
    ok: true,
    source_type: 'github_dir',
    repo_revision: parsed.ref,
    content_hash: listing.contentHash,
    files,
    skipped_entries: skipped
  };
}
