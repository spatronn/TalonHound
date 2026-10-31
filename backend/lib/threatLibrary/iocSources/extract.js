/**
 * Extract IOCs from an approved Additional IOC Source into the report candidate set.
 * Does not approve IOCs into global inventory. Preserves analyst review state.
 */

import { applyAnalystState } from '../candidateAnalystState.js';
import { bulkMatchCandidates } from '../iocMatch.js';
import { pdfToCanonicalDocument } from '../pdfIngest.js';
import { loadReportCandidateRows, reconcileReportCandidates } from '../store.js';
import { IOC_SOURCE_FETCH, LINKED_SOURCE_IOC_ASSERTION } from './constants.js';
import { fetchIocSourceUrl, publicFetchError } from './fetchSafe.js';
import { enumerateGitHubIocSource, parseGitHubUrl, resolveGitHubCommitSha } from './github.js';
import { buildPreviewFromParses, parseIocSourceContent } from './parseContent.js';
import { guardSourceUrl, loadReportScopeContext } from './inspect.js';
import { inventoryBacklinkScope } from './campaignScope.js';

const URL_SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

/** host (lower-cased) + path of a URL value, or null without a path. */
function hostPathIdentity(value) {
  const rest = String(value || '').replace(URL_SCHEME_RE, '');
  const slash = rest.indexOf('/');
  if (slash <= 0) return null;
  return `${rest.slice(0, slash).toLowerCase()}${rest.slice(slash)}`;
}

/**
 * A linked pack that publishes a file name as a domain ("domain-name:value =
 * 'sqlmap.py'" in a CISA STIX bundle) when the report itself lists that exact
 * value as a file / tool: `.py`, `.pl` are real TLDs, so syntax alone cannot
 * tell. The report's own typing wins and the linked row is Context Only, never
 * an Indicator (42-report audit, 35483).
 * @param {object[]} candidates linked-source candidates
 * @param {object[]} priorRows the report's persisted candidate rows
 */
export function demoteFilenameDomains(candidates, priorRows) {
  const artifacts = new Set(
    (priorRows || [])
      .filter((r) => r.has_original_document_occurrence !== false && FILE_IDENTITY_TYPES.has(String(r.candidate_type || '')))
      .map((r) => String(r.normalized_value || '').toLowerCase())
  );
  if (!artifacts.size) return candidates;
  return candidates.map((c) => {
    if (c.candidate_type !== 'domain' || !artifacts.has(String(c.normalized_value || '').toLowerCase())) return c;
    return {
      ...c,
      assessment: 'context_only',
      role: 'reference',
      match_state: 'context_only',
      evidence: { ...(c.evidence || {}), linked_type_conflict: 'original_document_file_identity' }
    };
  });
}

/** Original-document types that name a file, never a host. */
const FILE_IDENTITY_TYPES = new Set(['technical_artifact', 'file_name', 'file_path', 'relative_path']);

/**
 * A scheme-less URL of a linked pack ("docsend.online/download/drivers") is
 * the report's existing absolute URL with that host + path
 * ("https://docsend.online/download/drivers") when exactly one such URL is
 * known — the same folding the document extractor applies — so the union
 * never holds the same resource twice (tl-ioc-source-scope-v3). Ambiguous
 * (two schemes) or unknown spellings are kept as written.
 * @param {object[]} candidates linked-source candidates
 * @param {object[]} priorRows the report's persisted candidate rows
 */
export function foldSchemeLessLinkedUrls(candidates, priorRows) {
  const absolute = new Map();
  const note = (value) => {
    if (!URL_SCHEME_RE.test(String(value || ''))) return;
    const id = hostPathIdentity(value);
    if (!id) return;
    if (!absolute.has(id)) absolute.set(id, new Set());
    absolute.get(id).add(value);
  };
  for (const r of priorRows || []) if (r.candidate_type === 'url') note(r.normalized_value);
  for (const c of candidates) if (c.candidate_type === 'url') note(c.normalized_value);
  const out = new Map();
  for (const c of candidates) {
    let next = c;
    if (c.candidate_type === 'url' && !URL_SCHEME_RE.test(String(c.normalized_value || ''))) {
      const targets = absolute.get(hostPathIdentity(c.normalized_value));
      if (targets?.size === 1) {
        const [target] = targets;
        next = { ...c, normalized_value: target, scheme_less_alias_of: c.normalized_value };
      }
    }
    const key = `${next.candidate_type}\0${next.normalized_value}`;
    if (!out.has(key)) out.set(key, next);
  }
  return [...out.values()];
}
import {
  listSourceFiles,
  loadOriginalIndicatorKeys,
  loadOtherLinkedKeys,
  replaceSourceFiles,
  transitionSource
} from './store.js';

const GIT_SHA_RE = /^[0-9a-f]{40}$/i;

/**
 * Prefer commit-pinned download URLs when the source stores a resolved SHA.
 * @param {object} file
 * @param {object|null} gh
 * @param {string|null|undefined} repoRevision
 */
function pinnedDownloadUrl(file, gh, repoRevision) {
  const stored = file.download_url || null;
  if (!gh || !repoRevision || !GIT_SHA_RE.test(String(repoRevision)) || !file.path) {
    return stored || file.path;
  }
  const pin = String(repoRevision).toLowerCase();
  // Rewrite branch-named raw URLs onto the inspected commit.
  if (stored && /raw\.githubusercontent\.com\//i.test(stored)) {
    return stored.replace(
      /^(https?:\/\/raw\.githubusercontent\.com\/[^/]+\/[^/]+)\/[^/]+\//i,
      `$1/${pin}/`
    );
  }
  const path = String(file.path).replace(/^\/+/, '');
  return `https://raw.githubusercontent.com/${gh.owner}/${gh.repo}/${pin}/${path
    .split('/')
    .map(encodeURIComponent)
    .join('/')}`;
}

/**
 * @param {import('pg').Pool} pool
 * @param {object} source
 * @param {{ fetchImpl?: Function, destinationGuard?: Function }} [deps]
 */
export async function extractIocSource(pool, source, deps = {}) {
  await transitionSource(pool, source, 'start_extract');

  // Intelligence can change between inspection and approval: re-check first.
  const verdict = await guardSourceUrl(source, deps);
  if (!verdict.ok) {
    await transitionSource(pool, source, 'block', {
      error_code: verdict.code,
      error_detail: verdict.reason
    });
    return { ok: false, code: verdict.code };
  }

  const priorRows = await loadReportCandidateRows(pool, source.report_id);
  const priorByKey = new Map(priorRows.map((r) => [`${r.candidate_type}\0${r.normalized_value}`, r]));

  try {
    let files = await listSourceFiles(pool, source.id);
    const selected = files.filter((f) => f.selected !== false);
    const gh = parseGitHubUrl(source.canonical_url || source.original_url);

    // Refuse silent branch drift: if tip commit differs from inspected SHA, fail and require re-inspect.
    if (gh && source.repo_revision && GIT_SHA_RE.test(String(source.repo_revision))) {
      const tip = await resolveGitHubCommitSha(gh, deps);
      if (tip.ok && tip.repo_revision && tip.repo_revision !== String(source.repo_revision).toLowerCase()) {
        await transitionSource(pool, source, 'fail_extract', {
          error_code: 'source_revision_changed',
          error_detail: `Source tip ${tip.repo_revision} differs from inspected revision ${source.repo_revision}; re-inspect before extract`
        });
        return {
          ok: false,
          code: 'source_revision_changed',
          inspected: source.repo_revision,
          tip: tip.repo_revision
        };
      }
    }

    // A repository root is never enumerated here: its campaign folder is
    // resolved and listed only by inspection.
    if (gh && gh.kind === 'dir' && !String(gh.path || '').replace(/^\/+|\/+$/g, '') && !selected.length) {
      await transitionSource(pool, source, 'fail_extract', {
        error_code: 'campaign_scope_unresolved',
        error_detail: 'Repository root without an inspected campaign folder; inspect the source first'
      });
      return { ok: false, code: 'campaign_scope_unresolved' };
    }
    const reportScope = await loadReportScopeContext(pool, source.report_id);

    // Inspection deselected every listed file (all belong to other reports,
    // or unattributable folder hash lists): never re-list the folder and
    // ingest them anyway (tl-ioc-source-scope-v3).
    if (files.length && !selected.length) {
      await transitionSource(pool, source, 'fail_extract', {
        error_code: 'campaign_scope_unresolved',
        error_detail: 'Every file of this source was deselected at inspection (not attributable to this report)'
      });
      return { ok: false, code: 'campaign_scope_unresolved' };
    }
    if (!files.length && gh) {
      const listing = await enumerateGitHubIocSource(source.canonical_url || source.original_url, deps);
      if (!listing.ok) {
        await transitionSource(pool, source, 'fail_extract', {
          error_code: listing.code,
          error_detail: listing.message
        });
        return { ok: false, code: listing.code };
      }
      files = await replaceSourceFiles(pool, source.id, listing.files);
    }

    const targets = (files.length ? files : [{
      path: source.canonical_url,
      download_url: source.canonical_url || source.original_url,
      selected: true
    }]).filter((f) => f.selected !== false);

    const parseResults = [];
    const mergedByKey = new Map();
    const fileUpdates = [];

    for (const file of targets) {
      const url = pinnedDownloadUrl(file, gh, source.repo_revision);
      try {
        const fetched = await fetchIocSourceUrl(url, {
          fetchImpl: deps.fetchImpl,
          destinationGuard: deps.destinationGuard,
          maxBytes: gh ? IOC_SOURCE_FETCH.GITHUB_MAX_FILE_BYTES : IOC_SOURCE_FETCH.MAX_BYTES
        });
        // When inspect stored sha256(content), refuse silent byte drift on the pinned URL.
        const priorHash = String(file.content_sha || '').toLowerCase();
        if (/^[0-9a-f]{64}$/.test(priorHash)
          && fetched.contentHash
          && priorHash !== String(fetched.contentHash).toLowerCase()) {
          await transitionSource(pool, source, 'fail_extract', {
            error_code: 'source_content_changed',
            error_detail: `File ${file.path} content hash changed since inspection; re-inspect before extract`
          });
          return { ok: false, code: 'source_content_changed', path: file.path };
        }
        // A folder file whose metadata row names another article is another
        // campaign's inventory, also when the source was never inspected.
        const backlinkScope = gh?.kind === 'dir' ? inventoryBacklinkScope(fetched.body, file.path, reportScope) : null;
        if (backlinkScope?.verdict === 'other_report') {
          parseResults.push({ ok: false, code: 'campaign_backlink_other_report', path: file.path });
          fileUpdates.push({
            path: file.path,
            download_url: url,
            size_bytes: fetched.bytes,
            content_sha: fetched.contentHash,
            content_type: fetched.contentType,
            selected: false,
            parse_status: 'skipped',
            error_detail: `campaign_backlink_other_report: the file names ${backlinkScope.backlink}`
          });
          continue;
        }
        const parsed = await parseIocSourceContent({
          body: fetched.body,
          buffer: fetched.buffer,
          contentType: fetched.contentType || file.content_type,
          url,
          path: file.path,
          sourcePublicId: source.public_id,
          pdfToDocument: pdfToCanonicalDocument,
          reportScope
        });
        parseResults.push({ ...parsed, path: file.path });
        fileUpdates.push({
          path: file.path,
          download_url: url,
          size_bytes: fetched.bytes,
          content_sha: fetched.contentHash,
          content_type: fetched.contentType,
          selected: true,
          parse_status: parsed.ok ? 'ok' : 'failed',
          estimated_raw_count: parsed.raw_count ?? 0,
          estimated_unique_count: parsed.unique_count ?? 0,
          type_breakdown: parsed.type_breakdown || {},
          error_detail: parsed.ok ? null : parsed.message
        });
        if (parsed.ok) {
          for (const c of parsed.candidates) {
            const key = `${c.candidate_type}\0${c.normalized_value}`;
            if (!mergedByKey.has(key)) mergedByKey.set(key, c);
          }
        }
      } catch (err) {
        const pub = publicFetchError(err);
        parseResults.push({ ok: false, code: pub.code, message: pub.message, path: file.path });
        fileUpdates.push({
          path: file.path,
          download_url: url,
          selected: true,
          parse_status: 'failed',
          error_detail: pub.message
        });
      }
    }

    await replaceSourceFiles(pool, source.id, fileUpdates);

    if (!mergedByKey.size) {
      await transitionSource(pool, source, 'fail_extract', {
        error_code: 'no_indicators',
        error_detail: 'No indicators could be extracted from the selected files'
      });
      return { ok: false, code: 'no_indicators' };
    }

    let candidates = demoteFilenameDomains(foldSchemeLessLinkedUrls([...mergedByKey.values()], priorRows), priorRows);
    const matched = await bulkMatchCandidates(pool, candidates);
    candidates = Array.isArray(matched?.candidates) ? matched.candidates : candidates;

    // Preserve analyst decisions on surviving identities.
    candidates = candidates.map((c) => {
      const key = `${c.candidate_type}\0${c.normalized_value}`;
      const prior = priorByKey.get(key);
      const next = {
        ...c,
        source_assertion: LINKED_SOURCE_IOC_ASSERTION,
        has_original_document_occurrence: prior?.has_original_document_occurrence === true
      };
      return applyAnalystState(next, prior || null);
    });

    const reconciled = await reconcileReportCandidates(pool, source.report_id, candidates, {
      scope: { sourceId: source.id }
    });

    const originalKeys = await loadOriginalIndicatorKeys(pool, source.report_id);
    const otherKeys = await loadOtherLinkedKeys(pool, source.report_id, source.id);
    const preview = buildPreviewFromParses(parseResults, { originalKeys, otherLinkedKeys: otherKeys });
    preview.extracted = true;
    preview.added = reconciled.added.length;
    preview.updated = reconciled.updated.length;
    preview.removed_orphans = reconciled.removed.length;

    const updated = await transitionSource(pool, source, 'finish_extract', {
      preview,
      last_fetched_at: new Date().toISOString()
    });

    return {
      ok: true,
      source: updated,
      preview,
      added: reconciled.added.length,
      updated: reconciled.updated.length,
      removed: reconciled.removed.length
    };
  } catch (err) {
    const pub = publicFetchError(err);
    await transitionSource(pool, source, 'fail_extract', {
      error_code: pub.code,
      error_detail: pub.message
    });
    return { ok: false, code: pub.code };
  }
}
