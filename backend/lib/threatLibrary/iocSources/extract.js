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
 * @param {{ fetchImpl?: Function }} [deps]
 */
export async function extractIocSource(pool, source, deps = {}) {
  await transitionSource(pool, source, 'start_extract');

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

    if ((!selected.length || !files.length) && gh) {
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
        const parsed = await parseIocSourceContent({
          body: fetched.body,
          buffer: fetched.buffer,
          contentType: fetched.contentType || file.content_type,
          url,
          path: file.path,
          sourcePublicId: source.public_id,
          pdfToDocument: pdfToCanonicalDocument
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

    let candidates = [...mergedByKey.values()];
    candidates = await bulkMatchCandidates(pool, candidates);

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
