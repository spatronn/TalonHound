/**
 * Load shadow-hybrid evaluation cases (golden + experiment-local + optional paths).
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateBenchmarkCase } from '../../benchmark/benchmarkRunner.js';
import { extractCanonicalDocumentFromHtml } from '../../extract/extractHtml.js';
import { pagesToBlocks, PDF_LAYOUT_VERSION } from '../../pdfLayout.js';
import { createCanonicalDocument } from '../../canonicalDocument.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const SHADOW_CASES_DIR = path.join(here, 'cases');

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function resolveSourcePath(caseFile, rel) {
  return path.resolve(path.dirname(caseFile), rel);
}

/**
 * Load a canonical document for a case.
 * @param {object} c validated case
 * @param {string} caseFilePath
 */
export function loadCaseDocument(c, caseFilePath) {
  const kind = c.source?.kind;
  if (kind === 'canonical') {
    const p = resolveSourcePath(caseFilePath, c.source.path);
    return readJson(p);
  }
  if (kind === 'canonical_inline') {
    return c.source.document;
  }
  if (kind === 'canonical_abs') {
    return readJson(c.source.path);
  }
  if (kind === 'html_file') {
    const p = resolveSourcePath(caseFilePath, c.source.path);
    const html = fs.readFileSync(p, 'utf8');
    const url = c.source_reference?.url || c.source?.url || 'https://example.invalid/shadow-hybrid';
    const out = extractCanonicalDocumentFromHtml(html, { url, finalUrl: url, httpStatus: 200 });
    if (out?.ok === false) throw new Error(`html extraction failed: ${out.code || 'unknown'}`);
    return out.document || out;
  }
  if (kind === 'pdf_items') {
    const p = resolveSourcePath(caseFilePath, c.source.path);
    const raw = readJson(p);
    const pages = Array.isArray(raw) ? raw : raw[c.source.pages_key || 'pages'];
    const { blocks } = pagesToBlocks(pages);
    return createCanonicalDocument({
      title: c.title || c.id,
      language: c.language || null,
      blocks,
      meta: { extractor: PDF_LAYOUT_VERSION, adapter: 'pdf' }
    });
  }
  throw new Error(`shadow hybrid unsupported source kind: ${kind}`);
}

/**
 * Discover case files from directories.
 * @param {string[]} dirs
 */
export function listCaseFiles(dirs) {
  const out = [];
  for (const dir of dirs) {
    if (!dir || !fs.existsSync(dir)) continue;
    for (const name of fs.readdirSync(dir).sort()) {
      if (!name.endsWith('.json')) continue;
      out.push(path.join(dir, name));
    }
  }
  return out;
}

/**
 * @param {string} caseFilePath
 */
export function loadCaseDefinition(caseFilePath) {
  const c = readJson(caseFilePath);
  // Allow experiment-local extensions without breaking validateBenchmarkCase.
  if (c.source?.kind === 'canonical_abs' || c.source?.kind === 'canonical_inline') {
    if (!c.id || !c.ground_truth?.indicators) throw new Error(`invalid shadow case ${caseFilePath}`);
    return c;
  }
  return validateBenchmarkCase(c, caseFilePath);
}

export function defaultCaseDirs(repoBackendRoot) {
  return [
    path.join(repoBackendRoot, 'lib/threatLibrary/benchmark/cases'),
    SHADOW_CASES_DIR
  ];
}

/** Prefer golden + shadow cases; optionally include controls via filter. */
export function selectCaseFiles(allFiles, opts = {}) {
  const includeControls = opts.includeControls !== false;
  const ids = opts.ids ? new Set(opts.ids) : null;
  return allFiles.filter((f) => {
    const base = path.basename(f);
    if (ids) {
      try {
        const id = readJson(f).id;
        return ids.has(id);
      } catch {
        return false;
      }
    }
    if (base.startsWith('golden-')) return true;
    if (base.startsWith('shadow-')) return true;
    if (includeControls && base.startsWith('control-')) return true;
    if (includeControls && base.startsWith('pdf-')) return true;
    return false;
  });
}
