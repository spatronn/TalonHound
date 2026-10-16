/**
 * Locate a frontend source module for backend parity tests, independent of the
 * working directory and of where the repository is checked out (main checkout,
 * git worktree, CI). Resolution order:
 *
 * 1. `TALONHOUND_FRONTEND_DIR` — the frontend root (the directory holding
 *    `src/`), for a backend tree without its sibling frontend, e.g. a backend
 *    container with the host checkout mounted.
 * 2. `backend/test-fixtures/<fixtureName>` — a copied module (backend image
 *    has no frontend tree; `docker cp` the file there).
 * 3. The sibling frontend of this backend in the same repository.
 *
 * Never falls back to an absolute host path, and never silently skips: a
 * parity test without the frontend module fails with the resolution list.
 */
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const BACKEND_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * @param {string} relFromFrontendRoot e.g. 'src/components/threatLibrary/candidateReview.js'
 * @param {{ fixtureName?: string, env?: NodeJS.ProcessEnv }} [opts]
 * @returns {string[]} candidate absolute paths, in resolution order
 */
export function frontendModuleCandidates(relFromFrontendRoot, opts = {}) {
  const env = opts.env || process.env;
  const rel = relFromFrontendRoot.split('/');
  const out = [];
  if (env.TALONHOUND_FRONTEND_DIR) out.push(path.resolve(env.TALONHOUND_FRONTEND_DIR, ...rel));
  if (opts.fixtureName) out.push(path.join(BACKEND_ROOT, 'test-fixtures', opts.fixtureName));
  out.push(path.resolve(BACKEND_ROOT, '..', 'frontend', ...rel));
  return out;
}

/**
 * @param {string} relFromFrontendRoot
 * @param {{ fixtureName?: string, env?: NodeJS.ProcessEnv }} [opts]
 * @returns {string} absolute path of the first existing candidate
 */
export function resolveFrontendModule(relFromFrontendRoot, opts = {}) {
  const candidates = frontendModuleCandidates(relFromFrontendRoot, opts);
  const found = candidates.find((p) => existsSync(p));
  if (!found) {
    throw new Error(
      `frontend module ${relFromFrontendRoot} not found; looked in:\n  ${candidates.join('\n  ')}\n` +
        'set TALONHOUND_FRONTEND_DIR to the frontend root, or copy the module into backend/test-fixtures/'
    );
  }
  return found;
}

/**
 * Import a frontend module (ES module) for a parity test.
 * @param {string} relFromFrontendRoot
 * @param {{ fixtureName?: string, env?: NodeJS.ProcessEnv }} [opts]
 */
export async function importFrontendModule(relFromFrontendRoot, opts = {}) {
  return import(pathToFileURL(resolveFrontendModule(relFromFrontendRoot, opts)).href);
}

export const CANDIDATE_REVIEW_MODULE = 'src/components/threatLibrary/candidateReview.js';
export const CANDIDATE_REVIEW_FIXTURE = 'candidateReview.frontend.js';
