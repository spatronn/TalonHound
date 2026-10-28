#!/usr/bin/env node
/**
 * Plan which TalonHound rollback image tags can be removed.
 *
 * A rollback generation is the set of `<prefix><service>:rollback-<label>` tags
 * sharing one label (deploy-application.sh writes `rollback-<previous HEAD>`).
 * The newest `keep` complete generations (those with a backend image) are kept,
 * plus any newer partial generation. Only tags matching that pattern are ever
 * planned; images used by any container (running or stopped) are never planned.
 *
 * Input (stdin, JSON): { images: [{ Repository, Tag, ID, CreatedAt }], inUseImageIds: [id] }
 *   images: `docker image ls --no-trunc --format '{{json .}}'` lines collected into an array
 * Output (stdout): the plan as JSON, or with `--format lines` the records read by
 * prune-rollback-images.sh, which does the actual removal.
 */

import { pathToFileURL } from 'node:url';

export const MIN_KEEP = 2;
const ROLLBACK_TAG_RE = /^rollback-([A-Za-z0-9][A-Za-z0-9._-]*)$/;

/** docker CreatedAt ("2026-10-27 18:57:02 +0000 UTC") or ISO → epoch ms (0 if unknown). */
export function parseDockerTime(value) {
  const raw = String(value || '').trim();
  if (!raw) return 0;
  const iso = raw
    // trailing zone name after the numeric offset ("UTC", "+03", "EEST")
    .replace(/( [+-]\d{4}) \S+$/, '$1')
    .replace(/ ([+-]\d{2})(\d{2})$/, '$1:$2')
    .replace(/^(\d{4}-\d{2}-\d{2}) /, '$1T');
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : 0;
}

function normalizeId(id) {
  const s = String(id || '').trim();
  return s.startsWith('sha256:') ? s : `sha256:${s}`;
}

/**
 * @param {{ images: object[], inUseImageIds?: string[] }} inventory
 * @param {{ keep?: number, prefix?: string }} [opts]
 */
export function planRollbackRetention(inventory, { keep = MIN_KEEP, prefix = 'talonhound-' } = {}) {
  const keepN = Number(keep);
  if (!Number.isInteger(keepN) || keepN < MIN_KEEP) {
    throw new Error(`keep must be an integer >= ${MIN_KEEP}`);
  }
  const inUse = new Set((inventory.inUseImageIds || []).map(normalizeId));
  const allImages = (inventory.images || []).map((img) => ({
    repository: String(img.Repository || img.repository || ''),
    tag: String(img.Tag || img.tag || ''),
    id: normalizeId(img.ID || img.id),
    created: parseDockerTime(img.CreatedAt || img.created)
  }));

  // How many tags point at each image id (to tell untag-only from real deletion).
  const tagsPerId = new Map();
  for (const img of allImages) {
    if (img.tag && img.tag !== '<none>') tagsPerId.set(img.id, (tagsPerId.get(img.id) || 0) + 1);
  }

  const generations = new Map();
  for (const img of allImages) {
    if (!img.repository.startsWith(prefix)) continue;
    const m = ROLLBACK_TAG_RE.exec(img.tag);
    if (!m) continue;
    const label = m[1];
    if (!generations.has(label)) generations.set(label, { label, refs: [], created: 0, complete: false });
    const gen = generations.get(label);
    gen.refs.push(img);
    gen.created = Math.max(gen.created, img.created);
    if (img.repository === `${prefix}backend`) gen.complete = true;
  }

  const ordered = [...generations.values()].sort(
    (a, b) => b.created - a.created || b.label.localeCompare(a.label)
  );
  const kept = [];
  const expired = [];
  let completeKept = 0;
  for (const gen of ordered) {
    if (completeKept < keepN) {
      kept.push(gen);
      if (gen.complete) completeKept += 1;
    } else {
      expired.push(gen);
    }
  }

  const remove = [];
  const skipped = [];
  const removalsPerId = new Map();
  for (const gen of expired) {
    for (const img of gen.refs) {
      const ref = `${img.repository}:${img.tag}`;
      if (inUse.has(img.id)) {
        skipped.push({ ref, generation: gen.label, reason: 'in_use' });
        continue;
      }
      remove.push({ ref, id: img.id, generation: gen.label });
      removalsPerId.set(img.id, (removalsPerId.get(img.id) || 0) + 1);
    }
  }
  for (const r of remove) {
    // Image data is freed only when every tag of the id is removed.
    r.untag_only = (tagsPerId.get(r.id) || 0) > (removalsPerId.get(r.id) || 0);
  }

  const summarize = (g) => ({
    label: g.label,
    complete: g.complete,
    created: g.created ? new Date(g.created).toISOString() : null,
    refs: g.refs.map((i) => `${i.repository}:${i.tag}`)
  });
  return {
    keep: keepN,
    prefix,
    kept_generations: kept.map(summarize),
    expired_generations: expired.map(summarize),
    remove,
    skipped
  };
}

function parseArgs(argv) {
  const out = { keep: MIN_KEEP, prefix: 'talonhound-', format: 'json' };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--keep') out.keep = Number(argv[++i]);
    else if (a === '--prefix') out.prefix = String(argv[++i] || '');
    else if (a === '--format') out.format = String(argv[++i] || '');
    else throw new Error(`Unknown argument: ${a}`);
  }
  if (!out.prefix) throw new Error('--prefix must not be empty');
  if (!['json', 'lines'].includes(out.format)) throw new Error('--format must be json or lines');
  return out;
}

/** One record per line for the shell wrapper: KEEP <label> / REMOVE <ref> / SKIP <ref>. */
export function formatPlanLines(plan) {
  const lines = [
    ...plan.kept_generations.map((g) => `KEEP ${g.label}`),
    ...plan.remove.map((r) => `REMOVE ${r.ref}`),
    ...plan.skipped.map((r) => `SKIP ${r.ref}`)
  ];
  return lines.length ? `${lines.join('\n')}\n` : '';
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  let raw = '';
  for await (const chunk of process.stdin) raw += chunk;
  const plan = planRollbackRetention(JSON.parse(raw || '{}'), args);
  process.stdout.write(args.format === 'lines' ? formatPlanLines(plan) : `${JSON.stringify(plan, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`rollback-image-retention: ${err.message}\n`);
    process.exit(2);
  });
}
