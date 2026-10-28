#!/usr/bin/env node
/**
 * Threat Library file restore phases, driven by scripts/restore-stack.sh.
 *
 *   node scripts/restore-threat-library-artifacts.js verify <bundleDir>
 *   node scripts/restore-threat-library-artifacts.js stage  <bundleDir> --id <restoreId>
 *   node scripts/restore-threat-library-artifacts.js commit --id <restoreId>
 *   node scripts/restore-threat-library-artifacts.js abort  --id <restoreId>
 *
 * The storage root is THREAT_LIBRARY_STORAGE_DIR. `verify` and `stage` never
 * touch the live reports/ tree; only `commit` swaps it (keeping the previous
 * tree as .reports-pre-restore-<id>). Prints one JSON line; exit 1 on failure.
 */
import fs from 'node:fs';
import path from 'node:path';
import { parseManifest } from '../lib/backup/manifest.js';
import { verifyThreatLibraryComponent } from '../lib/backup/threatLibraryComponent.js';
import {
  abortThreatLibraryRestore,
  commitThreatLibraryRestore,
  stageThreatLibraryRestore
} from '../lib/backup/threatLibraryRestore.js';
import { getThreatLibraryStorageRoot } from '../lib/threatLibrary/artifactStore.js';

const [command, ...rest] = process.argv.slice(2);
const idIdx = rest.indexOf('--id');
const restoreId = idIdx >= 0 ? rest[idIdx + 1] : null;
const bundleDir = rest[0] && !rest[0].startsWith('--') ? path.resolve(rest[0]) : null;
const storageRoot = getThreatLibraryStorageRoot();

function readManifest(dir) {
  return parseManifest(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
}

async function main() {
  switch (command) {
    case 'verify': {
      const manifest = readManifest(bundleDir);
      const component = manifest.components?.threat_library;
      if (!component) return { ok: true, included: false };
      const r = await verifyThreatLibraryComponent(bundleDir, component);
      if (!r.ok) throw Object.assign(new Error(r.error), { code: r.errorCode });
      return { ok: true, included: true, file_count: r.fileCount, bytes: r.totalBytes };
    }
    case 'stage':
      return { ok: true, ...(await stageThreatLibraryRestore({ bundleDir, manifest: readManifest(bundleDir), storageRoot, restoreId })), stagingDir: undefined };
    case 'commit':
      return { ok: true, ...(await commitThreatLibraryRestore({ storageRoot, restoreId })) };
    case 'abort':
      await abortThreatLibraryRestore({ storageRoot, restoreId });
      return { ok: true };
    default:
      throw Object.assign(new Error('usage: verify|stage|commit|abort'), { code: 'USAGE' });
  }
}

main()
  .then((r) => console.log(JSON.stringify(r)))
  .catch((err) => {
    console.log(JSON.stringify({ ok: false, code: err.code || 'RESTORE_FAILED', error: err.message }));
    process.exitCode = 1;
  });
