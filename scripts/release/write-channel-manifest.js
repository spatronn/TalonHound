/**
 * Write updates/<channel>.json for the public update checker.
 *
 * Usage:
 *   node scripts/release/write-channel-manifest.js \
 *     --version 0.1.0-beta.3 \
 *     --released-at 2026-09-04T12:00:00Z \
 *     --out updates/beta.json
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { isValidSemVer, releaseChannel } from '../../backend/lib/releaseSemver.js';
import { parseUpdateChannelManifest } from '../../backend/lib/updateChannelManifest.js';

function argValue(argv, name) {
  const idx = argv.indexOf(name);
  if (idx < 0) return null;
  return argv[idx + 1] || null;
}

const argv = process.argv.slice(2);
const version = String(argValue(argv, '--version') || '').trim();
const releasedAt = String(argValue(argv, '--released-at') || new Date().toISOString()).trim();
const outPath = String(argValue(argv, '--out') || '').trim();
const minSupported = String(argValue(argv, '--minimum-supported') || version).trim();
const critical = argv.includes('--critical');
const githubRepo = String(argValue(argv, '--github-repo') || 'spatronn/TalonHound').trim();

if (!isValidSemVer(version)) {
  console.error('Invalid --version');
  process.exit(1);
}
if (!outPath) {
  console.error('--out is required');
  process.exit(1);
}

const channel = releaseChannel(version);
if (channel !== 'beta' && channel !== 'stable') {
  console.error(`Channel ${channel} is not published via updates/*.json yet`);
  process.exit(1);
}

const manifest = {
  schemaVersion: 1,
  channel,
  latest: version,
  released_at: releasedAt,
  minimum_supported_version: minSupported,
  release_url: `https://github.com/${githubRepo}/releases/tag/v${version}`,
  critical,
  release_manifest_url: `https://github.com/${githubRepo}/releases/download/v${version}/release-manifest.json`
};

const parsed = parseUpdateChannelManifest(manifest);
if (!parsed.ok) {
  console.error(parsed.error);
  process.exit(1);
}

mkdirSync(path.dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
console.log(`Wrote ${outPath}`);
