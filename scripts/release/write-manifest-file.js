#!/usr/bin/env node
/**
 * Write release-manifest.json from build metadata and image digests.
 *
 * Usage:
 *   node scripts/release/write-manifest-file.js \
 *     --version 0.1.0-beta.1 \
 *     --git-tag v0.1.0-beta.1 \
 *     --git-commit abc123 \
 *     --released-at 2026-08-23T12:00:00.000Z \
 *     --latest-migration 165 \
 *     --images-file /tmp/images.json \
 *     --out release-manifest.json
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { buildReleaseManifest } from './generate-manifest.js';

function readArg(name) {
  const index = process.argv.indexOf(name);
  if (index === -1 || !process.argv[index + 1]) {
    throw new Error(`Missing required argument: ${name}`);
  }
  return process.argv[index + 1];
}

const version = readArg('--version');
const gitTag = readArg('--git-tag');
const gitCommit = readArg('--git-commit');
const releasedAt = readArg('--released-at');
const latestMigration = Number(readArg('--latest-migration'));
const imagesFile = readArg('--images-file');
const outFile = readArg('--out');

const images = JSON.parse(readFileSync(imagesFile, 'utf8'));
const manifest = buildReleaseManifest({
  version,
  gitTag,
  gitCommit,
  releasedAt,
  images,
  latestMigration
});

writeFileSync(outFile, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
console.log(`Wrote ${outFile}`);
