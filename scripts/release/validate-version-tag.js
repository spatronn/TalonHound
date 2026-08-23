#!/usr/bin/env node
/**
 * Validate that a git release tag matches the canonical VERSION file.
 * Usage: node scripts/release/validate-version-tag.js <tag>
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateReleaseTagMatchesVersion } from '../../backend/lib/releaseSemver.js';

const tag = process.argv[2];
if (!tag) {
  console.error('Usage: node scripts/release/validate-version-tag.js <tag>');
  process.exit(2);
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const version = readFileSync(path.join(repoRoot, 'VERSION'), 'utf8').trim();
const result = validateReleaseTagMatchesVersion(tag, version);

if (!result.ok) {
  console.error(result.error);
  process.exit(1);
}

console.log(`OK: ${result.tag} matches VERSION ${result.version}`);
