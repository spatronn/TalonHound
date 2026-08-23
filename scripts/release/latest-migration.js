import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isRunnableMigrationFile, sortMigrationFiles } from '../../backend/lib/migrationFiles.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../backend/migrations'
);

const files = sortMigrationFiles(readdirSync(migrationsDir).filter(isRunnableMigrationFile));
const latest = files.at(-1) || '';
const match = latest.match(/^(\d+)_/);
const latestNumber = match ? Number(match[1]) : null;

console.log(JSON.stringify({ latestMigrationFile: latest, latestMigration: latestNumber }));
