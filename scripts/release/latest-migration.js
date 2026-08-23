import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isRunnableMigrationFile, sortMigrationFiles, getLatestMigrationMeta } from '../../backend/lib/migrationFiles.js';

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../backend/migrations'
);

const { latestMigrationFile, latestMigration } = await getLatestMigrationMeta(migrationsDir);
console.log(JSON.stringify({ latestMigrationFile, latestMigration }));
