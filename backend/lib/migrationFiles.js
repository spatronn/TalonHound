/**
 * Migration file discovery helpers (no DB dependency — safe to import in tests).
 */

/** @param {string} name */
export function isRunnableMigrationFile(name) {
  if (!name || typeof name !== 'string') return false;
  if (!name.endsWith('.sql')) return false;
  const lower = name.toLowerCase();
  if (lower.endsWith('.sql.disabled')) return false;
  if (lower.includes('.disabled')) return false;
  if (lower.endsWith('.bak')) return false;
  if (lower.endsWith('.tmp')) return false;
  if (lower.endsWith('.old')) return false;
  return true;
}

/** @param {string[]} files */
export function sortMigrationFiles(files) {
  return [...files].sort((a, b) => a.localeCompare(b));
}

/**
 * @param {string} migrationsDir
 * @param {(dir: string) => Promise<string[]>} [readdirFn]
 */
export async function getLatestMigrationMeta(migrationsDir, readdirFn) {
  const files = await listRunnableMigrationFiles(migrationsDir, readdirFn);
  const latestFile = files.at(-1) || '';
  const match = latestFile.match(/^(\d+)_/);
  return {
    latestMigrationFile: latestFile,
    latestMigration: match ? Number(match[1]) : null
  };
}

/**
 * @param {string} migrationsDir
 * @param {(dir: string) => Promise<string[]>} readdirFn
 */
export async function listRunnableMigrationFiles(migrationsDir, readdirFn) {
  const read = readdirFn || (await import('node:fs/promises')).readdir;
  const entries = await read(migrationsDir);
  return sortMigrationFiles(entries.filter(isRunnableMigrationFile));
}
