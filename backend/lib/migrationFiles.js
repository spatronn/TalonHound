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
 * @param {(dir: string) => Promise<string[]>} readdirFn
 */
export async function listRunnableMigrationFiles(migrationsDir, readdirFn) {
  const read = readdirFn || (await import('node:fs/promises')).readdir;
  const entries = await read(migrationsDir);
  return sortMigrationFiles(entries.filter(isRunnableMigrationFile));
}
