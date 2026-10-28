/**
 * What a backup row can recover. Format 3+ backups carry Threat Library source
 * files; format 2 (and older) are PostgreSQL-only.
 *
 * @param {{ status?: string, format_version?: number|null, threat_library?: { included: boolean, file_count: number|null, bytes: number|null } }} row
 */
export function describeBackupContents(row) {
  const tl = row?.threat_library;
  if (row?.status !== 'completed') return { kind: 'none', short: null };
  if (tl?.included) {
    const n = Number(tl.file_count || 0);
    return {
      kind: 'full',
      short: `DB + ${n} Threat Library file${n === 1 ? '' : 's'}`,
      threatLibraryRecovery: true
    };
  }
  return { kind: 'database_only', short: 'Database only', threatLibraryRecovery: false };
}
