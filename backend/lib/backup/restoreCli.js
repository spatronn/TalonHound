// Host CLI restore command helpers (no DB; GUI restore flow removed).

/** Preferred documented form uses --file for external archives; --backup-id for volume registry. */
export function buildRestoreCliCommand(backupId) {
  return `./scripts/restore-stack.sh --backup-id ${backupId} --confirm`;
}

export function buildRestoreCliCommandFromFile(filePath) {
  return `./scripts/restore-stack.sh --file ${filePath} --confirm`;
}
